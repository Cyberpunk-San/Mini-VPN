#include "tun.h"

#include "log.h"
#include "util.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/if_tun.h>
#include <net/route.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

int tun_open(char name[IFNAMSIZ])
{
    int fd = open("/dev/net/tun", O_RDWR | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0) {
        log_error("open /dev/net/tun: %s", strerror(errno));
        return -1;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof ifr);
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    snprintf(ifr.ifr_name, IFNAMSIZ, "%s", name);

    if (ioctl(fd, TUNSETIFF, &ifr) < 0) {
        log_error("create TUN device '%s': %s%s", name, strerror(errno),
                  errno == EPERM ? " (run as root or grant CAP_NET_ADMIN)" : "");
        close(fd);
        return -1;
    }
    snprintf(name, IFNAMSIZ, "%s", ifr.ifr_name);
    return fd;
}

static void fill_sockaddr(struct sockaddr *sa, uint32_t ip)
{
    struct sockaddr_in sin;
    memset(&sin, 0, sizeof sin);
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(ip);
    memcpy(sa, &sin, sizeof sin);
}

int tun_configure(const char *name, uint32_t ip, uint32_t netmask, int mtu)
{
    int s = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (s < 0) {
        log_error("socket: %s", strerror(errno));
        return -1;
    }

    struct ifreq ifr;
    const char *step;
    memset(&ifr, 0, sizeof ifr);
    snprintf(ifr.ifr_name, IFNAMSIZ, "%s", name);

    step = "set address";
    fill_sockaddr(&ifr.ifr_addr, ip);
    if (ioctl(s, SIOCSIFADDR, &ifr) < 0)
        goto fail;

    step = "set netmask";
    fill_sockaddr(&ifr.ifr_netmask, netmask);
    if (ioctl(s, SIOCSIFNETMASK, &ifr) < 0)
        goto fail;

    step = "set MTU";
    ifr.ifr_mtu = mtu;
    if (ioctl(s, SIOCSIFMTU, &ifr) < 0)
        goto fail;

    step = "bring up";
    if (ioctl(s, SIOCGIFFLAGS, &ifr) < 0)
        goto fail;
    ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
    if (ioctl(s, SIOCSIFFLAGS, &ifr) < 0)
        goto fail;

    close(s);
    return 0;

fail:
    log_error("%s: %s failed: %s", name, step, strerror(errno));
    close(s);
    return -1;
}

void tun_disable_ipv6(const char *name)
{
    char path[128];
    snprintf(path, sizeof path, "/proc/sys/net/ipv6/conf/%s/disable_ipv6", name);
    int fd = open(path, O_WRONLY | O_CLOEXEC);
    if (fd < 0)
        return;
    if (write(fd, "1", 1) != 1)
        log_debug("could not disable IPv6 on %s: %s", name, strerror(errno));
    close(fd);
}

static int route_ioctl(unsigned long request, uint32_t dst, uint32_t mask, uint32_t gw, const char *dev)
{
    struct rtentry rt;
    char devbuf[IFNAMSIZ];

    memset(&rt, 0, sizeof rt);
    fill_sockaddr(&rt.rt_dst, dst & mask);
    fill_sockaddr(&rt.rt_genmask, mask);
    rt.rt_flags = RTF_UP;
    if (gw) {
        fill_sockaddr(&rt.rt_gateway, gw);
        rt.rt_flags |= RTF_GATEWAY;
    }
    if (mask == 0xffffffffu)
        rt.rt_flags |= RTF_HOST;
    snprintf(devbuf, sizeof devbuf, "%s", dev);
    rt.rt_dev = devbuf;

    int s = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (s < 0)
        return -1;
    int rc = ioctl(s, request, &rt);
    int saved = errno;
    close(s);
    errno = saved;
    return rc;
}

static void describe_route(char *buf, size_t len, uint32_t dst, uint32_t mask, uint32_t gw, const char *dev)
{
    char d[INET_ADDRSTRLEN], g[INET_ADDRSTRLEN];
    if (gw)
        snprintf(buf, len, "%s/%d via %s dev %s", ip_str(dst, d), mask_to_prefix(mask), ip_str(gw, g), dev);
    else
        snprintf(buf, len, "%s/%d dev %s", ip_str(dst, d), mask_to_prefix(mask), dev);
}

int route_add(uint32_t dst, uint32_t mask, uint32_t gw, const char *dev)
{
    char desc[96];
    describe_route(desc, sizeof desc, dst, mask, gw, dev);
    if (route_ioctl(SIOCADDRT, dst, mask, gw, dev) == 0) {
        log_info("added route %s", desc);
        return 0;
    }
    if (errno == EEXIST) {
        log_debug("route %s already exists", desc);
        return 1;
    }
    log_error("add route %s: %s", desc, strerror(errno));
    return -1;
}

int route_del(uint32_t dst, uint32_t mask, uint32_t gw, const char *dev)
{
    char desc[96];
    describe_route(desc, sizeof desc, dst, mask, gw, dev);
    if (route_ioctl(SIOCDELRT, dst, mask, gw, dev) == 0) {
        log_info("removed route %s", desc);
        return 0;
    }
    log_warn("remove route %s: %s", desc, strerror(errno));
    return -1;
}

int route_get_default(uint32_t *gw, char dev[IFNAMSIZ])
{
    FILE *f = fopen("/proc/net/route", "re");
    if (!f)
        return -1;

    char line[256];
    unsigned best_metric = UINT_MAX;
    int found = 0;

    if (!fgets(line, sizeof line, f)) { /* header */
        fclose(f);
        return -1;
    }
    while (fgets(line, sizeof line, f)) {
        char ifname[IFNAMSIZ];
        unsigned dest, gateway, flags, refcnt, use, metric, mask;
        if (sscanf(line, "%15s %x %x %x %u %u %u %x", ifname, &dest, &gateway, &flags, &refcnt,
                   &use, &metric, &mask) != 8)
            continue;
        if (dest != 0 || mask != 0 || !(flags & RTF_UP))
            continue;
        if (metric < best_metric) {
            best_metric = metric;
            /* The kernel prints the raw network-order word, so it reads back as-is. */
            *gw = ntohl(gateway);
            snprintf(dev, IFNAMSIZ, "%s", ifname);
            found = 1;
        }
    }
    fclose(f);
    return found ? 0 : -1;
}
