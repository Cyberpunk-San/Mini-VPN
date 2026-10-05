#ifndef MINIVPN_TUN_H
#define MINIVPN_TUN_H

/* Virtual interface and routing-table management through the kernel's ioctl
 * interface. All addresses are host byte order. */

#include <net/if.h>
#include <stdint.h>

/* Creates a TUN device (layer 3, no packet-info header). name may contain a
 * "%d" template and is updated with the name the kernel chose. Non-blocking. */
int tun_open(char name[IFNAMSIZ]);

/* Assigns address/netmask/MTU and brings the interface up. */
int tun_configure(const char *name, uint32_t ip, uint32_t netmask, int mtu);

/* Stops the kernel from emitting IPv6 router solicitations etc. into the tunnel. */
void tun_disable_ipv6(const char *name);

/* gw == 0 means a directly connected route through dev.
 * Returns 0 if added, 1 if it already existed, -1 on error. */
int route_add(uint32_t dst, uint32_t mask, uint32_t gw, const char *dev);
int route_del(uint32_t dst, uint32_t mask, uint32_t gw, const char *dev);

/* Reads the lowest-metric default route from /proc/net/route. */
int route_get_default(uint32_t *gw, char dev[IFNAMSIZ]);

#endif
