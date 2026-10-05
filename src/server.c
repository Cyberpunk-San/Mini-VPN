/* VPN server: one UDP socket for all clients, one TUN device, a registry of
 * authorised devices, and a session table indexed both by session id
 * (incoming UDP) and by tunnel IP (packets read from the TUN device).
 * Single-threaded, driven by epoll. */

#include "minivpn.h"

#include "channel.h"
#include "config.h"
#include "control.h"
#include "devices.h"
#include "json.h"
#include "license.h"
#include "log.h"
#include "proto.h"
#include "sys.h"
#include "tun.h"
#include "util.h"

#include <arpa/inet.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <unistd.h>

#define ID_BUCKETS 256
#define IO_BATCH   256 /* packets handled per readiness event before yielding */

typedef struct session {
    uint32_t id;
    uint32_t vip; /* the device's tunnel address */
    uint8_t device_id[DEVICE_ID_LEN];
    char device_name[DEVICE_NAME_MAX + 1];
    struct sockaddr_in peer;
    channel ch;
    uint8_t client_pub[KEY_LEN];
    uint8_t welcome[WELCOME_LEN]; /* cached for retransmitted HELLOs */
    time_t created, created_wall, last_rx, last_tx;
    uint64_t rx_pkts, tx_pkts, rx_bytes, tx_bytes;
    struct session *id_next;
    struct session *prev, *next;
} session;

typedef struct {
    const server_config *cfg;
    int udp, tun, ep, sigfd, timerfd, ctl;
    char dev[IFNAMSIZ];
    uint32_t net, mask, server_ip, pool_size;
    device_table devices;
    license_info license;
    session **by_ip; /* index = vip - net */
    session *by_id[ID_BUCKETS];
    session *head;
    unsigned count;
    time_t now, started, started_wall;
    time_t last_auth_warning;
    uint64_t dropped, rejected_handshakes;
    int running;
} server;

static session *find_by_id(server *s, uint32_t id)
{
    for (session *x = s->by_id[id % ID_BUCKETS]; x; x = x->id_next)
        if (x->id == id)
            return x;
    return NULL;
}

static session *find_by_ip(server *s, uint32_t ip)
{
    if ((ip & s->mask) != s->net)
        return NULL;
    return s->by_ip[ip - s->net];
}

static session *find_by_device(server *s, const uint8_t id[DEVICE_ID_LEN])
{
    for (session *x = s->head; x; x = x->next)
        if (!memcmp(x->device_id, id, DEVICE_ID_LEN))
            return x;
    return NULL;
}

/* Unlinks and frees a session without logging (used when a rekey replaces it). */
static void session_remove(server *s, session *x)
{
    session **pp = &s->by_id[x->id % ID_BUCKETS];
    while (*pp != x)
        pp = &(*pp)->id_next;
    *pp = x->id_next;

    if (x->prev)
        x->prev->next = x->next;
    else
        s->head = x->next;
    if (x->next)
        x->next->prev = x->prev;

    s->by_ip[x->vip - s->net] = NULL;
    s->count--;

    channel_free(&x->ch);
    secure_zero(x, sizeof *x);
    free(x);
}

static void session_destroy(server *s, session *x, const char *reason)
{
    char ip[INET_ADDRSTRLEN], peer[SA_STRLEN];
    log_info("device %s (%s, %s) disconnected: %s; online %lds, rx %llu pkts/%llu B, tx %llu pkts/%llu B",
             x->device_name, ip_str(x->vip, ip), sa_str(&x->peer, peer), reason, (long)(s->now - x->created),
             (unsigned long long)x->rx_pkts, (unsigned long long)x->rx_bytes,
             (unsigned long long)x->tx_pkts, (unsigned long long)x->tx_bytes);
    session_remove(s, x);
}

static void send_sealed(server *s, session *x, uint8_t type, const uint8_t *pt, size_t len)
{
    uint8_t out[BUF_SIZE];
    ssize_t n = channel_seal(&x->ch, type, pt, len, out);
    if (n < 0) {
        log_error("encryption failed for session %08x", x->id);
        return;
    }
    if (sendto(s->udp, out, (size_t)n, 0, (const struct sockaddr *)&x->peer, sizeof x->peer) < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK && errno != ENOBUFS)
            log_debug("sendto session %08x: %s", x->id, strerror(errno));
        s->dropped++;
        return;
    }
    x->last_tx = s->now;
    x->tx_pkts++;
    x->tx_bytes += len;
}

static void kick(server *s, session *x, const char *reason)
{
    send_sealed(s, x, PKT_DISCONNECT, NULL, 0);
    session_destroy(s, x, reason);
}

/* Re-reads license and device registry. Sessions whose device was removed,
 * disabled, re-keyed or re-addressed are disconnected immediately. */
static int reload(server *s, unsigned *kicked_out)
{
    device_table fresh;
    license_info lic;
    unsigned kicked = 0;

    license_load(s->cfg->license_path, &lic);
    if (devices_load(s->cfg->devices_path, s->net, s->mask, s->server_ip, lic.max_devices, &fresh))
        return -1; /* keep serving with the previous registry */

    if (lic.status != s->license.status || lic.max_devices != s->license.max_devices)
        log_info("license: %s", lic.message);
    s->license = lic;

    devices_free(&s->devices);
    s->devices = fresh;

    session *next;
    for (session *x = s->head; x; x = next) {
        next = x->next;
        const device *d = devices_find(&s->devices, x->device_id);
        if (!d) {
            kick(s, x, "access revoked");
            kicked++;
        } else if (d->ip != x->vip) {
            kick(s, x, "address changed by administrator");
            kicked++;
        } else {
            snprintf(x->device_name, sizeof x->device_name, "%s", d->name); /* renamed */
        }
    }

    log_info("loaded %zu authorised device(s)", s->devices.count);
    if (s->devices.over_limit)
        log_warn("%zu device(s) NOT loaded: license allows %u. %s", s->devices.over_limit,
                 s->license.max_devices, s->license.status == LICENSE_VALID ? "Upgrade your license."
                                                                             : "Install a Business license.");
    if (kicked)
        log_info("disconnected %u session(s) after reload", kicked);
    if (kicked_out)
        *kicked_out = kicked;
    return 0;
}

static void reject_hello(server *s, const struct sockaddr_in *from, const char *why)
{
    char addr[SA_STRLEN];
    s->rejected_handshakes++;
    /* Rate-limited: a misconfigured or revoked client retries forever. */
    if (s->now - s->last_auth_warning >= 10) {
        s->last_auth_warning = s->now;
        log_warn("rejected handshake from %s: %s", sa_str(from, addr), why);
    }
}

static void on_hello(server *s, const uint8_t *pkt, size_t len, const struct sockaddr_in *from)
{
    char addr[SA_STRLEN], ip[INET_ADDRSTRLEN];
    uint8_t device_id[DEVICE_ID_LEN];
    hello_msg h;

    int r = hello_peek_device(pkt, len, device_id);
    if (r != PARSE_OK) {
        reject_hello(s, from, r == PARSE_VERSION ? "unsupported protocol version (upgrade the client)" : "malformed");
        return;
    }
    const device *d = devices_find(&s->devices, device_id);
    if (!d) {
        reject_hello(s, from, "unknown, revoked or disabled device");
        return;
    }
    if (hello_parse(pkt, len, d->auth_key, &h) != PARSE_OK) {
        reject_hello(s, from, "authentication failed (wrong device key)");
        return;
    }

    int64_t skew = (int64_t)time(NULL) - (int64_t)h.timestamp;
    if (skew > HELLO_MAX_SKEW || skew < -HELLO_MAX_SKEW) {
        log_warn("rejected handshake from %s (%s): timestamp off by %llds (replay or clock skew)",
                 sa_str(from, addr), d->name, (long long)skew);
        return;
    }

    /* A device holds at most one session. The same ephemeral key means a
     * retransmission (our WELCOME was lost) or a replay: resend the WELCOME. */
    session *old = find_by_device(s, device_id);
    if (old && !memcmp(old->client_pub, h.pub, KEY_LEN)) {
        sendto(s->udp, old->welcome, WELCOME_LEN, 0, (const struct sockaddr *)&old->peer, sizeof old->peer);
        return;
    }
    /* A rekey continues the same connection: keep its counters and start time
     * so dashboards show per-device totals, not per-key-epoch ones. */
    int rekey = old != NULL;
    struct { time_t created, created_wall; uint64_t rx_pkts, tx_pkts, rx_bytes, tx_bytes; } carry = { 0 };
    if (old) {
        carry.created = old->created;
        carry.created_wall = old->created_wall;
        carry.rx_pkts = old->rx_pkts;
        carry.tx_pkts = old->tx_pkts;
        carry.rx_bytes = old->rx_bytes;
        carry.tx_bytes = old->tx_bytes;
        log_debug("device %s rekeying, session %08x replaced", old->device_name, old->id);
        session_remove(s, old);
    }
    /* The address may still be held by a stale session of another device
     * whose registry entry changed; the registry is authoritative. */
    session *squatter = find_by_ip(s, d->ip);
    if (squatter)
        kick(s, squatter, "address reassigned");

    x25519_keypair kp;
    uint8_t shared[KEY_LEN], c2s[KEY_LEN], s2c[KEY_LEN];
    session *x = calloc(1, sizeof *x);
    if (!x) {
        log_error("out of memory");
        return;
    }

    uint32_t sid;
    do {
        if (crypto_random(&sid, sizeof sid))
            goto fail;
    } while (sid == 0 || find_by_id(s, sid));

    if (x25519_keygen(&kp) || x25519_shared(kp.priv, h.pub, shared) ||
        derive_session_keys(d->key, shared, device_id, h.pub, kp.pub, sid, c2s, s2c) ||
        channel_init(&x->ch, sid, s2c, c2s))
        goto fail;

    welcome_msg w = {
        .mtu = (uint16_t)s->cfg->mtu,
        .sid = sid,
        .client_ip = d->ip,
        .netmask = s->mask,
        .server_ip = s->server_ip,
    };
    memcpy(w.pub, kp.pub, KEY_LEN);
    if (welcome_build(x->welcome, d->auth_key, h.mac, &w)) {
        channel_free(&x->ch);
        goto fail;
    }

    x->id = sid;
    x->vip = d->ip;
    memcpy(x->device_id, device_id, DEVICE_ID_LEN);
    snprintf(x->device_name, sizeof x->device_name, "%s", d->name);
    x->peer = *from;
    memcpy(x->client_pub, h.pub, KEY_LEN);
    x->last_rx = x->last_tx = s->now;
    if (rekey) {
        x->created = carry.created;
        x->created_wall = carry.created_wall;
        x->rx_pkts = carry.rx_pkts;
        x->tx_pkts = carry.tx_pkts;
        x->rx_bytes = carry.rx_bytes;
        x->tx_bytes = carry.tx_bytes;
    } else {
        x->created = s->now;
        x->created_wall = time(NULL);
    }

    x->id_next = s->by_id[sid % ID_BUCKETS];
    s->by_id[sid % ID_BUCKETS] = x;
    x->next = s->head;
    if (s->head)
        s->head->prev = x;
    s->head = x;
    s->by_ip[d->ip - s->net] = x;
    s->count++;

    sendto(s->udp, x->welcome, WELCOME_LEN, 0, (const struct sockaddr *)from, sizeof *from);
    if (rekey)
        log_debug("device %s re-keyed, session %08x", d->name, sid);
    else
        log_info("device %s connected from %s: tunnel address %s, session %08x (%u online)", d->name,
                 sa_str(from, addr), ip_str(d->ip, ip), sid, s->count);
    x = NULL;

fail:
    if (x) {
        log_error("handshake with %s failed (crypto error)", sa_str(from, addr));
        free(x);
    }
    secure_zero(&kp, sizeof kp);
    secure_zero(shared, sizeof shared);
    secure_zero(c2s, sizeof c2s);
    secure_zero(s2c, sizeof s2c);
}

/* A decrypted IP packet from a client: deliver to another client directly,
 * or hand it to the kernel through the TUN device. */
static void route_from_client(server *s, session *x, const uint8_t *pkt, size_t len)
{
    char a[INET_ADDRSTRLEN];

    if (len < 20 || (pkt[0] >> 4) != 4)
        return;
    size_t total = get_u16(pkt + 2);
    if (total < 20 || total > len)
        return;

    uint32_t src = get_u32(pkt + 12);
    uint32_t dst = get_u32(pkt + 16);
    if (src != x->vip) {
        log_debug("device %s: dropped packet with spoofed source %s", x->device_name, ip_str(src, a));
        s->dropped++;
        return;
    }

    session *target = find_by_ip(s, dst);
    if (target) {
        if (s->cfg->client_to_client)
            send_sealed(s, target, PKT_DATA, pkt, total);
        else
            s->dropped++;
        return;
    }

    if (write(s->tun, pkt, total) < 0) {
        if (errno != EAGAIN)
            log_warn("write to %s: %s", s->dev, strerror(errno));
        s->dropped++;
    }
}

static void on_sealed(server *s, const uint8_t *pkt, size_t len, const struct sockaddr_in *from)
{
    char addr[SA_STRLEN], old[SA_STRLEN];
    uint8_t plain[BUF_SIZE];
    uint8_t type;

    if (len < WIRE_OVERHEAD)
        return;
    session *x = find_by_id(s, get_u32(pkt + 4));
    if (!x) {
        log_debug("packet for unknown session from %s", sa_str(from, addr));
        return;
    }

    ssize_t n = channel_open(&x->ch, pkt, len, &type, plain);
    if (n < 0) {
        log_debug("session %08x: dropped packet from %s (%s)", x->id, sa_str(from, addr),
                  n == CH_ERR_REPLAY ? "replay" : "authentication failed");
        return;
    }

    /* Authenticated traffic from a new address: the client roamed (Wi-Fi to
     * mobile, NAT rebinding). Follow it, like WireGuard does. */
    if (x->peer.sin_addr.s_addr != from->sin_addr.s_addr || x->peer.sin_port != from->sin_port) {
        log_info("device %s moved %s -> %s", x->device_name, sa_str(&x->peer, old), sa_str(from, addr));
        x->peer = *from;
    }
    x->last_rx = s->now;
    x->rx_pkts++;
    x->rx_bytes += (uint64_t)n;

    switch (type) {
    case PKT_DATA:
        route_from_client(s, x, plain, (size_t)n);
        break;
    case PKT_KEEPALIVE:
        break;
    case PKT_DISCONNECT:
        session_destroy(s, x, "client disconnected");
        break;
    }
}

static void on_udp(server *s)
{
    uint8_t pkt[BUF_SIZE];
    for (int i = 0; i < IO_BATCH; i++) {
        struct sockaddr_in from;
        socklen_t fromlen = sizeof from;
        ssize_t n = recvfrom(s->udp, pkt, sizeof pkt, 0, (struct sockaddr *)&from, &fromlen);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            if (errno != EAGAIN && errno != EWOULDBLOCK)
                log_warn("recvfrom: %s", strerror(errno));
            return;
        }
        if (n == 0 || fromlen != sizeof from || from.sin_family != AF_INET)
            continue;

        switch (pkt[0]) {
        case PKT_HELLO:
            on_hello(s, pkt, (size_t)n, &from);
            break;
        case PKT_DATA:
        case PKT_KEEPALIVE:
        case PKT_DISCONNECT:
            on_sealed(s, pkt, (size_t)n, &from);
            break;
        default:
            break;
        }
    }
}

static void on_tun(server *s)
{
    char a[INET_ADDRSTRLEN];
    uint8_t pkt[BUF_SIZE];
    for (int i = 0; i < IO_BATCH; i++) {
        ssize_t n = read(s->tun, pkt, sizeof pkt);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            if (errno != EAGAIN && errno != EWOULDBLOCK)
                log_warn("read %s: %s", s->dev, strerror(errno));
            return;
        }
        if (n < 20 || (pkt[0] >> 4) != 4 || (size_t)n > BUF_SIZE - WIRE_OVERHEAD)
            continue;

        uint32_t dst = get_u32(pkt + 16);
        session *x = find_by_ip(s, dst);
        if (!x) {
            log_debug("no client for %s, dropping", ip_str(dst, a));
            s->dropped++;
            continue;
        }
        send_sealed(s, x, PKT_DATA, pkt, (size_t)n);
    }
}

static void on_tick(server *s)
{
    session *next;
    for (session *x = s->head; x; x = next) {
        next = x->next;
        if (s->now - x->last_rx > SESSION_TIMEOUT) {
            session_destroy(s, x, "timed out");
            continue;
        }
        /* Keeps NAT mappings on the client's path alive and lets the client
         * detect a dead server. */
        if (s->now - x->last_tx >= KEEPALIVE_INTERVAL)
            send_sealed(s, x, PKT_KEEPALIVE, NULL, 0);
    }
}

static void print_status(server *s)
{
    char ip[INET_ADDRSTRLEN], peer[SA_STRLEN];
    log_info("status: %u of %zu device(s) online on %s, %llu packet(s) dropped; %s", s->count,
             s->devices.count, s->dev, (unsigned long long)s->dropped, s->license.message);
    for (session *x = s->head; x; x = x->next)
        log_info("  %-20s %-15s %-21s up %4lds idle %3lds rx %llu B tx %llu B", x->device_name,
                 ip_str(x->vip, ip), sa_str(&x->peer, peer), (long)(s->now - x->created),
                 (long)(s->now - x->last_rx), (unsigned long long)x->rx_bytes,
                 (unsigned long long)x->tx_bytes);
}

static void write_status_json(server *s, FILE *out)
{
    char ip[INET_ADDRSTRLEN], peer[SA_STRLEN], idhex[2 * DEVICE_ID_LEN + 1], sid[16];

    fputs("{\"ok\":true,\"version\":", out);
    json_string(out, MINIVPN_VERSION);
    fprintf(out, ",\"started\":%lld,\"uptime\":%lld,\"interface\":", (long long)s->started_wall,
            (long long)(s->now - s->started));
    json_string(out, s->dev);
    fprintf(out, ",\"subnet\":\"%s/%d\",\"port\":%u,\"client_to_client\":%s", ip_str(s->net, ip),
            mask_to_prefix(s->mask), s->cfg->port, s->cfg->client_to_client ? "true" : "false");
    fprintf(out, ",\"devices_loaded\":%zu,\"devices_over_limit\":%zu,\"devices_invalid\":%zu",
            s->devices.count, s->devices.over_limit, s->devices.invalid);
    fprintf(out, ",\"packets_dropped\":%llu,\"handshakes_rejected\":%llu,\"license\":",
            (unsigned long long)s->dropped, (unsigned long long)s->rejected_handshakes);
    license_write_json(&s->license, out);
    fputs(",\"sessions\":[", out);
    for (session *x = s->head; x; x = x->next) {
        hex_encode(x->device_id, DEVICE_ID_LEN, idhex);
        snprintf(sid, sizeof sid, "%08x", x->id);
        fputs(x == s->head ? "{" : ",{", out);
        fputs("\"device\":", out);
        json_string(out, x->device_name);
        fprintf(out, ",\"device_id\":\"%s\",\"session\":\"%s\",\"ip\":\"%s\",\"endpoint\":\"%s\"", idhex, sid,
                ip_str(x->vip, ip), sa_str(&x->peer, peer));
        fprintf(out, ",\"connected_at\":%lld,\"idle\":%lld,\"rx_bytes\":%llu,\"tx_bytes\":%llu,"
                     "\"rx_packets\":%llu,\"tx_packets\":%llu}",
                (long long)x->created_wall, (long long)(s->now - x->last_rx),
                (unsigned long long)x->rx_bytes, (unsigned long long)x->tx_bytes,
                (unsigned long long)x->rx_pkts, (unsigned long long)x->tx_pkts);
    }
    fputs("]}\n", out);
}

static void on_control(server *s)
{
    char cmd[256];
    for (int i = 0; i < 16; i++) {
        int fd = control_accept(s->ctl, cmd, sizeof cmd);
        if (fd < 0)
            return;
        FILE *out = fdopen(fd, "w");
        if (!out) {
            close(fd);
            continue;
        }
        log_debug("control: %s", cmd);

        if (!strcmp(cmd, "status")) {
            write_status_json(s, out);
        } else if (!strcmp(cmd, "reload")) {
            unsigned kicked = 0;
            if (reload(s, &kicked) == 0)
                fprintf(out, "{\"ok\":true,\"devices_loaded\":%zu,\"devices_over_limit\":%zu,\"kicked\":%u}\n",
                        s->devices.count, s->devices.over_limit, kicked);
            else
                fputs("{\"ok\":false,\"error\":\"could not read the device registry\"}\n", out);
        } else if (!strncmp(cmd, "kick ", 5)) {
            uint8_t id[DEVICE_ID_LEN];
            session *x = hex_decode(cmd + 5, id, DEVICE_ID_LEN) ? NULL : find_by_device(s, id);
            if (x) {
                kick(s, x, "disconnected by administrator");
                fputs("{\"ok\":true}\n", out);
            } else {
                fputs("{\"ok\":false,\"error\":\"device is not connected\"}\n", out);
            }
        } else {
            fputs("{\"ok\":false,\"error\":\"unknown command (status, reload, kick <device-id>)\"}\n", out);
        }
        fclose(out);
    }
}

static void on_signal(server *s)
{
    struct signalfd_siginfo si;
    while (read(s->sigfd, &si, sizeof si) == (ssize_t)sizeof si) {
        switch (si.ssi_signo) {
        case SIGUSR1:
            print_status(s);
            break;
        case SIGHUP:
            log_info("received SIGHUP, reloading devices and license");
            reload(s, NULL);
            break;
        default:
            log_info("received %s, shutting down", strsignal((int)si.ssi_signo));
            s->running = 0;
            break;
        }
    }
}

int server_run(const server_config *cfg)
{
    char ip[INET_ADDRSTRLEN], listen_ip[INET_ADDRSTRLEN];
    int rc = 1;
    server s;
    memset(&s, 0, sizeof s);
    s.cfg = cfg;
    s.udp = s.tun = s.ep = s.sigfd = s.timerfd = s.ctl = -1;
    s.net = cfg->subnet;
    s.mask = cfg->netmask;
    s.pool_size = ~s.mask + 1;
    s.server_ip = s.net + 1;
    s.now = s.started = mono_now();
    s.started_wall = time(NULL);

    s.by_ip = calloc(s.pool_size, sizeof *s.by_ip);
    if (!s.by_ip) {
        log_error("out of memory");
        goto out;
    }
    warn_if_world_readable(cfg->devices_path, 1);
    if (reload(&s, NULL))
        goto out;
    log_info("%s", s.license.message);
    if (s.devices.count == 0)
        log_warn("no devices registered yet; add one with: minivpn-admin add <name>");

    snprintf(s.dev, sizeof s.dev, "%s", cfg->dev);
    if ((s.tun = tun_open(s.dev)) < 0)
        goto out;
    tun_disable_ipv6(s.dev);
    if (tun_configure(s.dev, s.server_ip, s.mask, cfg->mtu))
        goto out;

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(cfg->port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    if (cfg->listen_addr && inet_pton(AF_INET, cfg->listen_addr, &addr.sin_addr) != 1) {
        log_error("invalid listen address '%s'", cfg->listen_addr);
        goto out;
    }
    s.udp = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (s.udp < 0 || bind(s.udp, (struct sockaddr *)&addr, sizeof addr) < 0) {
        log_error("bind UDP port %u: %s", cfg->port, strerror(errno));
        goto out;
    }
    tune_socket_buffers(s.udp);

    if (cfg->control_path && *cfg->control_path && (s.ctl = control_listen(cfg->control_path)) < 0)
        goto out;
    if ((s.sigfd = make_signalfd()) < 0 || (s.timerfd = make_timerfd(1000)) < 0)
        goto out;
    if ((s.ep = epoll_create1(EPOLL_CLOEXEC)) < 0) {
        log_error("epoll_create1: %s", strerror(errno));
        goto out;
    }
    if (epoll_watch(s.ep, s.udp) || epoll_watch(s.ep, s.tun) || epoll_watch(s.ep, s.sigfd) ||
        epoll_watch(s.ep, s.timerfd) || (s.ctl >= 0 && epoll_watch(s.ep, s.ctl)))
        goto out;

    /* Everything privileged (TUN, ioctl, bind) is done; shed root now. The
     * registry stays readable through group permissions for reloads. */
    if (cfg->user && *cfg->user && drop_privileges(cfg->user))
        goto out;

    inet_ntop(AF_INET, &addr.sin_addr, listen_ip, sizeof listen_ip);
    log_info("minivpn server %s listening on %s:%u, tunnel %s %s/%d, MTU %d, %zu device(s) authorised",
             MINIVPN_VERSION, listen_ip, cfg->port, s.dev, ip_str(s.server_ip, ip), mask_to_prefix(s.mask),
             cfg->mtu, s.devices.count);

    rc = 0;
    s.running = 1;
    while (s.running) {
        struct epoll_event ev[8];
        int n = epoll_wait(s.ep, ev, 8, -1);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            log_error("epoll_wait: %s", strerror(errno));
            rc = 1;
            break;
        }
        s.now = mono_now();
        for (int i = 0; i < n; i++) {
            int fd = ev[i].data.fd;
            if (fd == s.udp) {
                on_udp(&s);
            } else if (fd == s.tun) {
                on_tun(&s);
            } else if (fd == s.timerfd) {
                uint64_t expirations;
                if (read(fd, &expirations, sizeof expirations) > 0)
                    on_tick(&s);
            } else if (fd == s.sigfd) {
                on_signal(&s);
            } else if (fd == s.ctl) {
                on_control(&s);
            }
        }
    }

    /* Tell clients we're going away so they reconnect promptly instead of
     * waiting for the dead-peer timeout. */
    while (s.head)
        kick(&s, s.head, "server shutting down");

out:
    if (s.ep >= 0)
        close(s.ep);
    if (s.timerfd >= 0)
        close(s.timerfd);
    if (s.sigfd >= 0)
        close(s.sigfd);
    if (s.ctl >= 0) {
        close(s.ctl);
        unlink(cfg->control_path); /* may fail after dropping root; replaced on next start */
    }
    if (s.udp >= 0)
        close(s.udp);
    if (s.tun >= 0)
        close(s.tun); /* non-persistent TUN: the interface disappears with the fd */
    devices_free(&s.devices);
    free(s.by_ip);
    return rc;
}
