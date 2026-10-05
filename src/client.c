/* VPN client: handshakes with the server, configures its TUN device with the
 * address it is given, then shuttles packets between TUN and UDP. Handles
 * keepalives, dead-peer detection, reconnects and periodic rekeying. */

#include "minivpn.h"

#include "channel.h"
#include "log.h"
#include "proto.h"
#include "sys.h"
#include "tun.h"
#include "util.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <unistd.h>

#define IO_BATCH        256
#define MAX_HELLO_DELAY 8

typedef struct {
    const client_config *cfg;
    uint8_t auth_key[KEY_LEN];
    int udp, tun, ep, sigfd, timerfd;
    char dev[IFNAMSIZ];
    struct sockaddr_in server_addr;
    time_t now, started;
    int running, exit_code;

    /* Handshake in flight (also during a rekey, while the old session still works). */
    int hs_active;
    x25519_keypair hs_kp;
    uint8_t hello[HELLO_LEN];
    uint8_t hello_mac[MAC_LEN];
    time_t hs_started, hs_last_sent;
    int hs_delay;

    /* Established session. */
    int connected, ever_connected;
    channel ch;
    time_t session_start, last_rx, last_tx;

    /* Tunnel addressing handed out by the server. */
    int tun_ready;
    uint32_t vip, netmask, server_vip;

    /* --redirect-gateway bookkeeping, undone on exit. */
    int host_route_added;
    uint32_t orig_gw;
    char orig_dev[IFNAMSIZ];

    uint64_t rx_pkts, tx_pkts, rx_bytes, tx_bytes, reconnects;
} client;

static void send_hello(client *c)
{
    if (send(c->udp, c->hello, HELLO_LEN, 0) < 0 && errno != EAGAIN)
        log_debug("send HELLO: %s", strerror(errno));
    c->hs_last_sent = c->now;
}

static void start_handshake(client *c)
{
    hello_msg h;
    memset(&h, 0, sizeof h);

    if (x25519_keygen(&c->hs_kp)) {
        log_error("key generation failed");
        c->hs_active = 0;
        return;
    }
    memcpy(h.device_id, c->cfg->device_id, DEVICE_ID_LEN);
    memcpy(h.pub, c->hs_kp.pub, KEY_LEN);
    h.timestamp = (uint64_t)time(NULL);
    if (hello_build(c->hello, c->auth_key, &h)) {
        log_error("building HELLO failed");
        c->hs_active = 0;
        return;
    }
    memcpy(c->hello_mac, h.mac, MAC_LEN);

    c->hs_active = 1;
    c->hs_started = c->now;
    c->hs_delay = 1;
    send_hello(c);
}

static void end_session(client *c)
{
    if (c->connected)
        channel_free(&c->ch);
    c->connected = 0;
}

static void send_sealed(client *c, uint8_t type, const uint8_t *pt, size_t len)
{
    uint8_t out[BUF_SIZE];
    ssize_t n = channel_seal(&c->ch, type, pt, len, out);
    if (n < 0) {
        log_error("encryption failed");
        return;
    }
    if (send(c->udp, out, (size_t)n, 0) < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK && errno != ENOBUFS)
            log_debug("send: %s", strerror(errno));
        return;
    }
    c->last_tx = c->now;
    c->tx_pkts++;
    c->tx_bytes += len;
}

/* Route everything through the tunnel without losing the path to the server:
 * pin a host route to the server via the old gateway, then add 0/1 and 128/1
 * which are more specific than the existing default route and win. */
static int setup_full_tunnel(client *c)
{
    char gw[INET_ADDRSTRLEN];
    uint32_t server = ntohl(c->server_addr.sin_addr.s_addr);

    if (route_get_default(&c->orig_gw, c->orig_dev)) {
        log_error("--redirect-gateway: no existing default route found");
        return -1;
    }
    int r = route_add(server, 0xffffffffu, c->orig_gw, c->orig_dev);
    if (r < 0)
        return -1;
    c->host_route_added = (r == 0);

    if (route_add(0x00000000u, 0x80000000u, 0, c->dev) < 0 ||
        route_add(0x80000000u, 0x80000000u, 0, c->dev) < 0)
        return -1;
    log_info("all IPv4 traffic now goes through %s (server reached via %s on %s)", c->dev,
             ip_str(c->orig_gw, gw), c->orig_dev);
    return 0;
}

static int configure_tunnel(client *c, const welcome_msg *w)
{
    int first = !c->tun_ready;

    if (tun_configure(c->dev, w->client_ip, w->netmask, w->mtu))
        return -1;
    c->vip = w->client_ip;
    c->netmask = w->netmask;
    c->server_vip = w->server_ip;
    c->tun_ready = 1;

    for (int i = 0; i < c->cfg->nroutes; i++)
        if (route_add(c->cfg->route_net[i], c->cfg->route_mask[i], 0, c->dev) < 0)
            return -1;
    if (first && c->cfg->redirect_gateway && setup_full_tunnel(c))
        return -1;
    return 0;
}

static int welcome_is_sane(const welcome_msg *w)
{
    int prefix = mask_to_prefix(w->netmask);
    return w->sid != 0 && w->mtu >= MIN_MTU && w->mtu <= MAX_MTU && prefix >= 8 && prefix <= 30 &&
           (w->client_ip & w->netmask) == (w->server_ip & w->netmask) && w->client_ip != w->server_ip;
}

static void on_welcome(client *c, const uint8_t *pkt, size_t len)
{
    char ip[INET_ADDRSTRLEN], srv[INET_ADDRSTRLEN];
    uint8_t shared[KEY_LEN], c2s[KEY_LEN], s2c[KEY_LEN];
    welcome_msg w;

    if (!c->hs_active)
        return;
    int r = welcome_parse(pkt, len, c->auth_key, c->hello_mac, &w);
    if (r != PARSE_OK) {
        log_debug("ignored WELCOME (%s)", r == PARSE_AUTH ? "authentication failed" : "malformed");
        return;
    }
    if (!welcome_is_sane(&w)) {
        log_error("server sent an invalid configuration; ignoring");
        return;
    }

    if (x25519_shared(c->hs_kp.priv, w.pub, shared) ||
        derive_session_keys(c->cfg->psk, shared, c->cfg->device_id, c->hs_kp.pub, w.pub, w.sid, c2s, s2c)) {
        log_error("key agreement failed");
        goto wipe;
    }

    int was_connected = c->connected;
    uint32_t old_sid = c->ch.sid;
    end_session(c);
    if (channel_init(&c->ch, w.sid, c2s, s2c)) {
        log_error("cipher setup failed");
        goto wipe;
    }
    c->connected = 1;
    c->hs_active = 0;
    c->session_start = c->last_rx = c->last_tx = c->now;
    secure_zero(&c->hs_kp, sizeof c->hs_kp);

    if (!c->tun_ready || w.client_ip != c->vip || w.netmask != c->netmask) {
        if (configure_tunnel(c, &w)) {
            log_error("could not configure %s; exiting", c->dev);
            c->exit_code = 1;
            c->running = 0;
            goto wipe;
        }
    }

    if (was_connected) {
        log_info("rekeyed: session %08x -> %08x", old_sid, w.sid);
    } else {
        log_info("%s: tunnel address %s/%d on %s, server %s, MTU %u (session %08x)",
                 c->ever_connected ? "reconnected" : "connected", ip_str(w.client_ip, ip),
                 mask_to_prefix(w.netmask), c->dev, ip_str(w.server_ip, srv), w.mtu, w.sid);
    }
    c->ever_connected = 1;

wipe:
    secure_zero(shared, sizeof shared);
    secure_zero(c2s, sizeof c2s);
    secure_zero(s2c, sizeof s2c);
}

static void on_sealed(client *c, const uint8_t *pkt, size_t len)
{
    uint8_t plain[BUF_SIZE];
    uint8_t type;

    if (!c->connected || len < WIRE_OVERHEAD || get_u32(pkt + 4) != c->ch.sid)
        return;
    ssize_t n = channel_open(&c->ch, pkt, len, &type, plain);
    if (n < 0) {
        log_debug("dropped packet (%s)", n == CH_ERR_REPLAY ? "replay" : "authentication failed");
        return;
    }
    c->last_rx = c->now;
    c->rx_pkts++;
    c->rx_bytes += (uint64_t)n;

    switch (type) {
    case PKT_DATA:
        if (n >= 20 && (plain[0] >> 4) == 4 && write(c->tun, plain, (size_t)n) < 0 && errno != EAGAIN)
            log_warn("write to %s: %s", c->dev, strerror(errno));
        break;
    case PKT_KEEPALIVE:
        break;
    case PKT_DISCONNECT:
        log_warn("server closed the session; reconnecting");
        end_session(c);
        c->reconnects++;
        start_handshake(c);
        break;
    }
}

static void on_udp(client *c)
{
    uint8_t pkt[BUF_SIZE];
    for (int i = 0; i < IO_BATCH; i++) {
        ssize_t n = recv(c->udp, pkt, sizeof pkt, 0);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            if (errno == ECONNREFUSED) { /* ICMP port unreachable: server not running */
                log_debug("server port unreachable");
                continue;
            }
            if (errno != EAGAIN && errno != EWOULDBLOCK)
                log_warn("recv: %s", strerror(errno));
            return;
        }
        if (n == 0)
            continue;
        switch (pkt[0]) {
        case PKT_WELCOME:
            on_welcome(c, pkt, (size_t)n);
            break;
        case PKT_DATA:
        case PKT_KEEPALIVE:
        case PKT_DISCONNECT:
            on_sealed(c, pkt, (size_t)n);
            break;
        default:
            break;
        }
    }
}

static void on_tun(client *c)
{
    uint8_t pkt[BUF_SIZE];
    for (int i = 0; i < IO_BATCH; i++) {
        ssize_t n = read(c->tun, pkt, sizeof pkt);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            if (errno != EAGAIN && errno != EWOULDBLOCK)
                log_warn("read %s: %s", c->dev, strerror(errno));
            return;
        }
        if (!c->connected || n < 20 || (pkt[0] >> 4) != 4 || (size_t)n > BUF_SIZE - WIRE_OVERHEAD)
            continue;
        send_sealed(c, PKT_DATA, pkt, (size_t)n);
    }
}

static void on_tick(client *c)
{
    if (c->connected && c->now - c->last_rx > DEAD_PEER_TIMEOUT) {
        log_warn("no response from server for %ds; reconnecting", DEAD_PEER_TIMEOUT);
        end_session(c);
        c->reconnects++;
    }

    if (c->hs_active) {
        if (c->now - c->hs_started >= HANDSHAKE_TIMEOUT) {
            log_warn("handshake timed out; retrying with fresh keys");
            start_handshake(c);
        } else if (c->now - c->hs_last_sent >= c->hs_delay) {
            /* Identical retransmission: the server recognises the key and
             * re-sends its WELCOME instead of creating a second session. */
            if (c->hs_delay >= 4 && !c->connected)
                log_warn("no answer from the server yet (check the address, firewall, and that this "
                         "device has not been revoked)");
            send_hello(c);
            if (c->hs_delay < MAX_HELLO_DELAY)
                c->hs_delay *= 2;
        }
    } else if (!c->connected) {
        start_handshake(c);
    } else if (c->cfg->rekey_interval > 0 && c->now - c->session_start >= c->cfg->rekey_interval) {
        log_debug("session is %lds old, rekeying", (long)(c->now - c->session_start));
        start_handshake(c);
    }

    if (c->connected && c->now - c->last_tx >= KEEPALIVE_INTERVAL)
        send_sealed(c, PKT_KEEPALIVE, NULL, 0);
}

static void print_status(client *c)
{
    char ip[INET_ADDRSTRLEN], srv[SA_STRLEN];
    if (!c->connected) {
        log_info("status: not connected (server %s, %s)", sa_str(&c->server_addr, srv),
                 c->hs_active ? "handshake in progress" : "idle");
        return;
    }
    log_info("status: connected to %s, session %08x, address %s/%d, session age %lds, "
             "last rx %lds ago, rx %llu pkts/%llu B, tx %llu pkts/%llu B, reconnects %llu",
             sa_str(&c->server_addr, srv), c->ch.sid, ip_str(c->vip, ip), mask_to_prefix(c->netmask),
             (long)(c->now - c->session_start), (long)(c->now - c->last_rx),
             (unsigned long long)c->rx_pkts, (unsigned long long)c->rx_bytes,
             (unsigned long long)c->tx_pkts, (unsigned long long)c->tx_bytes,
             (unsigned long long)c->reconnects);
}

static void on_signal(client *c)
{
    struct signalfd_siginfo si;
    while (read(c->sigfd, &si, sizeof si) == (ssize_t)sizeof si) {
        if (si.ssi_signo == SIGUSR1) {
            print_status(c);
        } else {
            log_info("received %s, disconnecting", strsignal((int)si.ssi_signo));
            c->running = 0;
        }
    }
}

static int resolve_server(client *c)
{
    char port[8];
    struct addrinfo hints, *res;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    snprintf(port, sizeof port, "%u", c->cfg->port);

    int r = getaddrinfo(c->cfg->server_host, port, &hints, &res);
    if (r) {
        log_error("cannot resolve '%s': %s", c->cfg->server_host, gai_strerror(r));
        return -1;
    }
    memcpy(&c->server_addr, res->ai_addr, sizeof c->server_addr);
    freeaddrinfo(res);
    return 0;
}

int client_run(const client_config *cfg)
{
    char srv[SA_STRLEN];
    client c;
    memset(&c, 0, sizeof c);
    c.cfg = cfg;
    c.udp = c.tun = c.ep = c.sigfd = c.timerfd = -1;
    c.exit_code = 1;

    if (derive_auth_key(cfg->psk, c.auth_key)) {
        log_error("key derivation failed");
        goto out;
    }
    if (resolve_server(&c))
        goto out;

    snprintf(c.dev, sizeof c.dev, "%s", cfg->dev);
    if ((c.tun = tun_open(c.dev)) < 0)
        goto out;
    tun_disable_ipv6(c.dev);

    /* A connected UDP socket: the kernel drops datagrams from anyone but the
     * server and reports ICMP errors to us. */
    c.udp = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (c.udp < 0 || connect(c.udp, (struct sockaddr *)&c.server_addr, sizeof c.server_addr) < 0) {
        log_error("UDP socket to %s: %s", sa_str(&c.server_addr, srv), strerror(errno));
        goto out;
    }
    tune_socket_buffers(c.udp);

    if ((c.sigfd = make_signalfd()) < 0 || (c.timerfd = make_timerfd(1000)) < 0)
        goto out;
    if ((c.ep = epoll_create1(EPOLL_CLOEXEC)) < 0) {
        log_error("epoll_create1: %s", strerror(errno));
        goto out;
    }
    if (epoll_watch(c.ep, c.udp) || epoll_watch(c.ep, c.tun) || epoll_watch(c.ep, c.sigfd) ||
        epoll_watch(c.ep, c.timerfd))
        goto out;

    log_info("minivpn client %s: connecting to %s using %s", MINIVPN_VERSION,
             sa_str(&c.server_addr, srv), c.dev);

    c.exit_code = 0;
    c.running = 1;
    c.now = c.started = mono_now();
    start_handshake(&c);

    while (c.running) {
        struct epoll_event ev[8];
        int n = epoll_wait(c.ep, ev, 8, -1);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            log_error("epoll_wait: %s", strerror(errno));
            c.exit_code = 1;
            break;
        }
        c.now = mono_now();
        for (int i = 0; i < n && c.running; i++) {
            int fd = ev[i].data.fd;
            if (fd == c.udp) {
                on_udp(&c);
            } else if (fd == c.tun) {
                on_tun(&c);
            } else if (fd == c.timerfd) {
                uint64_t expirations;
                if (read(fd, &expirations, sizeof expirations) > 0)
                    on_tick(&c);
            } else if (fd == c.sigfd) {
                on_signal(&c);
            }
        }
    }

    if (c.connected)
        send_sealed(&c, PKT_DISCONNECT, NULL, 0);
    end_session(&c);
    if (c.host_route_added)
        route_del(ntohl(c.server_addr.sin_addr.s_addr), 0xffffffffu, c.orig_gw, c.orig_dev);

out:
    if (c.ep >= 0)
        close(c.ep);
    if (c.timerfd >= 0)
        close(c.timerfd);
    if (c.sigfd >= 0)
        close(c.sigfd);
    if (c.udp >= 0)
        close(c.udp);
    if (c.tun >= 0)
        close(c.tun); /* removes the interface and every route through it */
    secure_zero(c.auth_key, sizeof c.auth_key);
    secure_zero(&c.hs_kp, sizeof c.hs_kp);
    return c.exit_code;
}
