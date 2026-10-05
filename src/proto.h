#ifndef MINIVPN_PROTO_H
#define MINIVPN_PROTO_H

/* Wire protocol (all integers big-endian). See docs/PROTOCOL.md for the full spec.
 *
 * HELLO    client -> server, 92 bytes, authenticated with HMAC(device auth_key)
 *   type(1)=1 | version(1) | reserved(2) | device_id(16) | client_pub(32) | unix_time(8) | mac(32)
 *
 * WELCOME  server -> client, 84 bytes, HMAC binds it to the HELLO it answers
 *   type(1)=2 | version(1) | mtu(2) | sid(4) | server_pub(32) |
 *   client_ip(4) | netmask(4) | server_ip(4) | mac(32)
 *
 * DATA / KEEPALIVE / DISCONNECT  (ChaCha20-Poly1305, header is the AAD)
 *   type(1) | reserved(3) | sid(4) | counter(8) | ciphertext(n) | tag(16)
 */

#include <stddef.h>
#include <stdint.h>

#include "crypto.h"

#define PROTO_VERSION 2
#define DEVICE_ID_LEN 16
#define DEFAULT_PORT  51900
#define DEFAULT_MTU   1400
#define MIN_MTU       576
#define MAX_MTU       1500
#define BUF_SIZE      2048

#define HDR_LEN       16
#define WIRE_OVERHEAD (HDR_LEN + TAG_LEN)
#define HELLO_LEN     92
#define WELCOME_LEN   84

/* Timers, in seconds. */
#define KEEPALIVE_INTERVAL 10
#define SESSION_TIMEOUT    60 /* server forgets a silent client */
#define DEAD_PEER_TIMEOUT  30 /* client gives up on a silent server and reconnects */
#define HELLO_MAX_SKEW     60 /* max clock difference accepted in a HELLO */
#define HANDSHAKE_TIMEOUT  45 /* client restarts a handshake with fresh keys */
#define DEFAULT_REKEY      300

enum pkt_type {
    PKT_HELLO = 1,
    PKT_WELCOME = 2,
    PKT_DATA = 3,
    PKT_KEEPALIVE = 4,
    PKT_DISCONNECT = 5,
};

enum parse_result {
    PARSE_OK = 0,
    PARSE_MALFORMED = -1,
    PARSE_VERSION = -2,
    PARSE_AUTH = -3,
};

typedef struct {
    uint8_t device_id[DEVICE_ID_LEN]; /* selects which device key authenticates the HELLO */
    uint8_t pub[KEY_LEN];
    uint64_t timestamp;
    uint8_t mac[MAC_LEN];
} hello_msg;

typedef struct {
    uint16_t mtu;
    uint32_t sid;
    uint8_t pub[KEY_LEN];
    uint32_t client_ip; /* host order */
    uint32_t netmask;
    uint32_t server_ip;
} welcome_msg;

/* auth_key = HKDF(ikm=device key, info="minivpn v2 handshake auth") */
int derive_auth_key(const uint8_t psk[KEY_LEN], uint8_t out[KEY_LEN]);

/* c2s||s2c = HKDF(salt=device key, ikm=X25519 shared secret,
 *                 info="minivpn v2 session keys"||device_id||client_pub||server_pub||sid) */
int derive_session_keys(const uint8_t psk[KEY_LEN], const uint8_t shared[KEY_LEN],
                        const uint8_t device_id[DEVICE_ID_LEN],
                        const uint8_t client_pub[KEY_LEN], const uint8_t server_pub[KEY_LEN],
                        uint32_t sid, uint8_t c2s[KEY_LEN], uint8_t s2c[KEY_LEN]);

/* Serializes h (device_id, pub, timestamp) and stores the computed MAC in h->mac. */
int hello_build(uint8_t out[HELLO_LEN], const uint8_t auth_key[KEY_LEN], hello_msg *h);
/* Reads the (unauthenticated) device id so the server can look up the right key. */
int hello_peek_device(const uint8_t *in, size_t len, uint8_t device_id[DEVICE_ID_LEN]);
int hello_parse(const uint8_t *in, size_t len, const uint8_t auth_key[KEY_LEN], hello_msg *h);

int welcome_build(uint8_t out[WELCOME_LEN], const uint8_t auth_key[KEY_LEN],
                  const uint8_t hello_mac[MAC_LEN], const welcome_msg *w);
int welcome_parse(const uint8_t *in, size_t len, const uint8_t auth_key[KEY_LEN],
                  const uint8_t hello_mac[MAC_LEN], welcome_msg *w);

void data_header_build(uint8_t hdr[HDR_LEN], uint8_t type, uint32_t sid, uint64_t counter);

#endif
