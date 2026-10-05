#include "proto.h"

#include "util.h"

#include <string.h>

#define HELLO_MAC_OFF   60
#define WELCOME_MAC_OFF 52

static const char AUTH_LABEL[] = "minivpn v2 handshake auth";
static const char KEYS_LABEL[] = "minivpn v2 session keys";

int derive_auth_key(const uint8_t psk[KEY_LEN], uint8_t out[KEY_LEN])
{
    return hkdf_sha256(NULL, 0, psk, KEY_LEN, (const uint8_t *)AUTH_LABEL, sizeof AUTH_LABEL - 1,
                       out, KEY_LEN);
}

int derive_session_keys(const uint8_t psk[KEY_LEN], const uint8_t shared[KEY_LEN],
                        const uint8_t device_id[DEVICE_ID_LEN],
                        const uint8_t client_pub[KEY_LEN], const uint8_t server_pub[KEY_LEN],
                        uint32_t sid, uint8_t c2s[KEY_LEN], uint8_t s2c[KEY_LEN])
{
    uint8_t info[sizeof KEYS_LABEL - 1 + DEVICE_ID_LEN + 2 * KEY_LEN + 4];
    uint8_t okm[2 * KEY_LEN];
    size_t off = 0;

    memcpy(info, KEYS_LABEL, sizeof KEYS_LABEL - 1);
    off += sizeof KEYS_LABEL - 1;
    memcpy(info + off, device_id, DEVICE_ID_LEN);
    off += DEVICE_ID_LEN;
    memcpy(info + off, client_pub, KEY_LEN);
    off += KEY_LEN;
    memcpy(info + off, server_pub, KEY_LEN);
    off += KEY_LEN;
    put_u32(info + off, sid);
    off += 4;

    int rc = hkdf_sha256(psk, KEY_LEN, shared, KEY_LEN, info, off, okm, sizeof okm);
    if (rc == 0) {
        memcpy(c2s, okm, KEY_LEN);
        memcpy(s2c, okm + KEY_LEN, KEY_LEN);
    }
    secure_zero(okm, sizeof okm);
    return rc;
}

int hello_build(uint8_t out[HELLO_LEN], const uint8_t auth_key[KEY_LEN], hello_msg *h)
{
    out[0] = PKT_HELLO;
    out[1] = PROTO_VERSION;
    out[2] = out[3] = 0;
    memcpy(out + 4, h->device_id, DEVICE_ID_LEN);
    memcpy(out + 20, h->pub, KEY_LEN);
    put_u64(out + 52, h->timestamp);
    if (hmac_sha256(auth_key, KEY_LEN, out, HELLO_MAC_OFF, out + HELLO_MAC_OFF))
        return -1;
    memcpy(h->mac, out + HELLO_MAC_OFF, MAC_LEN);
    return 0;
}

int hello_peek_device(const uint8_t *in, size_t len, uint8_t device_id[DEVICE_ID_LEN])
{
    if (len < 2 || in[0] != PKT_HELLO)
        return PARSE_MALFORMED;
    if (in[1] != PROTO_VERSION)
        return PARSE_VERSION;
    if (len != HELLO_LEN)
        return PARSE_MALFORMED;
    memcpy(device_id, in + 4, DEVICE_ID_LEN);
    return PARSE_OK;
}

int hello_parse(const uint8_t *in, size_t len, const uint8_t auth_key[KEY_LEN], hello_msg *h)
{
    uint8_t mac[MAC_LEN];

    int r = hello_peek_device(in, len, h->device_id);
    if (r != PARSE_OK)
        return r;
    if (hmac_sha256(auth_key, KEY_LEN, in, HELLO_MAC_OFF, mac) ||
        !ct_equal(mac, in + HELLO_MAC_OFF, MAC_LEN))
        return PARSE_AUTH;

    memcpy(h->pub, in + 20, KEY_LEN);
    h->timestamp = get_u64(in + 52);
    memcpy(h->mac, in + HELLO_MAC_OFF, MAC_LEN);
    return PARSE_OK;
}

/* MAC over hello_mac || welcome body: a WELCOME is only valid as the answer to
 * the exact HELLO the client sent, which stops replayed WELCOMEs. */
static int welcome_mac(const uint8_t auth_key[KEY_LEN], const uint8_t hello_mac[MAC_LEN],
                       const uint8_t *body, uint8_t out[MAC_LEN])
{
    uint8_t buf[MAC_LEN + WELCOME_MAC_OFF];
    memcpy(buf, hello_mac, MAC_LEN);
    memcpy(buf + MAC_LEN, body, WELCOME_MAC_OFF);
    return hmac_sha256(auth_key, KEY_LEN, buf, sizeof buf, out);
}

int welcome_build(uint8_t out[WELCOME_LEN], const uint8_t auth_key[KEY_LEN],
                  const uint8_t hello_mac[MAC_LEN], const welcome_msg *w)
{
    out[0] = PKT_WELCOME;
    out[1] = PROTO_VERSION;
    put_u16(out + 2, w->mtu);
    put_u32(out + 4, w->sid);
    memcpy(out + 8, w->pub, KEY_LEN);
    put_u32(out + 40, w->client_ip);
    put_u32(out + 44, w->netmask);
    put_u32(out + 48, w->server_ip);
    return welcome_mac(auth_key, hello_mac, out, out + WELCOME_MAC_OFF);
}

int welcome_parse(const uint8_t *in, size_t len, const uint8_t auth_key[KEY_LEN],
                  const uint8_t hello_mac[MAC_LEN], welcome_msg *w)
{
    uint8_t mac[MAC_LEN];

    if (len != WELCOME_LEN || in[0] != PKT_WELCOME)
        return PARSE_MALFORMED;
    if (in[1] != PROTO_VERSION)
        return PARSE_VERSION;
    if (welcome_mac(auth_key, hello_mac, in, mac) || !ct_equal(mac, in + WELCOME_MAC_OFF, MAC_LEN))
        return PARSE_AUTH;

    w->mtu = get_u16(in + 2);
    w->sid = get_u32(in + 4);
    memcpy(w->pub, in + 8, KEY_LEN);
    w->client_ip = get_u32(in + 40);
    w->netmask = get_u32(in + 44);
    w->server_ip = get_u32(in + 48);
    return PARSE_OK;
}

void data_header_build(uint8_t hdr[HDR_LEN], uint8_t type, uint32_t sid, uint64_t counter)
{
    hdr[0] = type;
    hdr[1] = hdr[2] = hdr[3] = 0;
    put_u32(hdr + 4, sid);
    put_u64(hdr + 8, counter);
}
