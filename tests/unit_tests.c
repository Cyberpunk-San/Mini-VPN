/* Unit tests for the protocol core. Crypto wrappers are checked against
 * published RFC test vectors; the rest against hand-built scenarios. */

#include "channel.h"
#include "crypto.h"
#include "devices.h"
#include "license.h"
#include "log.h"
#include "proto.h"
#include "replay.h"
#include "util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int checks, failures;

#define CHECK(cond)                                                              \
    do {                                                                         \
        checks++;                                                                \
        if (!(cond)) {                                                           \
            failures++;                                                          \
            fprintf(stderr, "  FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);    \
        }                                                                        \
    } while (0)

static void unhex(const char *hex, uint8_t *out, size_t len)
{
    if (hex_decode(hex, out, len)) {
        fprintf(stderr, "bad test vector: %s\n", hex);
        exit(2);
    }
}

static void test_hmac_rfc4231(void)
{
    uint8_t out[MAC_LEN], want[MAC_LEN];
    unhex("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843", want, sizeof want);
    CHECK(hmac_sha256((const uint8_t *)"Jefe", 4, (const uint8_t *)"what do ya want for nothing?", 28, out) == 0);
    CHECK(memcmp(out, want, sizeof want) == 0);
}

static void test_hkdf_rfc5869(void)
{
    uint8_t ikm[22], salt[13], info[10], okm[42], want[42];
    memset(ikm, 0x0b, sizeof ikm);
    for (int i = 0; i < 13; i++)
        salt[i] = (uint8_t)i;
    for (int i = 0; i < 10; i++)
        info[i] = (uint8_t)(0xf0 + i);
    unhex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
          want, sizeof want);
    CHECK(hkdf_sha256(salt, sizeof salt, ikm, sizeof ikm, info, sizeof info, okm, sizeof okm) == 0);
    CHECK(memcmp(okm, want, sizeof want) == 0);
}

static void test_x25519(void)
{
    uint8_t alice_priv[KEY_LEN], bob_pub[KEY_LEN], want[KEY_LEN], out[KEY_LEN];
    unhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a", alice_priv, KEY_LEN);
    unhex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f", bob_pub, KEY_LEN);
    unhex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742", want, KEY_LEN);
    CHECK(x25519_shared(alice_priv, bob_pub, out) == 0); /* RFC 7748 section 6.1 */
    CHECK(memcmp(out, want, KEY_LEN) == 0);

    x25519_keypair a, b;
    uint8_t s1[KEY_LEN], s2[KEY_LEN];
    CHECK(x25519_keygen(&a) == 0 && x25519_keygen(&b) == 0);
    CHECK(x25519_shared(a.priv, b.pub, s1) == 0 && x25519_shared(b.priv, a.pub, s2) == 0);
    CHECK(memcmp(s1, s2, KEY_LEN) == 0);

    static const uint8_t zero_point[KEY_LEN];
    CHECK(x25519_shared(a.priv, zero_point, s1) != 0); /* low-order point must be rejected */
}

static void test_aead(void)
{
    uint8_t key[KEY_LEN], ct[64 + TAG_LEN], pt[64];
    const uint8_t aad[] = "header";
    const uint8_t msg[] = "attack at dawn";
    aead_ctx enc, dec;

    CHECK(crypto_random(key, sizeof key) == 0);
    CHECK(aead_init(&enc, key, 1) == 0 && aead_init(&dec, key, 0) == 0);

    for (uint64_t ctr = 0; ctr < 5; ctr++) { /* context reuse across packets */
        CHECK(aead_seal(&enc, ctr, aad, sizeof aad, msg, sizeof msg, ct) == 0);
        CHECK(aead_open(&dec, ctr, aad, sizeof aad, ct, sizeof msg + TAG_LEN, pt) == (int)sizeof msg);
        CHECK(memcmp(pt, msg, sizeof msg) == 0);
    }

    CHECK(aead_seal(&enc, 9, aad, sizeof aad, msg, sizeof msg, ct) == 0);
    CHECK(aead_open(&dec, 10, aad, sizeof aad, ct, sizeof msg + TAG_LEN, pt) < 0); /* wrong nonce */
    CHECK(aead_open(&dec, 9, (const uint8_t *)"HEADER", 7, ct, sizeof msg + TAG_LEN, pt) < 0); /* wrong AAD */
    ct[3] ^= 1;
    CHECK(aead_open(&dec, 9, aad, sizeof aad, ct, sizeof msg + TAG_LEN, pt) < 0); /* flipped bit */
    ct[3] ^= 1;
    CHECK(aead_open(&dec, 9, aad, sizeof aad, ct, sizeof msg + TAG_LEN, pt) == (int)sizeof msg);

    CHECK(aead_seal(&enc, 11, aad, sizeof aad, NULL, 0, ct) == 0); /* empty payload (keepalive) */
    CHECK(aead_open(&dec, 11, aad, sizeof aad, ct, TAG_LEN, pt) == 0);

    aead_free(&enc);
    aead_free(&dec);
}

static void test_replay(void)
{
    replay_window w;
    memset(&w, 0, sizeof w);

    for (uint64_t c = 0; c < 3; c++) {
        CHECK(replay_check(&w, c) == 0);
        replay_update(&w, c);
    }
    CHECK(replay_check(&w, 1) != 0); /* duplicate */

    replay_update(&w, 5);
    CHECK(replay_check(&w, 4) == 0); /* reordered but fresh */
    replay_update(&w, 4);
    CHECK(replay_check(&w, 4) != 0);
    CHECK(replay_check(&w, 3) == 0);

    replay_update(&w, 2000); /* big jump clears the window */
    CHECK(replay_check(&w, 2000) != 0);
    CHECK(replay_check(&w, 2000 - REPLAY_WINDOW) != 0); /* too old */
    CHECK(replay_check(&w, 2000 - REPLAY_WINDOW + 1) == 0);
    CHECK(replay_check(&w, 1000) == 0);
    replay_update(&w, 1000);
    CHECK(replay_check(&w, 1000) != 0);

    /* Ring aliasing: counter 10 and 1034 share a slot. */
    memset(&w, 0, sizeof w);
    replay_update(&w, 10);
    replay_update(&w, 1030);
    CHECK(replay_check(&w, 10) != 0);   /* still in window and used */
    CHECK(replay_check(&w, 11) == 0);
    replay_update(&w, 1034);            /* slot of 10 now belongs to 1034 */
    CHECK(replay_check(&w, 10) != 0);   /* fell out of the window */
    CHECK(replay_check(&w, 1034) != 0);
    CHECK(replay_check(&w, 1033) == 0);
}

static void test_channel(void)
{
    uint8_t k1[KEY_LEN], k2[KEY_LEN];
    uint8_t p1[BUF_SIZE], p2[BUF_SIZE], out[BUF_SIZE];
    const uint8_t msg[] = "an IP packet";
    channel a, b;
    uint8_t type;

    crypto_random(k1, sizeof k1);
    crypto_random(k2, sizeof k2);
    CHECK(channel_init(&a, 0x1234, k1, k2) == 0);
    CHECK(channel_init(&b, 0x1234, k2, k1) == 0);

    ssize_t n1 = channel_seal(&a, PKT_DATA, msg, sizeof msg, p1);
    ssize_t n2 = channel_seal(&a, PKT_KEEPALIVE, NULL, 0, p2);
    CHECK(n1 == (ssize_t)(sizeof msg + WIRE_OVERHEAD) && n2 == WIRE_OVERHEAD);
    CHECK(get_u32(p1 + 4) == 0x1234);

    /* Out of order delivery is fine... */
    CHECK(channel_open(&b, p2, (size_t)n2, &type, out) == 0 && type == PKT_KEEPALIVE);
    CHECK(channel_open(&b, p1, (size_t)n1, &type, out) == (ssize_t)sizeof msg && type == PKT_DATA);
    CHECK(memcmp(out, msg, sizeof msg) == 0);
    /* ...duplicates are not. */
    CHECK(channel_open(&b, p1, (size_t)n1, &type, out) == CH_ERR_REPLAY);

    /* Tampering with the header (AAD) breaks authentication. */
    ssize_t n3 = channel_seal(&a, PKT_DATA, msg, sizeof msg, p1);
    p1[0] = PKT_DISCONNECT;
    CHECK(channel_open(&b, p1, (size_t)n3, &type, out) == CH_ERR_AUTH);
    /* A forged packet must not burn the counter: the real one still gets through. */
    p1[0] = PKT_DATA;
    CHECK(channel_open(&b, p1, (size_t)n3, &type, out) == (ssize_t)sizeof msg);

    CHECK(channel_open(&b, p1, 10, &type, out) == CH_ERR_SHORT);

    /* Wrong direction key: a packet can't be reflected back to its sender. */
    ssize_t n4 = channel_seal(&a, PKT_DATA, msg, sizeof msg, p1);
    CHECK(channel_open(&a, p1, (size_t)n4, &type, out) == CH_ERR_AUTH);

    channel_free(&a);
    channel_free(&b);
}

static void test_handshake(void)
{
    uint8_t psk[KEY_LEN], other_psk[KEY_LEN], auth[KEY_LEN], other_auth[KEY_LEN];
    uint8_t hello[HELLO_LEN], welcome[WELCOME_LEN];
    x25519_keypair ck, sk;
    hello_msg h, hp;
    welcome_msg w, wp;

    crypto_random(psk, sizeof psk);
    crypto_random(other_psk, sizeof other_psk);
    CHECK(derive_auth_key(psk, auth) == 0 && derive_auth_key(other_psk, other_auth) == 0);
    CHECK(x25519_keygen(&ck) == 0 && x25519_keygen(&sk) == 0);

    uint8_t dev_id[DEVICE_ID_LEN], peeked[DEVICE_ID_LEN];
    crypto_random(dev_id, sizeof dev_id);

    memset(&h, 0, sizeof h);
    memcpy(h.device_id, dev_id, DEVICE_ID_LEN);
    memcpy(h.pub, ck.pub, KEY_LEN);
    h.timestamp = 1700000000;
    CHECK(hello_build(hello, auth, &h) == 0);

    CHECK(hello_peek_device(hello, HELLO_LEN, peeked) == PARSE_OK && !memcmp(peeked, dev_id, DEVICE_ID_LEN));
    CHECK(hello_parse(hello, HELLO_LEN, auth, &hp) == PARSE_OK);
    CHECK(memcmp(hp.pub, ck.pub, KEY_LEN) == 0 && hp.timestamp == 1700000000);
    CHECK(memcmp(hp.device_id, dev_id, DEVICE_ID_LEN) == 0 && memcmp(hp.mac, h.mac, MAC_LEN) == 0);
    CHECK(hello_parse(hello, HELLO_LEN, other_auth, &hp) == PARSE_AUTH);
    CHECK(hello_parse(hello, HELLO_LEN - 1, auth, &hp) == PARSE_MALFORMED);
    hello[1] = 1; /* old protocol version */
    CHECK(hello_parse(hello, HELLO_LEN, auth, &hp) == PARSE_VERSION);
    hello[1] = PROTO_VERSION;
    hello[55] ^= 0x80; /* tamper with the timestamp */
    CHECK(hello_parse(hello, HELLO_LEN, auth, &hp) == PARSE_AUTH);
    hello[55] ^= 0x80;
    hello[4] ^= 1; /* claim to be a different device with the same MAC */
    CHECK(hello_parse(hello, HELLO_LEN, auth, &hp) == PARSE_AUTH);

    memset(&w, 0, sizeof w);
    w.mtu = 1400;
    w.sid = 0x55667788;
    memcpy(w.pub, sk.pub, KEY_LEN);
    w.client_ip = 0x0a080002;
    w.netmask = 0xffffff00;
    w.server_ip = 0x0a080001;
    CHECK(welcome_build(welcome, auth, h.mac, &w) == 0);
    CHECK(welcome_parse(welcome, WELCOME_LEN, auth, h.mac, &wp) == PARSE_OK);
    CHECK(wp.mtu == 1400 && wp.sid == 0x55667788 && wp.client_ip == 0x0a080002 &&
          wp.netmask == 0xffffff00 && wp.server_ip == 0x0a080001 && memcmp(wp.pub, sk.pub, KEY_LEN) == 0);

    uint8_t wrong_mac[MAC_LEN];
    memcpy(wrong_mac, h.mac, MAC_LEN);
    wrong_mac[0] ^= 1;
    CHECK(welcome_parse(welcome, WELCOME_LEN, auth, wrong_mac, &wp) == PARSE_AUTH); /* bound to the HELLO */
    CHECK(welcome_parse(welcome, WELCOME_LEN, other_auth, h.mac, &wp) == PARSE_AUTH);

    /* Both ends derive identical, direction-separated keys. */
    uint8_t cs[KEY_LEN], ss[KEY_LEN], c_c2s[KEY_LEN], c_s2c[KEY_LEN], s_c2s[KEY_LEN], s_s2c[KEY_LEN];
    CHECK(x25519_shared(ck.priv, sk.pub, cs) == 0 && x25519_shared(sk.priv, ck.pub, ss) == 0);
    CHECK(derive_session_keys(psk, cs, dev_id, ck.pub, sk.pub, w.sid, c_c2s, c_s2c) == 0);
    CHECK(derive_session_keys(psk, ss, dev_id, ck.pub, sk.pub, w.sid, s_c2s, s_s2c) == 0);
    CHECK(memcmp(c_c2s, s_c2s, KEY_LEN) == 0 && memcmp(c_s2c, s_s2c, KEY_LEN) == 0);
    CHECK(memcmp(c_c2s, c_s2c, KEY_LEN) != 0);

    /* Knowing the DH secret is not enough without the device key. */
    CHECK(derive_session_keys(other_psk, cs, dev_id, ck.pub, sk.pub, w.sid, s_c2s, s_s2c) == 0);
    CHECK(memcmp(c_c2s, s_c2s, KEY_LEN) != 0);
}

static void test_ed25519(void)
{
    /* RFC 8032 section 7.1, test 1 (empty message). */
    uint8_t priv[KEY_LEN], pub[KEY_LEN], want[SIG_LEN], sig[SIG_LEN];
    unhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60", priv, KEY_LEN);
    unhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", pub, KEY_LEN);
    unhex("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
          "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b", want, SIG_LEN);
    CHECK(ed25519_sign(priv, (const uint8_t *)"", 0, sig) == 0);
    CHECK(memcmp(sig, want, SIG_LEN) == 0);
    CHECK(ed25519_verify(pub, (const uint8_t *)"", 0, sig) == 1);
    CHECK(ed25519_verify(pub, (const uint8_t *)"x", 1, sig) == 0);
    sig[0] ^= 1;
    CHECK(ed25519_verify(pub, (const uint8_t *)"", 0, sig) == 0);
}

static const char *write_temp(const char *content)
{
    static char path[64];
    snprintf(path, sizeof path, "/tmp/minivpn-unit-XXXXXX");
    int fd = mkstemp(path);
    if (fd < 0 || write(fd, content, strlen(content)) != (ssize_t)strlen(content)) {
        perror("temp file");
        exit(2);
    }
    close(fd);
    return path;
}

static void test_license(void)
{
    license_info li;

    license_load("/nonexistent/license.key", &li);
    CHECK(li.status == LICENSE_NONE && li.max_devices == COMMUNITY_MAX_DEVICES);
    license_load(NULL, &li);
    CHECK(li.status == LICENSE_NONE);

    const char *p = write_temp("customer = Acme\nedition = business\nmax_devices = 50\n"
                               "issued = 2026-01-01\nexpires = 2027-01-01\nlicense_id = LIC-1\n"
                               "signature = 00\n");
    license_load(p, &li);
    CHECK(li.status == LICENSE_INVALID && li.max_devices == COMMUNITY_MAX_DEVICES);
    unlink(p);

    p = write_temp("this is not a license\n");
    license_load(p, &li);
    CHECK(li.status == LICENSE_INVALID);
    unlink(p);

    license_fields f;
    memset(&f, 0, sizeof f);
    snprintf(f.customer, sizeof f.customer, "Acme Corp");
    snprintf(f.edition, sizeof f.edition, "business");
    snprintf(f.max_devices, sizeof f.max_devices, "50");
    snprintf(f.issued, sizeof f.issued, "2026-01-01");
    snprintf(f.expires, sizeof f.expires, "2027-01-01");
    snprintf(f.license_id, sizeof f.license_id, "LIC-abc");
    CHECK(license_fields_error(&f) == NULL);
    snprintf(f.max_devices, sizeof f.max_devices, "0");
    CHECK(license_fields_error(&f) != NULL);
    snprintf(f.max_devices, sizeof f.max_devices, "50");
    snprintf(f.expires, sizeof f.expires, "2025-12-31");
    CHECK(license_fields_error(&f) != NULL); /* expires before issued */
    snprintf(f.expires, sizeof f.expires, "2027-1-1");
    CHECK(license_fields_error(&f) != NULL);
}

static void test_devices(void)
{
    device_table t;
    uint32_t net = 0x0a080000, mask = 0xffffff00, srv = 0x0a080001;
    const char *k = "0000000000000000000000000000000000000000000000000000000000000001";
    char buf[2048];

    snprintf(buf, sizeof buf,
             "# comment\n\n"
             "00000000000000000000000000000001 %s 10.8.0.2 active 1700000000 alice\n"
             "00000000000000000000000000000002 %s 10.8.0.3 disabled 1700000000 bob\n"
             "00000000000000000000000000000003 %s 10.8.0.2 active 1700000000 carol\n"   /* dup ip */
             "00000000000000000000000000000004 %s 10.9.0.4 active 1700000000 dave\n"    /* outside */
             "00000000000000000000000000000005 %s 10.8.0.1 active 1700000000 eve\n"     /* server ip */
             "00000000000000000000000000000006 %s 10.8.0.6 active 1700000000 bad/name\n"
             "zz %s 10.8.0.7 active 1700000000 frank\n"
             "00000000000000000000000000000008 %s 10.8.0.8 active 1700000000 grace\n"
             "00000000000000000000000000000009 %s 10.8.0.9 active 1700000000 heidi\n",
             k, k, k, k, k, k, k, k, k);
    const char *p = write_temp(buf);

    CHECK(devices_load(p, net, mask, srv, 100, &t) == 0);
    CHECK(t.count == 3 && t.invalid == 5 && t.over_limit == 0);
    uint8_t id[DEVICE_ID_LEN];
    unhex("00000000000000000000000000000001", id, DEVICE_ID_LEN);
    const device *d = devices_find(&t, id);
    CHECK(d && d->ip == 0x0a080002 && !strcmp(d->name, "alice"));
    unhex("00000000000000000000000000000002", id, DEVICE_ID_LEN);
    CHECK(devices_find(&t, id) == NULL); /* disabled */
    devices_free(&t);

    CHECK(devices_load(p, net, mask, srv, 2, &t) == 0); /* license limit */
    CHECK(t.count == 2 && t.over_limit == 1);
    devices_free(&t);
    unlink(p);

    CHECK(devices_load("/nonexistent/devices", net, mask, srv, 5, &t) != 0);
    CHECK(device_name_valid("laptop-01.hq") && !device_name_valid("") && !device_name_valid("a b"));
}

static void test_util(void)
{
    uint32_t net, mask;
    CHECK(parse_cidr("10.8.0.77/24", &net, &mask) == 24 && net == 0x0a080000 && mask == 0xffffff00);
    CHECK(parse_cidr("0.0.0.0/0", &net, &mask) == 0 && net == 0 && mask == 0);
    CHECK(parse_cidr("1.2.3.4", &net, &mask) == 32 && mask == 0xffffffff);
    CHECK(parse_cidr("1.2.3.4/33", &net, &mask) < 0);
    CHECK(parse_cidr("1.2.3/24", &net, &mask) < 0);
    CHECK(parse_cidr("1.2.3.4/", &net, &mask) < 0);
    CHECK(mask_to_prefix(0xffff0000) == 16 && mask_to_prefix(0) == 0 && mask_to_prefix(0xff00ff00) < 0);

    uint8_t b[4];
    CHECK(hex_decode("de ad\nbe EF", b, 4) == 0 && get_u32(b) == 0xdeadbeef);
    CHECK(hex_decode("deadbe", b, 4) != 0);
    CHECK(hex_decode("deadbeef00", b, 4) != 0);
    CHECK(hex_decode("deadbeeg", b, 4) != 0);
}

int main(void)
{
    log_level = LVL_ERROR;

    struct { const char *name; void (*fn)(void); } tests[] = {
        { "HMAC-SHA256 (RFC 4231)", test_hmac_rfc4231 },
        { "HKDF-SHA256 (RFC 5869)", test_hkdf_rfc5869 },
        { "X25519 (RFC 7748)", test_x25519 },
        { "ChaCha20-Poly1305 AEAD", test_aead },
        { "anti-replay window", test_replay },
        { "encrypted channel", test_channel },
        { "handshake messages + key schedule", test_handshake },
        { "Ed25519 (RFC 8032)", test_ed25519 },
        { "license files", test_license },
        { "device registry", test_devices },
        { "parsing helpers", test_util },
    };

    for (size_t i = 0; i < sizeof tests / sizeof tests[0]; i++) {
        int before = failures;
        tests[i].fn();
        printf("  %-4s %s\n", failures == before ? "ok" : "FAIL", tests[i].name);
    }
    printf("%d checks, %d failed\n", checks, failures);
    return failures ? 1 : 0;
}
