#ifndef MINIVPN_CRYPTO_H
#define MINIVPN_CRYPTO_H

/* Thin wrappers over OpenSSL 3 for the primitives the protocol uses:
 * X25519 (key agreement), HMAC/HKDF-SHA256 (auth + key derivation) and
 * ChaCha20-Poly1305 (authenticated encryption of tunnel packets). */

#include <openssl/evp.h>
#include <stddef.h>
#include <stdint.h>

#define KEY_LEN   32
#define MAC_LEN   32
#define TAG_LEN   16
#define NONCE_LEN 12

typedef struct {
    uint8_t priv[KEY_LEN];
    uint8_t pub[KEY_LEN];
} x25519_keypair;

/* One direction of an AEAD channel; the key is bound once, the nonce per packet. */
typedef struct {
    EVP_CIPHER_CTX *ctx;
} aead_ctx;

int crypto_random(void *buf, size_t len);

int x25519_keygen(x25519_keypair *kp);
/* Fails on an all-zero result (low-order peer point). */
int x25519_shared(const uint8_t priv[KEY_LEN], const uint8_t peer_pub[KEY_LEN], uint8_t out[KEY_LEN]);

int hmac_sha256(const uint8_t *key, size_t keylen, const uint8_t *data, size_t len, uint8_t out[MAC_LEN]);
int hkdf_sha256(const uint8_t *salt, size_t saltlen, const uint8_t *ikm, size_t ikmlen,
                const uint8_t *info, size_t infolen, uint8_t *out, size_t outlen);

int aead_init(aead_ctx *a, const uint8_t key[KEY_LEN], int encrypt);
void aead_free(aead_ctx *a);
/* out receives ptlen bytes of ciphertext followed by the 16-byte tag. */
int aead_seal(aead_ctx *a, uint64_t counter, const uint8_t *aad, size_t aadlen,
              const uint8_t *pt, size_t ptlen, uint8_t *out);
/* in is ciphertext||tag. Returns plaintext length, or -1 if authentication fails. */
int aead_open(aead_ctx *a, uint64_t counter, const uint8_t *aad, size_t aadlen,
              const uint8_t *in, size_t inlen, uint8_t *out);

/* Ed25519 signatures (license files). */
#define SIG_LEN 64
int ed25519_keygen(uint8_t priv[KEY_LEN], uint8_t pub[KEY_LEN]);
int ed25519_sign(const uint8_t priv[KEY_LEN], const uint8_t *msg, size_t len, uint8_t sig[SIG_LEN]);
/* 1 if the signature is valid, 0 otherwise. */
int ed25519_verify(const uint8_t pub[KEY_LEN], const uint8_t *msg, size_t len, const uint8_t sig[SIG_LEN]);

int ct_equal(const void *a, const void *b, size_t len);
void secure_zero(void *p, size_t len);

#endif
