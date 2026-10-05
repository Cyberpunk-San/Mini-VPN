#include "crypto.h"

#include "util.h"

#include <openssl/crypto.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <string.h>

int crypto_random(void *buf, size_t len)
{
    return RAND_bytes(buf, (int)len) == 1 ? 0 : -1;
}

int x25519_keygen(x25519_keypair *kp)
{
    EVP_PKEY *pk = EVP_PKEY_Q_keygen(NULL, NULL, "X25519");
    if (!pk)
        return -1;
    size_t privlen = KEY_LEN, publen = KEY_LEN;
    int ok = EVP_PKEY_get_raw_private_key(pk, kp->priv, &privlen) == 1 &&
             EVP_PKEY_get_raw_public_key(pk, kp->pub, &publen) == 1 &&
             privlen == KEY_LEN && publen == KEY_LEN;
    EVP_PKEY_free(pk);
    return ok ? 0 : -1;
}

int x25519_shared(const uint8_t priv[KEY_LEN], const uint8_t peer_pub[KEY_LEN], uint8_t out[KEY_LEN])
{
    static const uint8_t zero[KEY_LEN];
    int rc = -1;
    size_t len = KEY_LEN;
    EVP_PKEY *me = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, priv, KEY_LEN);
    EVP_PKEY *peer = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, peer_pub, KEY_LEN);
    EVP_PKEY_CTX *ctx = me ? EVP_PKEY_CTX_new(me, NULL) : NULL;

    if (ctx && peer && EVP_PKEY_derive_init(ctx) == 1 && EVP_PKEY_derive_set_peer(ctx, peer) == 1 &&
        EVP_PKEY_derive(ctx, out, &len) == 1 && len == KEY_LEN)
        rc = CRYPTO_memcmp(out, zero, KEY_LEN) == 0 ? -1 : 0;

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(me);
    EVP_PKEY_free(peer);
    return rc;
}

int hmac_sha256(const uint8_t *key, size_t keylen, const uint8_t *data, size_t len, uint8_t out[MAC_LEN])
{
    unsigned int outlen = 0;
    if (!HMAC(EVP_sha256(), key, (int)keylen, data, len, out, &outlen))
        return -1;
    return outlen == MAC_LEN ? 0 : -1;
}

int hkdf_sha256(const uint8_t *salt, size_t saltlen, const uint8_t *ikm, size_t ikmlen,
                const uint8_t *info, size_t infolen, uint8_t *out, size_t outlen)
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    int ok = ctx && EVP_PKEY_derive_init(ctx) == 1 &&
             EVP_PKEY_CTX_set_hkdf_md(ctx, EVP_sha256()) == 1 &&
             (saltlen == 0 || EVP_PKEY_CTX_set1_hkdf_salt(ctx, salt, (int)saltlen) == 1) &&
             EVP_PKEY_CTX_set1_hkdf_key(ctx, ikm, (int)ikmlen) == 1 &&
             (infolen == 0 || EVP_PKEY_CTX_add1_hkdf_info(ctx, info, (int)infolen) == 1) &&
             EVP_PKEY_derive(ctx, out, &outlen) == 1;
    EVP_PKEY_CTX_free(ctx);
    return ok ? 0 : -1;
}

int aead_init(aead_ctx *a, const uint8_t key[KEY_LEN], int encrypt)
{
    a->ctx = EVP_CIPHER_CTX_new();
    if (!a->ctx)
        return -1;
    int ok = encrypt ? EVP_EncryptInit_ex(a->ctx, EVP_chacha20_poly1305(), NULL, key, NULL)
                     : EVP_DecryptInit_ex(a->ctx, EVP_chacha20_poly1305(), NULL, key, NULL);
    if (ok != 1) {
        aead_free(a);
        return -1;
    }
    return 0;
}

void aead_free(aead_ctx *a)
{
    EVP_CIPHER_CTX_free(a->ctx);
    a->ctx = NULL;
}

/* 96-bit nonce = 32 zero bits || 64-bit packet counter. Each direction has its
 * own key, so a (key, nonce) pair can never repeat. */
static void make_nonce(uint8_t nonce[NONCE_LEN], uint64_t counter)
{
    memset(nonce, 0, 4);
    put_u64(nonce + 4, counter);
}

int aead_seal(aead_ctx *a, uint64_t counter, const uint8_t *aad, size_t aadlen,
              const uint8_t *pt, size_t ptlen, uint8_t *out)
{
    uint8_t nonce[NONCE_LEN];
    int len = 0;
    size_t done = 0;

    make_nonce(nonce, counter);
    if (EVP_EncryptInit_ex(a->ctx, NULL, NULL, NULL, nonce) != 1)
        return -1;
    if (aadlen && EVP_EncryptUpdate(a->ctx, NULL, &len, aad, (int)aadlen) != 1)
        return -1;
    if (ptlen) {
        if (EVP_EncryptUpdate(a->ctx, out, &len, pt, (int)ptlen) != 1)
            return -1;
        done = (size_t)len;
    }
    if (EVP_EncryptFinal_ex(a->ctx, out + done, &len) != 1)
        return -1;
    done += (size_t)len;
    if (done != ptlen)
        return -1;
    return EVP_CIPHER_CTX_ctrl(a->ctx, EVP_CTRL_AEAD_GET_TAG, TAG_LEN, out + ptlen) == 1 ? 0 : -1;
}

int aead_open(aead_ctx *a, uint64_t counter, const uint8_t *aad, size_t aadlen,
              const uint8_t *in, size_t inlen, uint8_t *out)
{
    uint8_t nonce[NONCE_LEN];
    uint8_t tag[TAG_LEN];
    int len = 0;
    size_t done = 0;

    if (inlen < TAG_LEN)
        return -1;
    size_t ctlen = inlen - TAG_LEN;
    memcpy(tag, in + ctlen, TAG_LEN);

    make_nonce(nonce, counter);
    if (EVP_DecryptInit_ex(a->ctx, NULL, NULL, NULL, nonce) != 1)
        return -1;
    if (aadlen && EVP_DecryptUpdate(a->ctx, NULL, &len, aad, (int)aadlen) != 1)
        return -1;
    if (ctlen) {
        if (EVP_DecryptUpdate(a->ctx, out, &len, in, (int)ctlen) != 1)
            return -1;
        done = (size_t)len;
    }
    if (EVP_CIPHER_CTX_ctrl(a->ctx, EVP_CTRL_AEAD_SET_TAG, TAG_LEN, tag) != 1)
        return -1;
    if (EVP_DecryptFinal_ex(a->ctx, out + done, &len) != 1)
        return -1;
    return (int)ctlen;
}

int ed25519_keygen(uint8_t priv[KEY_LEN], uint8_t pub[KEY_LEN])
{
    EVP_PKEY *pk = EVP_PKEY_Q_keygen(NULL, NULL, "ED25519");
    if (!pk)
        return -1;
    size_t privlen = KEY_LEN, publen = KEY_LEN;
    int ok = EVP_PKEY_get_raw_private_key(pk, priv, &privlen) == 1 &&
             EVP_PKEY_get_raw_public_key(pk, pub, &publen) == 1 &&
             privlen == KEY_LEN && publen == KEY_LEN;
    EVP_PKEY_free(pk);
    return ok ? 0 : -1;
}

int ed25519_sign(const uint8_t priv[KEY_LEN], const uint8_t *msg, size_t len, uint8_t sig[SIG_LEN])
{
    EVP_PKEY *pk = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, priv, KEY_LEN);
    EVP_MD_CTX *md = EVP_MD_CTX_new();
    size_t siglen = SIG_LEN;
    int ok = pk && md && EVP_DigestSignInit(md, NULL, NULL, NULL, pk) == 1 &&
             EVP_DigestSign(md, sig, &siglen, msg, len) == 1 && siglen == SIG_LEN;
    EVP_MD_CTX_free(md);
    EVP_PKEY_free(pk);
    return ok ? 0 : -1;
}

int ed25519_verify(const uint8_t pub[KEY_LEN], const uint8_t *msg, size_t len, const uint8_t sig[SIG_LEN])
{
    EVP_PKEY *pk = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, pub, KEY_LEN);
    EVP_MD_CTX *md = EVP_MD_CTX_new();
    int ok = pk && md && EVP_DigestVerifyInit(md, NULL, NULL, NULL, pk) == 1 &&
             EVP_DigestVerify(md, sig, SIG_LEN, msg, len) == 1;
    EVP_MD_CTX_free(md);
    EVP_PKEY_free(pk);
    return ok;
}

int ct_equal(const void *a, const void *b, size_t len)
{
    return CRYPTO_memcmp(a, b, len) == 0;
}

void secure_zero(void *p, size_t len)
{
    OPENSSL_cleanse(p, len);
}
