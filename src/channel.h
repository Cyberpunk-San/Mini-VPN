#ifndef MINIVPN_CHANNEL_H
#define MINIVPN_CHANNEL_H

/* An established, encrypted session: per-direction keys, the outgoing packet
 * counter and the incoming replay window. Shared by client and server. */

#include <stdint.h>
#include <sys/types.h>

#include "crypto.h"
#include "replay.h"

typedef struct {
    uint32_t sid;
    aead_ctx tx;
    aead_ctx rx;
    uint64_t tx_counter;
    replay_window replay;
} channel;

enum {
    CH_ERR_SHORT = -1,
    CH_ERR_REPLAY = -2,
    CH_ERR_AUTH = -3,
};

int channel_init(channel *c, uint32_t sid, const uint8_t tx_key[KEY_LEN], const uint8_t rx_key[KEY_LEN]);
void channel_free(channel *c);

/* Writes header||ciphertext||tag to out (len + WIRE_OVERHEAD bytes). Returns the wire length. */
ssize_t channel_seal(channel *c, uint8_t type, const uint8_t *pt, size_t len, uint8_t *out);

/* Authenticates and decrypts a packet whose sid the caller already matched.
 * Returns the plaintext length or a CH_ERR_* code. */
ssize_t channel_open(channel *c, const uint8_t *in, size_t len, uint8_t *type, uint8_t *out);

#endif
