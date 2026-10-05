#include "channel.h"

#include "proto.h"
#include "util.h"

#include <string.h>

int channel_init(channel *c, uint32_t sid, const uint8_t tx_key[KEY_LEN], const uint8_t rx_key[KEY_LEN])
{
    memset(c, 0, sizeof *c);
    c->sid = sid;
    if (aead_init(&c->tx, tx_key, 1) || aead_init(&c->rx, rx_key, 0)) {
        channel_free(c);
        return -1;
    }
    return 0;
}

void channel_free(channel *c)
{
    aead_free(&c->tx);
    aead_free(&c->rx);
}

ssize_t channel_seal(channel *c, uint8_t type, const uint8_t *pt, size_t len, uint8_t *out)
{
    if (c->tx_counter == UINT64_MAX)
        return -1;
    uint64_t counter = c->tx_counter++;
    data_header_build(out, type, c->sid, counter);
    if (aead_seal(&c->tx, counter, out, HDR_LEN, pt, len, out + HDR_LEN))
        return -1;
    return (ssize_t)(HDR_LEN + len + TAG_LEN);
}

ssize_t channel_open(channel *c, const uint8_t *in, size_t len, uint8_t *type, uint8_t *out)
{
    if (len < WIRE_OVERHEAD)
        return CH_ERR_SHORT;

    uint64_t counter = get_u64(in + 8);
    /* Cheap check first; the window is only advanced once the tag verifies,
     * so forged packets cannot push legitimate counters out of the window. */
    if (replay_check(&c->replay, counter))
        return CH_ERR_REPLAY;

    int n = aead_open(&c->rx, counter, in, HDR_LEN, in + HDR_LEN, len - HDR_LEN, out);
    if (n < 0)
        return CH_ERR_AUTH;

    replay_update(&c->replay, counter);
    *type = in[0];
    return n;
}
