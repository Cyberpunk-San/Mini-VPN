#include "replay.h"

#include <string.h>

static int bit_get(const replay_window *w, uint64_t ctr)
{
    uint64_t slot = ctr % REPLAY_WINDOW;
    return (w->bits[slot / 64] >> (slot % 64)) & 1;
}

static void bit_set(replay_window *w, uint64_t ctr)
{
    uint64_t slot = ctr % REPLAY_WINDOW;
    w->bits[slot / 64] |= 1ull << (slot % 64);
}

static void bit_clear(replay_window *w, uint64_t ctr)
{
    uint64_t slot = ctr % REPLAY_WINDOW;
    w->bits[slot / 64] &= ~(1ull << (slot % 64));
}

int replay_check(const replay_window *w, uint64_t ctr)
{
    if (!w->seen_any || ctr > w->top)
        return 0;
    if (w->top - ctr >= REPLAY_WINDOW)
        return -1;
    return bit_get(w, ctr) ? -1 : 0;
}

void replay_update(replay_window *w, uint64_t ctr)
{
    if (!w->seen_any) {
        memset(w->bits, 0, sizeof w->bits);
        w->top = ctr;
        w->seen_any = 1;
    } else if (ctr > w->top) {
        /* Slots for counters we skipped over now belong to the new range. */
        if (ctr - w->top >= REPLAY_WINDOW) {
            memset(w->bits, 0, sizeof w->bits);
        } else {
            for (uint64_t c = w->top + 1; c <= ctr; c++)
                bit_clear(w, c);
        }
        w->top = ctr;
    }
    bit_set(w, ctr);
}
