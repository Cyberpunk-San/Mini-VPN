#ifndef MINIVPN_REPLAY_H
#define MINIVPN_REPLAY_H

/* Sliding-window anti-replay filter (RFC 6479 style ring bitmap). Accepts
 * counters that are new, or up to REPLAY_WINDOW-1 behind the highest seen and
 * not yet used, so UDP reordering is tolerated but duplicates are not. */

#include <stdint.h>

#define REPLAY_WINDOW 1024
#define REPLAY_WORDS  (REPLAY_WINDOW / 64)

typedef struct {
    uint64_t top;
    uint64_t bits[REPLAY_WORDS];
    int seen_any;
} replay_window;

/* 0 if ctr would be accepted, -1 if it is a replay or too old. Does not modify. */
int replay_check(const replay_window *w, uint64_t ctr);
/* Marks ctr as used. Call only after the packet authenticated. */
void replay_update(replay_window *w, uint64_t ctr);

#endif
