#ifndef MINIVPN_UTIL_H
#define MINIVPN_UTIL_H

#include <netinet/in.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>

#define SA_STRLEN 24 /* "255.255.255.255:65535" */

/* Big-endian (network order) field access for wire formats. */
static inline void put_u16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}

static inline void put_u32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static inline void put_u64(uint8_t *p, uint64_t v)
{
    for (int i = 7; i >= 0; i--) {
        p[i] = (uint8_t)v;
        v >>= 8;
    }
}

static inline uint16_t get_u16(const uint8_t *p)
{
    return (uint16_t)((p[0] << 8) | p[1]);
}

static inline uint32_t get_u32(const uint8_t *p)
{
    return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3];
}

static inline uint64_t get_u64(const uint8_t *p)
{
    uint64_t v = 0;
    for (int i = 0; i < 8; i++)
        v = v << 8 | p[i];
    return v;
}

/* Seconds on a clock that never jumps (used for all timeouts). */
time_t mono_now(void);

/* Parses "a.b.c.d/len" (or a bare address = /32). Outputs are host order.
 * Returns the prefix length, or -1 on error. */
int parse_cidr(const char *s, uint32_t *net, uint32_t *mask);
int mask_to_prefix(uint32_t mask);

const char *ip_str(uint32_t ip_host_order, char buf[INET_ADDRSTRLEN]);
const char *sa_str(const struct sockaddr_in *sa, char buf[SA_STRLEN]);

/* Decodes exactly outlen bytes of hex, ignoring whitespace. 0 on success. */
int hex_decode(const char *in, uint8_t *out, size_t outlen);
void hex_encode(const uint8_t *in, size_t len, char *out /* 2*len+1 */);

#endif
