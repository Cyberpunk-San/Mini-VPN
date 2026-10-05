#include "util.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

time_t mono_now(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec;
}

int parse_cidr(const char *s, uint32_t *net, uint32_t *mask)
{
    char buf[64];
    if (strlen(s) >= sizeof buf)
        return -1;
    strcpy(buf, s);

    int prefix = 32;
    char *slash = strchr(buf, '/');
    if (slash) {
        char *end;
        *slash = '\0';
        long p = strtol(slash + 1, &end, 10);
        if (end == slash + 1 || *end || p < 0 || p > 32)
            return -1;
        prefix = (int)p;
    }

    struct in_addr a;
    if (inet_pton(AF_INET, buf, &a) != 1)
        return -1;

    uint32_t m = prefix ? 0xffffffffu << (32 - prefix) : 0;
    *mask = m;
    *net = ntohl(a.s_addr) & m;
    return prefix;
}

int mask_to_prefix(uint32_t mask)
{
    int p = 0;
    while (p < 32 && (mask & (0x80000000u >> p)))
        p++;
    uint32_t expect = p ? 0xffffffffu << (32 - p) : 0;
    return expect == mask ? p : -1;
}

const char *ip_str(uint32_t ip, char buf[INET_ADDRSTRLEN])
{
    struct in_addr a = { .s_addr = htonl(ip) };
    return inet_ntop(AF_INET, &a, buf, INET_ADDRSTRLEN);
}

const char *sa_str(const struct sockaddr_in *sa, char buf[SA_STRLEN])
{
    char ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &sa->sin_addr, ip, sizeof ip);
    snprintf(buf, SA_STRLEN, "%s:%u", ip, ntohs(sa->sin_port));
    return buf;
}

static int hexval(int c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    c = tolower(c);
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    return -1;
}

int hex_decode(const char *in, uint8_t *out, size_t outlen)
{
    size_t n = 0;
    int hi = -1;
    for (; *in; in++) {
        if (isspace((unsigned char)*in))
            continue;
        int v = hexval((unsigned char)*in);
        if (v < 0)
            return -1;
        if (hi < 0) {
            hi = v;
        } else {
            if (n >= outlen)
                return -1;
            out[n++] = (uint8_t)(hi << 4 | v);
            hi = -1;
        }
    }
    return (n == outlen && hi < 0) ? 0 : -1;
}

void hex_encode(const uint8_t *in, size_t len, char *out)
{
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        out[2 * i] = digits[in[i] >> 4];
        out[2 * i + 1] = digits[in[i] & 15];
    }
    out[2 * len] = '\0';
}
