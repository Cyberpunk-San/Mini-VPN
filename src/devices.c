#include "devices.h"

#include "log.h"
#include "util.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int device_name_valid(const char *name)
{
    size_t n = strlen(name);
    if (n == 0 || n > DEVICE_NAME_MAX)
        return 0;
    for (const char *p = name; *p; p++)
        if (!isalnum((unsigned char)*p) && *p != '.' && *p != '_' && *p != '-')
            return 0;
    return 1;
}

static int conflicts(const device_table *t, const device *d, const char **what)
{
    for (size_t i = 0; i < t->count; i++) {
        if (!memcmp(t->items[i].id, d->id, DEVICE_ID_LEN)) {
            *what = "duplicate device id";
            return 1;
        }
        if (t->items[i].ip == d->ip) {
            *what = "address already used by another device";
            return 1;
        }
        if (!strcmp(t->items[i].name, d->name)) {
            *what = "duplicate name";
            return 1;
        }
    }
    return 0;
}

int devices_load(const char *path, uint32_t net, uint32_t mask, uint32_t server_ip,
                 size_t max_devices, device_table *out)
{
    memset(out, 0, sizeof *out);
    FILE *f = fopen(path, "re");
    if (!f) {
        log_error("cannot open device registry %s: %s", path, strerror(errno));
        return -1;
    }

    size_t cap = 0;
    char line[512];
    int lineno = 0;
    uint32_t broadcast = net | ~mask;

    while (fgets(line, sizeof line, f)) {
        lineno++;
        char *hash = strchr(line, '#');
        if (hash)
            *hash = '\0';

        char id_hex[64], key_hex[128], ip_s[32], status[16], name[64];
        unsigned long long created;
        int n = sscanf(line, "%63s %127s %31s %15s %llu %63s", id_hex, key_hex, ip_s, status, &created, name);
        if (n <= 0)
            continue; /* blank or comment */

        device d;
        struct in_addr a;
        const char *why = NULL;
        memset(&d, 0, sizeof d);

        if (n != 6)
            why = "expected 6 fields";
        else if (hex_decode(id_hex, d.id, DEVICE_ID_LEN))
            why = "bad device id";
        else if (hex_decode(key_hex, d.key, KEY_LEN))
            why = "bad key";
        else if (inet_pton(AF_INET, ip_s, &a) != 1)
            why = "bad address";
        else if (!device_name_valid(name))
            why = "bad name";
        else if (strcmp(status, "active") && strcmp(status, "disabled"))
            why = "status must be 'active' or 'disabled'";

        if (!why) {
            d.ip = ntohl(a.s_addr);
            if ((d.ip & mask) != net || d.ip == net || d.ip == server_ip || d.ip == broadcast)
                why = "address outside the VPN subnet or reserved";
        }
        if (!why && !strcmp(status, "disabled"))
            continue;
        if (!why)
            conflicts(out, &d, &why);
        if (!why && derive_auth_key(d.key, d.auth_key))
            why = "key derivation failed";

        if (why) {
            log_warn("%s:%d: skipping device: %s", path, lineno, why);
            out->invalid++;
            secure_zero(&d, sizeof d);
            continue;
        }

        if (out->count >= max_devices) {
            out->over_limit++;
            secure_zero(&d, sizeof d);
            continue;
        }

        memcpy(d.name, name, strlen(name) + 1); /* length checked by device_name_valid() */
        if (out->count == cap) {
            size_t ncap = cap ? cap * 2 : 16;
            device *items = realloc(out->items, ncap * sizeof *items);
            if (!items) {
                log_error("out of memory loading devices");
                secure_zero(&d, sizeof d);
                fclose(f);
                devices_free(out);
                return -1;
            }
            out->items = items;
            cap = ncap;
        }
        out->items[out->count++] = d;
        secure_zero(&d, sizeof d);
    }
    secure_zero(line, sizeof line);
    fclose(f);
    return 0;
}

void devices_free(device_table *t)
{
    if (t->items)
        secure_zero(t->items, t->count * sizeof *t->items);
    free(t->items);
    memset(t, 0, sizeof *t);
}

const device *devices_find(const device_table *t, const uint8_t id[DEVICE_ID_LEN])
{
    for (size_t i = 0; i < t->count; i++)
        if (ct_equal(t->items[i].id, id, DEVICE_ID_LEN))
            return &t->items[i];
    return NULL;
}
