#ifndef MINIVPN_DEVICES_H
#define MINIVPN_DEVICES_H

/* The device registry: every laptop/phone allowed to connect, with its own key
 * and fixed tunnel address. Managed by minivpn-admin, read by the server.
 *
 * One device per line, whitespace separated:
 *   <device_id 32 hex> <key 64 hex> <tunnel ip> <active|disabled> <created unix time> <name>
 */

#include <stddef.h>
#include <stdint.h>

#include "crypto.h"
#include "proto.h"

#define DEVICE_NAME_MAX 32

typedef struct {
    uint8_t id[DEVICE_ID_LEN];
    uint8_t key[KEY_LEN];
    uint8_t auth_key[KEY_LEN]; /* derived once at load time */
    uint32_t ip;
    char name[DEVICE_NAME_MAX + 1];
} device;

typedef struct {
    device *items;
    size_t count;
    size_t over_limit; /* active devices ignored because of the license limit */
    size_t invalid;    /* malformed or conflicting lines that were skipped */
} device_table;

/* Loads active devices whose address lies inside net/mask (excluding the
 * network, server and broadcast addresses). At most max_devices are loaded.
 * Returns 0 on success (individual bad lines are skipped with a warning), -1
 * if the file can't be read. */
int devices_load(const char *path, uint32_t net, uint32_t mask, uint32_t server_ip,
                 size_t max_devices, device_table *out);
void devices_free(device_table *t);
const device *devices_find(const device_table *t, const uint8_t id[DEVICE_ID_LEN]);

/* Allowed characters for device names: letters, digits, '.', '_', '-'. */
int device_name_valid(const char *name);

#endif
