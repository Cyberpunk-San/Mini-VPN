#ifndef MINIVPN_LICENSE_H
#define MINIVPN_LICENSE_H

/* Editions and license files.
 *
 * Without a license the server runs as Community edition (COMMUNITY_MAX_DEVICES).
 * A Business license is a small text file signed with the vendor's Ed25519 key;
 * the matching public key is compiled in (license_pubkey.h). Any edit to the
 * file invalidates the signature. An expired or invalid license never stops
 * the VPN: it falls back to Community limits and says why. */

#include <stdio.h>

#define COMMUNITY_MAX_DEVICES 5

enum license_status {
    LICENSE_NONE,     /* no license file: Community edition */
    LICENSE_VALID,
    LICENSE_EXPIRED,
    LICENSE_INVALID,  /* unreadable, malformed or bad signature */
};

typedef struct {
    char customer[128];
    char edition[32];
    char max_devices[16];
    char issued[16];  /* YYYY-MM-DD */
    char expires[16]; /* YYYY-MM-DD */
    char license_id[40];
    char signature[160];
} license_fields;

typedef struct {
    enum license_status status;
    license_fields fields;
    unsigned max_devices; /* effective device limit */
    char message[192];    /* human-readable explanation */
} license_info;

/* Loads and verifies path (NULL or missing -> Community). Never fails. */
void license_load(const char *path, license_info *out);

/* Canonical byte string that is signed: fixed key order, one "key=value\n" each. */
int license_canonical(const license_fields *f, char *out, size_t outlen);

/* Checks field syntax (dates, numbers, characters). Returns NULL or a reason. */
const char *license_fields_error(const license_fields *f);

const char *license_status_name(enum license_status s);
void license_write_json(const license_info *li, FILE *out);

#endif
