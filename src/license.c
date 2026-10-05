#include "license.h"

#include "config.h"
#include "crypto.h"
#include "json.h"
#include "license_pubkey.h"
#include "log.h"
#include "util.h"

#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

#define MAX_LICENSED_DEVICES 100000

static int set_field(char *dst, size_t len, const char *value)
{
    if (strlen(value) >= len)
        return -1;
    snprintf(dst, len, "%s", value);
    return 0;
}

static int license_cb(void *ctx, const char *key, const char *value, const char *path, int line)
{
    license_fields *f = ctx;
    struct { const char *name; char *dst; size_t len; } map[] = {
        { "customer", f->customer, sizeof f->customer },
        { "edition", f->edition, sizeof f->edition },
        { "max_devices", f->max_devices, sizeof f->max_devices },
        { "issued", f->issued, sizeof f->issued },
        { "expires", f->expires, sizeof f->expires },
        { "license_id", f->license_id, sizeof f->license_id },
        { "signature", f->signature, sizeof f->signature },
    };
    for (size_t i = 0; i < sizeof map / sizeof map[0]; i++) {
        if (!strcmp(key, map[i].name)) {
            if (set_field(map[i].dst, map[i].len, value)) {
                log_error("%s:%d: value for '%s' is too long", path, line, key);
                return -1;
            }
            return 0;
        }
    }
    log_error("%s:%d: unknown license field '%s'", path, line, key);
    return -1;
}

static int valid_date(const char *s)
{
    int y, m, d;
    char tail;
    if (strlen(s) != 10 || sscanf(s, "%4d-%2d-%2d%c", &y, &m, &d, &tail) != 3)
        return 0;
    return y >= 2000 && y <= 9999 && m >= 1 && m <= 12 && d >= 1 && d <= 31 && s[4] == '-' && s[7] == '-';
}

const char *license_fields_error(const license_fields *f)
{
    if (!f->customer[0])
        return "customer is missing";
    for (const char *p = f->customer; *p; p++)
        if (!isprint((unsigned char)*p) || *p == '#' || *p == '"' || *p == '\\')
            return "customer contains unsupported characters";
    if (strcmp(f->edition, "business") && strcmp(f->edition, "enterprise"))
        return "edition must be 'business' or 'enterprise'";
    char *end;
    long n = strtol(f->max_devices, &end, 10);
    if (!f->max_devices[0] || *end || n < 1 || n > MAX_LICENSED_DEVICES)
        return "max_devices must be a number from 1 to 100000";
    if (!valid_date(f->issued) || !valid_date(f->expires))
        return "dates must be YYYY-MM-DD";
    if (strcmp(f->expires, f->issued) < 0)
        return "expires is before issued";
    if (!f->license_id[0])
        return "license_id is missing";
    for (const char *p = f->license_id; *p; p++)
        if (!isalnum((unsigned char)*p) && *p != '-')
            return "license_id contains unsupported characters";
    return NULL;
}

int license_canonical(const license_fields *f, char *out, size_t outlen)
{
    int n = snprintf(out, outlen,
                     "minivpn-license-v1\ncustomer=%s\nedition=%s\nmax_devices=%s\nissued=%s\nexpires=%s\nlicense_id=%s\n",
                     f->customer, f->edition, f->max_devices, f->issued, f->expires, f->license_id);
    return (n < 0 || (size_t)n >= outlen) ? -1 : n;
}

static void today_utc(char out[16])
{
    time_t now = time(NULL);
    struct tm tm;
    gmtime_r(&now, &tm);
    strftime(out, 16, "%Y-%m-%d", &tm);
}

static void community(license_info *out, enum license_status status, const char *why)
{
    license_fields keep = out->fields;
    memset(out, 0, sizeof *out);
    out->fields = keep;
    out->status = status;
    out->max_devices = COMMUNITY_MAX_DEVICES;
    snprintf(out->message, sizeof out->message, "%s; running as Community edition (up to %d devices)",
             why, COMMUNITY_MAX_DEVICES);
}

void license_load(const char *path, license_info *out)
{
    char canon[512], today[16];
    uint8_t sig[SIG_LEN];
    struct stat st;

    memset(out, 0, sizeof *out);
    if (!path || !*path || (stat(path, &st) < 0 && errno == ENOENT)) {
        community(out, LICENSE_NONE, "no license installed");
        return;
    }
    if (config_parse(path, license_cb, &out->fields)) {
        memset(&out->fields, 0, sizeof out->fields);
        community(out, LICENSE_INVALID, "license file is unreadable or malformed");
        return;
    }
    const char *err = license_fields_error(&out->fields);
    if (err) {
        char why[160];
        snprintf(why, sizeof why, "license rejected: %s", err);
        community(out, LICENSE_INVALID, why);
        return;
    }
    if (hex_decode(out->fields.signature, sig, SIG_LEN) ||
        license_canonical(&out->fields, canon, sizeof canon) < 0 ||
        !ed25519_verify(LICENSE_PUBKEY, (const uint8_t *)canon, strlen(canon), sig)) {
        community(out, LICENSE_INVALID, "license signature is not valid (file modified or not issued by the vendor)");
        return;
    }

    today_utc(today);
    if (strcmp(today, out->fields.expires) > 0) {
        char why[160];
        snprintf(why, sizeof why, "license for %s expired on %s", out->fields.customer, out->fields.expires);
        community(out, LICENSE_EXPIRED, why);
        return;
    }

    out->status = LICENSE_VALID;
    out->max_devices = (unsigned)strtoul(out->fields.max_devices, NULL, 10);
    snprintf(out->message, sizeof out->message, "%s edition licensed to %s for %u devices, valid until %s",
             out->fields.edition, out->fields.customer, out->max_devices, out->fields.expires);
}

const char *license_status_name(enum license_status s)
{
    switch (s) {
    case LICENSE_VALID: return "valid";
    case LICENSE_EXPIRED: return "expired";
    case LICENSE_INVALID: return "invalid";
    default: return "none";
    }
}

void license_write_json(const license_info *li, FILE *out)
{
    int licensed = li->status == LICENSE_VALID;
    fputs("{\"status\":", out);
    json_string(out, license_status_name(li->status));
    fputs(",\"edition\":", out);
    json_string(out, licensed ? li->fields.edition : "community");
    fputs(",\"customer\":", out);
    json_string(out, li->fields.customer);
    fprintf(out, ",\"max_devices\":%u,\"expires\":", li->max_devices);
    json_string(out, li->fields.expires);
    fputs(",\"license_id\":", out);
    json_string(out, li->fields.license_id);
    fputs(",\"message\":", out);
    json_string(out, li->message);
    fputc('}', out);
}
