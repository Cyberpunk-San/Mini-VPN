#include "config.h"

#include "log.h"

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>

static char *trim(char *s)
{
    while (isspace((unsigned char)*s))
        s++;
    char *end = s + strlen(s);
    while (end > s && isspace((unsigned char)end[-1]))
        *--end = '\0';
    return s;
}

int config_parse(const char *path, config_cb cb, void *ctx)
{
    FILE *f = fopen(path, "re");
    if (!f) {
        log_error("cannot open %s: %s", path, strerror(errno));
        return -1;
    }

    char buf[1024];
    int line = 0, rc = 0;
    while (fgets(buf, sizeof buf, f)) {
        line++;
        if (!strchr(buf, '\n') && !feof(f)) {
            log_error("%s:%d: line too long", path, line);
            rc = -1;
            break;
        }
        char *hash = strchr(buf, '#');
        if (hash)
            *hash = '\0';
        char *s = trim(buf);
        if (!*s)
            continue;
        char *eq = strchr(s, '=');
        if (!eq) {
            log_error("%s:%d: expected 'key = value'", path, line);
            rc = -1;
            break;
        }
        *eq = '\0';
        char *key = trim(s), *value = trim(eq + 1);
        if (!*key) {
            log_error("%s:%d: missing key", path, line);
            rc = -1;
            break;
        }
        if (cb(ctx, key, value, path, line)) {
            rc = -1;
            break;
        }
    }
    fclose(f);
    return rc;
}

int config_bool(const char *v)
{
    if (!strcasecmp(v, "yes") || !strcasecmp(v, "true") || !strcasecmp(v, "on") || !strcmp(v, "1"))
        return 1;
    if (!strcasecmp(v, "no") || !strcasecmp(v, "false") || !strcasecmp(v, "off") || !strcmp(v, "0"))
        return 0;
    return -1;
}

void warn_if_world_readable(const char *path, int allow_group)
{
    struct stat st;
    mode_t bad = allow_group ? 007 : 077;
    if (stat(path, &st) == 0 && (st.st_mode & bad))
        log_warn("%s contains secret keys but is readable by other users; fix with: chmod %s %s", path,
                 allow_group ? "640" : "600", path);
}
