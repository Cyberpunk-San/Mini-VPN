#ifndef MINIVPN_CONFIG_H
#define MINIVPN_CONFIG_H

/* "key = value" configuration files with '#' comments. */

typedef int (*config_cb)(void *ctx, const char *key, const char *value, const char *path, int line);

/* Calls cb for each setting. Returns 0, or -1 if the file can't be read, a
 * line is malformed, or cb returns non-zero. */
int config_parse(const char *path, config_cb cb, void *ctx);

/* yes/no/true/false/on/off/1/0 -> 1/0, or -1 if unrecognised. */
int config_bool(const char *value);

/* Warns if a file holding secrets is readable by group/other (0 = fine). */
void warn_if_world_readable(const char *path, int allow_group);

#endif
