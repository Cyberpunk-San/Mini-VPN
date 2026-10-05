#ifndef MINIVPN_CONTROL_H
#define MINIVPN_CONTROL_H

/* Local management API: a Unix-domain stream socket. A client sends one
 * command line ("status", "reload", "kick <device-id>") and reads one JSON
 * reply, then the connection closes. Only root and the server's own user may
 * connect (checked with SO_PEERCRED). */

#include <stddef.h>
#include <sys/types.h>

/* Creates the listening socket (mode 0600), replacing a stale one. */
int control_listen(const char *path);

/* Accepts one pending connection and reads its command line (trimmed) into
 * cmd. Returns the connected fd, or -1 (nothing pending / rejected / error). */
int control_accept(int listen_fd, char *cmd, size_t cmdlen);

#endif
