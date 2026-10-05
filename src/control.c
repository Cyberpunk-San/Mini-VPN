#include "control.h"

#include "log.h"

#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/un.h>
#include <unistd.h>

int control_listen(const char *path)
{
    struct sockaddr_un addr;
    char dir[sizeof addr.sun_path];

    if (strlen(path) >= sizeof addr.sun_path) {
        log_error("control socket path too long: %s", path);
        return -1;
    }
    snprintf(dir, sizeof dir, "%s", path);
    mkdir(dirname(dir), 0755); /* usually /run/minivpn; fine if it exists */

    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        log_error("control socket: %s", strerror(errno));
        return -1;
    }
    memset(&addr, 0, sizeof addr);
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof addr.sun_path, "%s", path);

    unlink(path); /* stale socket from a previous run */
    mode_t old = umask(0177);
    int rc = bind(fd, (struct sockaddr *)&addr, sizeof addr);
    umask(old);
    if (rc < 0 || listen(fd, 16) < 0) {
        log_error("control socket %s: %s", path, strerror(errno));
        close(fd);
        return -1;
    }
    return fd;
}

int control_accept(int listen_fd, char *cmd, size_t cmdlen)
{
    int fd = accept4(listen_fd, NULL, NULL, SOCK_CLOEXEC);
    if (fd < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)
            log_warn("control accept: %s", strerror(errno));
        return -1;
    }

    struct ucred cred;
    socklen_t credlen = sizeof cred;
    if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cred, &credlen) < 0 ||
        (cred.uid != 0 && cred.uid != geteuid())) {
        log_warn("control: rejected connection from uid %d", (int)cred.uid);
        close(fd);
        return -1;
    }

    /* The admin tool writes its command immediately; never let a stuck
     * client block the data plane for more than a moment. */
    struct timeval tv = { .tv_sec = 0, .tv_usec = 500000 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);

    size_t n = 0;
    while (n + 1 < cmdlen) {
        ssize_t r = read(fd, cmd + n, cmdlen - 1 - n);
        if (r <= 0)
            break;
        n += (size_t)r;
        if (memchr(cmd, '\n', n))
            break;
    }
    cmd[n] = '\0';
    char *nl = strpbrk(cmd, "\r\n");
    if (nl)
        *nl = '\0';
    return fd;
}
