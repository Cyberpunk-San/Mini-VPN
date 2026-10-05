#include "sys.h"

#include "log.h"

#include <errno.h>
#include <grp.h>
#include <pwd.h>
#include <signal.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/timerfd.h>
#include <unistd.h>

int make_signalfd(void)
{
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGINT);
    sigaddset(&set, SIGTERM);
    sigaddset(&set, SIGHUP);
    sigaddset(&set, SIGUSR1);
    signal(SIGPIPE, SIG_IGN);

    if (sigprocmask(SIG_BLOCK, &set, NULL) < 0) {
        log_error("sigprocmask: %s", strerror(errno));
        return -1;
    }
    int fd = signalfd(-1, &set, SFD_NONBLOCK | SFD_CLOEXEC);
    if (fd < 0)
        log_error("signalfd: %s", strerror(errno));
    return fd;
}

int make_timerfd(unsigned interval_ms)
{
    int fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
    if (fd < 0) {
        log_error("timerfd_create: %s", strerror(errno));
        return -1;
    }
    struct itimerspec its;
    memset(&its, 0, sizeof its);
    its.it_interval.tv_sec = interval_ms / 1000;
    its.it_interval.tv_nsec = (long)(interval_ms % 1000) * 1000000L;
    its.it_value = its.it_interval;
    if (timerfd_settime(fd, 0, &its, NULL) < 0) {
        log_error("timerfd_settime: %s", strerror(errno));
        close(fd);
        return -1;
    }
    return fd;
}

int epoll_watch(int epfd, int fd)
{
    struct epoll_event ev;
    memset(&ev, 0, sizeof ev);
    ev.events = EPOLLIN;
    ev.data.fd = fd;
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev) < 0) {
        log_error("epoll_ctl: %s", strerror(errno));
        return -1;
    }
    return 0;
}

void tune_socket_buffers(int fd)
{
    int size = 4 << 20;
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &size, sizeof size);
    setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &size, sizeof size);
}

int drop_privileges(const char *user)
{
    struct passwd *pw = getpwnam(user);
    if (!pw) {
        log_error("unknown user '%s'", user);
        return -1;
    }
    if (setgroups(0, NULL) < 0 || setgid(pw->pw_gid) < 0 || setuid(pw->pw_uid) < 0) {
        log_error("dropping privileges to '%s': %s", user, strerror(errno));
        return -1;
    }
    if (pw->pw_uid != 0 && setuid(0) == 0) {
        log_error("privilege drop did not stick");
        return -1;
    }
    log_info("dropped privileges to user '%s' (uid %u)", user, (unsigned)pw->pw_uid);
    return 0;
}
