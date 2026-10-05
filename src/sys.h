#ifndef MINIVPN_SYS_H
#define MINIVPN_SYS_H

/* Event-loop plumbing: signals and timers as file descriptors so that one
 * epoll_wait() multiplexes everything without async signal handlers. */

/* Blocks SIGINT/SIGTERM/SIGHUP/SIGUSR1 and returns a signalfd delivering them. */
int make_signalfd(void);
/* Periodic timer that becomes readable every interval_ms. */
int make_timerfd(unsigned interval_ms);
int epoll_watch(int epfd, int fd);
/* Enlarges socket buffers so bursts are not dropped by the kernel. */
void tune_socket_buffers(int fd);
/* Permanently switches to an unprivileged user (after devices/sockets are open). */
int drop_privileges(const char *user);

#endif
