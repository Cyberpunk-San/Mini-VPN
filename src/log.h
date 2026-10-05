#ifndef MINIVPN_LOG_H
#define MINIVPN_LOG_H

enum { LVL_ERROR = 0, LVL_WARN, LVL_INFO, LVL_DEBUG };

extern int log_level;

void log_msg(int level, const char *fmt, ...) __attribute__((format(printf, 2, 3)));

#define log_error(...) log_msg(LVL_ERROR, __VA_ARGS__)
#define log_warn(...)  log_msg(LVL_WARN, __VA_ARGS__)
#define log_info(...)  log_msg(LVL_INFO, __VA_ARGS__)
#define log_debug(...)                                    \
    do {                                                  \
        if (log_level >= LVL_DEBUG)                       \
            log_msg(LVL_DEBUG, __VA_ARGS__);              \
    } while (0)

#endif
