#include "log.h"

#include <stdarg.h>
#include <stdio.h>
#include <time.h>

int log_level = LVL_INFO;

static const char *const level_names[] = { "ERROR", "WARN ", "INFO ", "DEBUG" };

void log_msg(int level, const char *fmt, ...)
{
    if (level > log_level)
        return;

    struct timespec ts;
    struct tm tm;
    char when[32];
    clock_gettime(CLOCK_REALTIME, &ts);
    localtime_r(&ts.tv_sec, &tm);
    strftime(when, sizeof when, "%Y-%m-%d %H:%M:%S", &tm);

    flockfile(stderr);
    fprintf(stderr, "%s.%03ld %s ", when, ts.tv_nsec / 1000000, level_names[level]);
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
    funlockfile(stderr);
}
