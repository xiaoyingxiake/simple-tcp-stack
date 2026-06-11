#ifndef LOG_H
#define LOG_H

#include <stdio.h>
#include <time.h>

#define LOG_INFO  "INFO"
#define LOG_DEBUG "DEBUG"
#define LOG_ERROR "ERROR"

#define log(level, fmt, ...) do { \
    time_t t = time(NULL); \
    struct tm *tm = localtime(&t); \
    printf("[%02d:%02d:%02d] [%s] " fmt "\n", \
           tm->tm_hour, tm->tm_min, tm->tm_sec, \
           level, ##__VA_ARGS__); \
} while(0)

#endif
