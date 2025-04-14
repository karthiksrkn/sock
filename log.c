// log.c
#include <stdio.h>
#include <stdarg.h>
#include "log.h"

FILE* log_file = NULL;
pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;

void log_message(const char* format, ...) {
    pthread_mutex_lock(&log_mutex);
    if (log_file) {
        va_list args;
        va_start(args, format);
        fprintf(log_file, "[%ld] ", time(NULL));
        vfprintf(log_file, format, args);  // Use vfprintf for variadic args
        fprintf(log_file, "\n");
        fflush(log_file);  // Ensure immediate write
        va_end(args);
    }
    pthread_mutex_unlock(&log_mutex);
}   