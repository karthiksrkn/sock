// log.h
#ifndef LOG_H
#define LOG_H
#include <stdio.h>
#include <pthread.h>
#include <stdarg.h>

// Declare global log file and mutex
extern FILE* log_file;
extern pthread_mutex_t log_mutex;

// Function to log messages to the file
void log_message(const char* format, ...);

#endif