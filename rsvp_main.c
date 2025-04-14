// rsvp.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include "rsvp_db.h"

int main(int argc, char *argv[]) {
    char *prog_name = strrchr(argv[0], '/');
    if (prog_name) prog_name++; else prog_name = argv[0];

    pid_t pid = fork();
    if (pid < 0) {
        perror("Fork failed");
        exit(EXIT_FAILURE);
    }

    if (pid == 0) { // Child
        if (strcmp(prog_name, "rsvpd") == 0) {
            rsvpd_main();
        } else if (strcmp(prog_name, "rsvpsh") == 0) {
            rsvpsh_main();
        } else {
            printf("Run as 'rsvpd' or 'rsvpsh' (e.g., via symlink)\n");
            exit(EXIT_FAILURE);
        }
    } else {
        wait(NULL); // Optional
    }
    return 0;
}