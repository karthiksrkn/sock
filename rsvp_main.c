/*
 * Copyright (c) 2025, Spanidea. All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the “Software”), to use,
 * copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 * the Software, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 **/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include "rsvp_db.h"
#include "rsvp_sh.h"

extern int rsvpd_main();
int main(int argc, char *argv[]) {
    char *prog_name = strrchr(argv[0], '/');
    if (prog_name) prog_name++; else prog_name = argv[0];

    if (strcmp(prog_name, "rsvpd") == 0) {
        return rsvpd_main();
    } else if (strcmp(prog_name, "rsvpsh") == 0) {
        return rsvpsh_main();
    } else {
        fprintf(stderr, "Run as 'rsvpd' or 'rsvpsh' (e.g., via symlink)\n");
        return EXIT_FAILURE;
    }
    return 0;
}
