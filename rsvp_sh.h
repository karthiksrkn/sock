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

#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include<stdint.h>
#include<arpa/inet.h>
#include<netinet/in.h>
#include<time.h>
#include<pthread.h>
#include<unistd.h>
#include<signal.h>
#include<errno.h>

// Show API functions 
void get_path_tree_info(char * , size_t );
void get_resv_tree_info(char * , size_t );

// Config API functions
int rsvp_add_config(const char * , char * , size_t);
int rsvp_delete_config(const char * , char * , size_t);

path_msg* create_path(const char *, char *, size_t);
int rsvpsh_main();
