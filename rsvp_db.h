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

#include "log.h"

#define EXPLICIT_NULL 0 
#define IMPLICIT_NULL 3 
#define BASE_LABEL 16
 
struct session {
    char sender[16];
    char receiver[16];
    uint16_t tunnel_id;
    uint8_t del;
    uint8_t dest; 
    time_t last_path_time;
    struct session *next;
};

/* Define path_msg structure */
typedef struct path_msg {
    struct in_addr src_ip;
    struct in_addr dest_ip;
    struct in_addr nexthop_ip;
    struct in_addr p_nexthop_ip;
    uint16_t tunnel_id;
    uint32_t IFH;
    uint32_t interval;
    uint8_t prefix_len;
    uint8_t setup_priority;
    uint8_t hold_priority;
    uint8_t flags;
    uint16_t lsp_id;
    char     dev[16];
    char name[32];
} path_msg;

/* Define resv_msg structure */
typedef struct resv_msg {
    struct in_addr src_ip;
    struct in_addr dest_ip;
    struct in_addr nexthop_ip;
    uint16_t tunnel_id;
    uint32_t IFH;
    uint32_t interval;
    uint32_t in_label;
    uint32_t out_label;
    uint16_t lsp_id;
    char     dev[16];
    uint8_t prefix_len;
} resv_msg;

typedef struct db_node {
    void *data;
    struct db_node *left, *right;
    int height;
}db_node;


static inline int get_height(db_node *node) {
    return node ? node->height : 0;
}

static inline int max(int a, int b) {
    return (a > b) ? a : b;
}

static inline int get_balance(db_node *node) {
    return node ? get_height(node->left) - get_height(node->right) : 0;
}

typedef int (*cmp_tunnel_id)(uint16_t , const void *);
typedef int (*cmp_message) (const void*, const void *);
db_node* insert_node(db_node *, void *, cmp_message func, uint8_t);
db_node* delete_node(db_node *, uint16_t, cmp_tunnel_id func, uint8_t);
db_node* search_node(db_node *, uint16_t, cmp_tunnel_id func);

void update_tables(uint16_t);
void free_tree(db_node *);
void display_tree_debug(db_node *, uint8_t);
void display_tree(db_node * , uint8_t , char * , size_t);

void print_session(struct session*);
struct session* search_session(struct session*, uint16_t);
struct session* insert_session(struct session*, uint16_t, char[], char[], uint8_t);
struct session* delete_session(struct session*, struct session*, struct session*);
void insert(char[], uint8_t);
db_node* path_tree_insert(db_node*, char[], struct in_addr);
db_node* resv_tree_insert(db_node*, char[], struct in_addr, uint8_t);
int compare_path_del(uint16_t , const void *);
int compare_resv_del(uint16_t , const void *);
int compare_path_insert(const void * , const void *);
int compare_resv_insert(const void * , const void *);

extern uint32_t allocate_label (void);
extern uint8_t free_label (uint32_t);
