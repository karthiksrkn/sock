//rsvp_db.h
#ifndef RSVP_DB_H
#define RSVP_DB_H

#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include<stdint.h>
#include<arpa/inet.h>
#include<netinet/in.h>
#include<time.h>
#include<pthread.h>

#define PACKET_SIZE 256
#define MAX_EXPLICIT_HOPS 10
#define MAX_OUTPUT_BUFFER 4096
#define MAX_NAME_LEN 32

extern pthread_mutex_t data_mutex;
extern struct db_node* path_tree;
extern struct db_node* resv_tree;
extern struct session* resv_head;
extern struct session* path_head;
extern int sock;
struct session {
    char sender[16];
    char receiver[16];
    uint8_t tunnel_id;
    time_t last_path_time;
    uint8_t dest;
    struct session *next;
};

/* Define path_msg structure */
typedef struct path_msg {
    struct in_addr src_ip;
    struct in_addr dest_ip;
    struct in_addr nexthop_ip;
    uint16_t tunnel_id;
    uint32_t IFH;
    uint32_t interval;
    uint8_t prefix_len;
    uint8_t setup_priority;
    uint8_t hold_priority;
    uint8_t flags;
    uint16_t lsp_id;
    char dev[16];
    char name[MAX_NAME_LEN];
    uint8_t path_type;
    struct in_addr explicit_hops[MAX_EXPLICIT_HOPS];
    int num_hops;
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
    char dev[16];
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

typedef int (*cmp)(int, const void *);
typedef int (*cmp1) (const void*, const void *);
db_node* insert_node(db_node *, void *, cmp1 func);
db_node* delete_node(db_node *, int, cmp func, int);
db_node* search_node(db_node *, int, cmp func);
void free_tree(db_node *);
void display_tree(db_node *, int, char*, size_t);
void display_tree_debug(db_node *, int);
path_msg* create_path(const char *, char *, size_t );

// Config API functions
int rsvp_add_config(const char* , char* , size_t );
int rsvp_delete_config(const char* , char* , size_t );

// Show API functions
void get_path_tree_info(char* , size_t );
void get_resv_tree_info(char* , size_t );

struct session* insert_session(struct session*, uint8_t, char[], char[], uint8_t);
struct session* delete_session(struct session*, char[], char[]);
db_node* path_tree_insert(db_node*, char[]);
db_node* resv_tree_insert(db_node*, char[], uint8_t);
int compare_path_del(int , const void *);
int compare_resv_del(int , const void *);
int compare_path_insert(const void * , const void *);
int compare_resv_insert(const void * , const void *);

// Main functions for daemon and shell
int rsvpd_main(void); // Daemon logic from rsvpd.c
int rsvpsh_main(void); // Shell logic from rsvpsh.c

#endif /* RSVP_DB_H */