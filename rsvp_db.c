// rsvp_db.c
#include <stdarg.h>
#include <string.h>
#include <stdio.h>
#include "rsvp_db.h"
#include "rsvp_msg.h"
#include "timer_event.h"

#define MAX_LABELS 1000

struct session* path_head = NULL;
struct session* resv_head = NULL;
struct db_node* path_tree = NULL;
struct db_node* resv_tree = NULL;

static uint32_t label_pool[MAX_LABELS];
static int label_index = 0;
static pthread_mutex_t label_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t data_mutex = PTHREAD_MUTEX_INITIALIZER;
struct session* sess = NULL;
struct session* head = NULL;
time_t now = 0;

char nhip[16];
char source_ip[16];
char destination_ip[16];
char next_hop_ip[16];
char dev[16];

// Show API functions
void get_path_tree_info(char* buffer, size_t buffer_size) {
    buffer[0] = '\0'; // Clear buffer
    if (path_tree == NULL) {
        snprintf(buffer, buffer_size, "No PATH entries\n");
        return;
    }
    display_tree(path_tree, 1, buffer, buffer_size);
    db_node *nn = path_tree;
    path_msg *pn = (path_msg*)nn->data;
    log_message("show node tunnel id %d", pn->tunnel_id);
    log_message("show node dest ip %s", inet_ntoa(pn->dest_ip));
}

void get_resv_tree_info(char* buffer, size_t buffer_size) {
    buffer[0] = '\0';
    if (resv_tree == NULL) {
        snprintf(buffer, buffer_size, "No RESV entries\n");
        return;
    }
    display_tree(resv_tree, 0, buffer, buffer_size);
}

// Config API functions
int rsvp_add_config(const char* args, char* response, size_t response_size) {
    if (strcmp(args, "-h") == 0 || strcmp(args, "--help") == 0) {
        snprintf(response, response_size,
                 "Usage: rsvp add config -t <id> -s <srcip> -d <dstip> -n <name> -p <policy> [-i <interval>] [-S <setup>] [-H <hold>] [-f <flags>]\n"
                 "  -t: Tunnel ID (required)\n"
                 "  -s: Source IP (required)\n"
                 "  -d: Destination IP (required)\n"
                 "  -n: Session name (required)\n"
                 "  -p: Policy (required, 'dynamic' or 'explicit')\n"
                 "  -i: Refresh interval (optional, default: 30)\n"
                 "  -S: Setup priority (optional, default: 7, range: 0-7)\n"
                 "  -H: Hold priority (optional, default: 7, range: 0-7)\n"
                 "  -f: Flags (optional, default: 0)\n"
                 "For explicit paths, add hops after -p explicit (e.g., -p explicit 1.1.1.1 2.2.2.2)\n");
        return 0;
    }

    path_msg *path = create_path(args, response, response_size);
    if (!path) {
        log_message("Failed to create path");
        snprintf(response, response_size, "Error: Failed to create path\n");
        return -1; // Error message already set by create_path
    }
    log_message("Processing tunnel %d in rsvp_add_config", path->tunnel_id);
    log_message("Calling insert_node for tunnel %d", path->tunnel_id);
    path_tree = insert_node(path_tree, path, compare_path_insert);
    log_message("insert_node completed for tunnel %d", path->tunnel_id);

    // Add to path_head for timer refreshes
    char sender_ip[16], receiver_ip[16];
    strncpy(sender_ip, inet_ntoa(path->src_ip), sizeof(sender_ip));
    strncpy(receiver_ip, inet_ntoa(path->dest_ip), sizeof(receiver_ip));
    sender_ip[sizeof(sender_ip) - 1] = '\0';
    receiver_ip[sizeof(receiver_ip) - 1] = '\0';
    log_message("Calling insert_session for tunnel %d", path->tunnel_id);
    path_head = insert_session(path_head, path->tunnel_id, sender_ip, receiver_ip, 1);
    log_message("dest ip/receiver ip %s", receiver_ip);
    log_message("insert_session completed for tunnel %d", path->tunnel_id);

    snprintf(response, response_size, "Added tunnel %d: %s -> %s (%s)\n", 
             path->tunnel_id, sender_ip, receiver_ip, path->name);
    log_message("Tunnel %d added: %s", path->tunnel_id, response);
    // Send initial PATH message
    log_message("Calling send_path_message for tunnel %d", path->tunnel_id);
    send_path_message(sock, path->tunnel_id);
    log_message("PATH sent for tunnel %d", path->tunnel_id);

    log_message("Unlocking mutex for tunnel %d", path->tunnel_id);
    return 0;
}

int rsvp_delete_config(const char* args, char* response, size_t response_size) {
    char args_copy[256];
    strncpy(args_copy, args, sizeof(args_copy));
    args_copy[sizeof(args_copy) - 1] = '\0';

    // Check for help
    if (strcmp(args, "-h") == 0 || strcmp(args, "--help") == 0) {
        snprintf(response, response_size,
                 "Usage: rsvp delete config -t <id>\n"
                 "  -t: Tunnel ID to delete (required)\n");
        return 0;
    }

    int tunnel_id = -1;
    char *token, *saveptr;
    token = strtok_r(args_copy, " ", &saveptr);
    while (token) {
        if (strcmp(token, "-t") == 0) {
            token = strtok_r(NULL, " ", &saveptr);
            if (token){
                 tunnel_id = atoi(token);
                 log_message("tunnel id :%d", tunnel_id);
            }
        }
        token = strtok_r(NULL, " ", &saveptr);
    }

    if (tunnel_id < 0) {
        snprintf(response, response_size, "Error: Missing required argument (-t)\n");
        return -1;
    }

    path_msg temp = { .tunnel_id = tunnel_id };
    log_message("before search node in delete config");
    db_node* found = search_node(path_tree, tunnel_id, compare_path_del);
    log_message("after search node in delete config");
    if (found == NULL) {
        snprintf(response, response_size, "Error: Tunnel %d not found\n", tunnel_id);
        return -1;
    }

    path_tree = delete_node(path_tree, tunnel_id, compare_path_del, free);
    snprintf(response, response_size, "Deleted tunnel %d\n", tunnel_id);
    return 0;
}
	

path_msg* create_path(const char *args, char *response, size_t response_size) {
    path_msg *path = malloc(sizeof(path_msg));
    if (!path) {
        snprintf(response, response_size, "Error: Memory allocation failed\n");
        return NULL;
    }

    // Initialize defaults
    path->tunnel_id = -1;
    path->src_ip.s_addr = 0;
    path->dest_ip.s_addr = 0;
    path->nexthop_ip.s_addr = 0;
    path->interval = 30;
    path->setup_priority = 7;
    path->hold_priority = 7;
    path->flags = 0;
    path->lsp_id = 1;
    path->IFH = 0;
    path->prefix_len = 0;
    strncpy(path->name, "Unnamed", sizeof(path->name) - 1);
    path->name[sizeof(path->name) - 1] = '\0';
    path->path_type = 0; // Default to dynamic
    path->num_hops = 0;

    char args_copy[256];
    strncpy(args_copy, args, sizeof(args_copy));
    args_copy[sizeof(args_copy) - 1] = '\0';

    char *token, *saveptr;
    token = strtok_r(args_copy, " ", &saveptr);
    while (token) {
        if (strcmp(token, "-t") == 0) {
            token = strtok_r(NULL, " ", &saveptr);
            if (token) path->tunnel_id = atoi(token);
        } else if (strcmp(token, "-s") == 0) {
            token = strtok_r(NULL, " ", &saveptr);
            if (token) inet_pton(AF_INET, token, &path->src_ip);
        } else if (strcmp(token, "-d") == 0) {
            token = strtok_r(NULL, " ", &saveptr);
            if (token) inet_pton(AF_INET, token, &path->dest_ip);
        } else if (strcmp(token, "-n") == 0) {
            token = strtok_r(NULL, " ", &saveptr);
            if (token) strncpy(path->name, token, sizeof(path->name) - 1);
        } else if (strcmp(token, "-p") == 0) {
            token = strtok_r(NULL, " ", &saveptr);
            if (token) {
                if (strcmp(token, "dynamic") == 0) {
                    path->path_type = 0;
                } else if (strcmp(token, "explicit") == 0) {
                    path->path_type = 1;
                    token = strtok_r(NULL, " ", &saveptr);
                    while (token && path->num_hops < MAX_EXPLICIT_HOPS && strchr(token, '.') != NULL) {
                        inet_pton(AF_INET, token, &path->explicit_hops[path->num_hops++]);
                        token = strtok_r(NULL, " ", &saveptr);
                    }
                    if (token) continue; // Skip non-IP token
                } else {
                    snprintf(response, response_size, "Error: Invalid path type '%s'. Use 'dynamic' or 'explicit'\n", token);
                    free(path);
                    return NULL;
                }
            }
        } else if (strcmp(token, "-i") == 0) {
            token = strtok_r(NULL, " ", &saveptr);
            if (token) path->interval = atoi(token);
        } else if (strcmp(token, "-S") == 0) {
            token = strtok_r(NULL, " ", &saveptr);
            if (token) path->setup_priority = atoi(token);
        } else if (strcmp(token, "-H") == 0) {
            token = strtok_r(NULL, " ", &saveptr);
            if (token) path->hold_priority = atoi(token);
        } else if (strcmp(token, "-f") == 0) {
            token = strtok_r(NULL, " ", &saveptr);
            if (token) path->flags = atoi(token);
        }
        token = strtok_r(NULL, " ", &saveptr);
    }

    // Validate required fields
    if (path->tunnel_id < 0 || path->src_ip.s_addr == 0 || path->dest_ip.s_addr == 0 || path->name[0] == '\0') {
        snprintf(response, response_size, "Error: Missing required arguments (-t, -s, -d, -n, -p)\n");
        free(path);
        return NULL;
    }
    if (path->path_type == 1 && path->num_hops == 0) {
        snprintf(response, response_size, "Error: Explicit path requires at least one hop\n");
        free(path);
        return NULL;
    }
    if (path->setup_priority > 7 || path->hold_priority > 7) {
        snprintf(response, response_size, "Error: Setup and Hold priorities must be between 0 and 7\n");
        free(path);
        return NULL;
    }

    // Set nexthop based on path type
    char nhip[16];
    if (path->path_type == 0) { // Dynamic
        get_nexthop(inet_ntoa(path->dest_ip), nhip, &path->prefix_len, dev, &path->IFH);
        if (strcmp(nhip, " ") == 0 || strlen(nhip) == 0) {
            inet_pton(AF_INET, "0.0.0.0", &path->nexthop_ip);
        } else {
            inet_pton(AF_INET, nhip, &path->nexthop_ip);
        }
    } else { // Explicit
        if (path->num_hops > 0) {
            path->nexthop_ip = path->explicit_hops[0]; // First hop for ingress
        } else {
            inet_pton(AF_INET, "0.0.0.0", &path->nexthop_ip); // Shouldn’t happen due to validation
        }
    }

    return path;
}

struct session* insert_session(struct session* sess, uint8_t t_id, char sender[], char receiver[], uint8_t dest) {
        now = time(NULL);
        printf("insert session\n");
        if(sess == NULL) {
                struct session *temp = (struct session*)malloc(sizeof(struct session));
                if(temp < 0)
                         printf("cannot allocate dynamic memory]n");

                temp->last_path_time = now;
                strcpy(temp->sender, sender);
                strcpy(temp->receiver, receiver);
		        temp->dest = dest;
		        temp->tunnel_id = t_id;
                temp->next = NULL;
                return temp;
        } else {
		        struct session *local = NULL;
                while(sess != NULL) {
                        if((strcmp(sess->sender, sender) == 0) &&
                           (strcmp(sess->receiver, receiver) == 0)) {
				                sess->last_path_time = now;
                                return sess;
                        }
			        local = sess;
                    sess=sess->next;
                }

                struct session *temp = (struct session*)malloc(sizeof(struct session));
                if(sess < 0)
                         printf("cannot allocate dynamic memory\n");

                temp->last_path_time = now;
		        strcpy(temp->sender, sender);
                strcpy(temp->receiver, receiver);
		        temp->dest = dest;
		        temp->tunnel_id = t_id;
                temp->next = NULL;
                local->next = temp;
            }
}


struct session* delete_session(struct session* sess, char sender[], char receiver[]) { 

    struct session *temp = NULL;
	struct session *head = sess;

        printf("delete session\n");
        while(sess != NULL) {
                if((head == sess) &&
                   (strcmp(sess->sender, sender) == 0) &&
                   (strcmp(sess->receiver, receiver) == 0)) {
                        temp = head;
                        head = head->next;
                        free(temp);
                        return head;
                } else {
                        if((strcmp(sess->sender, sender) == 0) &&
                           (strcmp(sess->receiver, receiver) == 0)) {
				                temp = sess->next;
                                *sess = *sess->next;
                                free(temp);
                        }else{
                                sess = sess->next;
                        }
                }
        }
}


//AVL for Path adn Resv table
//*****************************************


int compare_path_insert(const void *a, const void *b) {
    return (((path_msg *) a)->tunnel_id - ((path_msg *) b)->tunnel_id);
}

int compare_resv_insert(const void *a, const void *b) {
    return (((resv_msg *) a)->tunnel_id - ((resv_msg *) b)->tunnel_id);
}

int compare_path_del(int id, const void *b) {
        return (id - ((path_msg *) b)->tunnel_id);
}

int compare_resv_del(int id, const void *b) {
        return (id - ((resv_msg *) b)->tunnel_id);
}

/* Right rotation */
db_node* right_rotate(db_node *y) {
    db_node *x = y->left;
    db_node *T2 = x->right;
    x->right = y;
    y->left = T2;
    y->height = max(get_height(y->left), get_height(y->right)) + 1;
    x->height = max(get_height(x->left), get_height(x->right)) + 1;
    return x;
}

/* Left rotation */
db_node* left_rotate(db_node *x) {
    db_node *y = x->right;
    db_node *T2 = y->left;
    y->left = x;
    x->right = T2;
    x->height = max(get_height(x->left), get_height(x->right)) + 1;
    y->height = max(get_height(y->left), get_height(y->right)) + 1;
    return y;
}


/* Create a new AVL Node for path_msg */
db_node* create_node(void *data) {
    db_node *node = (db_node*)malloc(sizeof(db_node));
    if (!node) {
        printf("Memory allocation failed!\n");
        return NULL;
    }
    node->data = data;
    node->left = node->right = NULL;
    node->height = 1;
    return node;
}

/* Insert a path_msg node */
db_node* insert_node(db_node *node, void *data, int (*cmp1)(const void *, const void *)) {
    if (!node) return create_node(data);

    if (cmp1(data, node->data) < 0)
        node->left = insert_node(node->left, data, cmp1);
    else if (cmp1(data, node->data) > 0)
        node->right = insert_node(node->right, data, cmp1);
    else 
        return node; // Duplicate values not allowed

    node->height = 1 + max(get_height(node->left), get_height(node->right));
    int balance = get_balance(node);

    // Perform rotations if unbalanced
    if (balance > 1 && cmp1(data, node->left->data) < 0)
        return right_rotate(node);
    if (balance < -1 && cmp1(data, node->right->data) > 0)
        return left_rotate(node);
    if (balance > 1 && cmp1(data, node->left->data) > 0) {
        node->left = left_rotate(node->left);
        return right_rotate(node);
    }
    if (balance < -1 && cmp1(data, node->right->data) < 0) {
        node->right = right_rotate(node->right);
        return left_rotate(node);
    }

    return node;
}

/* Utility function to get the minimum value node */
db_node* min_node(db_node* node) {
    db_node* current = node;
    while (current->left != NULL)
        current = current->left;
    return current;
}

/* Delete a node from path_msg AVL tree */
db_node* delete_node(db_node* node, int tunnel_id, int (*cmp)(int , const void *), int msg) {
    if (node == NULL) return NULL;

    if (cmp(tunnel_id, node->data) < 0)
        node->left = delete_node(node->left, tunnel_id, cmp, msg);
    else if (cmp(tunnel_id, node->data) > 0) 
        node->right = delete_node(node->right, tunnel_id, cmp, msg);
    else {
        // Node with only one child or no child
        if ((node->left == NULL) || (node->right == NULL)) {
            db_node* temp = node->left ? node->left : node->right;
            if (temp == NULL) {
                temp = node;
                node = NULL;
            } else {
                *node = *temp; // Copy the contents
	    }
	    if(msg) {
	        free((path_msg*) temp->data);
	    } else {
	        free((resv_msg*) temp->data);
	    }
            free(temp);
        } else {
            db_node* temp = min_node(node->right);
            node->data = temp->data;
            if(msg)
                node->right = delete_node(node->right, ((path_msg *)temp->data)->tunnel_id, cmp, msg);
            else
                node->right = delete_node(node->right, ((resv_msg *)temp->data)->tunnel_id, cmp, msg);
        }
    }

    if (node == NULL) return node;

    node->height = 1 + max(get_height(node->left), get_height(node->right));
    int balance = get_balance(node);

    // Perform rotations if needed
    if (balance > 1 && get_balance(node->left) >= 0)
        return right_rotate(node);
    if (balance > 1 && get_balance(node->left) < 0) {
        node->left = left_rotate(node->left);
        return right_rotate(node);
    }
    if (balance < -1 && get_balance(node->right) <= 0)
        return left_rotate(node);
    if (balance < -1 && get_balance(node->right) > 0) {
        node->right = right_rotate(node->right);
        return left_rotate(node);
    }

    return node;
}


/* Search for a path_msg node */
db_node* search_node(db_node *node, int data, int (*cmp)(int, const void *)) {
    if (node == NULL) {
        return node;
    }
    if (cmp(data, node->data) == 0)
        return node;

    if (cmp(data, node->data) < 0) { 
        return search_node(node->left, data, cmp);
    } else {
        return search_node(node->right, data, cmp);
    }
}

/* Free a path tree */
void free_tree(db_node *node) {
    if (!node) return;
    free_tree(node->left);
    free_tree(node->right);
    free(node->data);
    free(node);
}

void display_tree(db_node *node, int msg, char *buffer, size_t buffer_size) {
    if (node == NULL) return;

    // In-order traversal: left, root, right
    display_tree(node->left, msg, buffer, buffer_size);

    char temp[256];
    size_t current_len = strlen(buffer);
    size_t remaining_size = buffer_size - current_len;

    if (remaining_size <= 1) return; // No space left (leave room for null terminator)

    if (msg) { // PATH tree (msg == 1)
        path_msg *p = (path_msg*)node->data;
        log_message("display tree dest ip %s", inet_ntoa(p->dest_ip));
        inet_ntop(AF_INET, &p->src_ip, source_ip, 16);
        inet_ntop(AF_INET, &p->dest_ip, destination_ip, 16);
        inet_ntop(AF_INET, &p->nexthop_ip, next_hop_ip, 16);
        snprintf(temp, sizeof(temp), 
                 "Tunnel ID: %d, Src: %s, Dst: %s, NextHop: %s, Name: %s\n",
                 p->tunnel_id, source_ip, destination_ip,
                 next_hop_ip, p->name);
    } else { // RESV tree (msg == 0)
        resv_msg *r = (resv_msg*)node->data;
        inet_ntop(AF_INET, &r->src_ip, source_ip, 16);
        inet_ntop(AF_INET, &r->dest_ip, destination_ip, 16);
        inet_ntop(AF_INET, &r->nexthop_ip, next_hop_ip, 16);
        snprintf(temp, sizeof(temp),
                "Tunnel ID: %u, Src: %s, Dest: %s, Next Hop: %s, In_label: %d, Out_label: %d\n",
                r->tunnel_id, source_ip, destination_ip, next_hop_ip, ntohl(r->in_label),
                ntohl(r->out_label));
    }

    // Append to buffer, ensuring we don't overflow
    strncat(buffer, temp, remaining_size - 1);
    buffer[buffer_size - 1] = '\0'; // Ensure null termination

    display_tree(node->right, msg, buffer, buffer_size);
}

// /* Display path tree (inorder traversal) */
void display_tree_debug(db_node *node, int msg) {
    if (!node) return;
    display_tree_debug(node->left, msg);
    if (msg) {
        path_msg *p = node->data;
        inet_ntop(AF_INET, &p->src_ip, source_ip, 16);
        inet_ntop(AF_INET, &p->dest_ip, destination_ip, 16);
        inet_ntop(AF_INET, &p->nexthop_ip, next_hop_ip, 16);
        printf("Tunnel ID: %u, Src: %s, Dest: %s, Next Hop: %s\n",
            p->tunnel_id,
            source_ip,
            destination_ip,
            next_hop_ip);
    } else {
        resv_msg *r = node->data;
        inet_ntop(AF_INET, &r->src_ip, source_ip, 16);
        inet_ntop(AF_INET, &r->dest_ip, destination_ip, 16);
        inet_ntop(AF_INET, &r->nexthop_ip, next_hop_ip, 16);
        printf("Tunnel ID: %u, Src: %s, Dest: %s, Next Hop: %s, In_label: %d, Out_label: %d\n",
                r->tunnel_id,
                source_ip,
                destination_ip,
                next_hop_ip,
                ntohl(r->in_label),
                ntohl(r->out_label));
    }
    display_tree_debug(node->right, msg);
}

//Fetch information from receive buffer
//-------------------------------------

db_node* path_tree_insert(db_node* path_tree, char buffer[]) {
    uint32_t ifh = 0;
    uint8_t prefix_len = 0;
 
    struct session_object *session_obj = (struct session_object*)(buffer + START_RECV_SESSION_OBJ);
    struct hop_object *hop_obj = (struct hop_object*)(buffer + START_RECV_HOP_OBJ);
    struct time_object *time_obj = (struct time_object*)(buffer + START_RECV_TIME_OBJ);
    struct session_attr_object *session_attr_obj = (struct session_attr_object*)(buffer + START_RECV_SESSION_ATTR_OBJ);
    
    path_msg *p = malloc(sizeof(path_msg));

    p->tunnel_id = session_obj->tunnel_id;
    p->src_ip = (session_obj->src_ip);
    p->dest_ip = (session_obj->dst_ip);
    p->interval = time_obj->interval;
    p->setup_priority = session_attr_obj->setup_prio;
    p->hold_priority = session_attr_obj->hold_prio;
    p->flags = session_attr_obj->flags;
    p->lsp_id = 1;
    strncpy(p->name, session_attr_obj->Name, sizeof(session_attr_obj->Name) - 1);
    p->name[sizeof(p->name) - 1] = '\0';

    if(get_nexthop(inet_ntoa(p->dest_ip), nhip, &prefix_len, dev, &ifh)) {
        strcpy(p->dev, dev);
        p->IFH = ifh;
        if(strcmp(nhip, " ") == 0) {
            inet_pton(AF_INET, "0.0.0.0", &p->nexthop_ip);
            p->prefix_len = prefix_len;
        }
        else {
            inet_pton(AF_INET, nhip, &p->nexthop_ip);
            p->prefix_len = prefix_len;
        }
    } else {
        printf("No route to destination\n");
        return NULL;
    }

    return insert_node(path_tree, p, compare_path_insert);
}


db_node* resv_tree_insert(db_node* resv_tree, char buffer[], uint8_t dst_reach) {

    uint32_t ifh = 0;
    uint8_t prefix_len = 0;

    struct session_object *session_obj = (struct session_object*)(buffer + START_RECV_SESSION_OBJ);
    struct hop_object *hop_obj = (struct hop_object*)(buffer + START_RECV_HOP_OBJ);
    struct time_object *time_obj = (struct time_object*)(buffer + START_RECV_TIME_OBJ);
    struct label_object *label_obj = (struct label_object*)(buffer + START_RECV_LABEL);

    resv_msg *p = malloc(sizeof(resv_msg));

    p->tunnel_id = session_obj->tunnel_id;
    p->src_ip = (session_obj->src_ip);
    p->dest_ip = (session_obj->dst_ip);
    p->interval = time_obj->interval;

    if(dst_reach) {
        p->in_label = htonl(3);
        p->out_label = htonl(-1);
	    p->prefix_len = prefix_len;
    }

    //get and assign nexthop
    if (get_nexthop(inet_ntoa(p->src_ip), nhip, &prefix_len,dev, &ifh)) {
        strcpy(p->dev, dev);
        p->IFH = ifh;
        p->prefix_len = prefix_len;
	    printf("prefix_len = %d\n", prefix_len);
        if(!dst_reach) {
                p->out_label = label_obj->label;
        }
        if(strcmp(nhip, " ") == 0) {
            if(!dst_reach)
                p->in_label = htonl(-1);
            inet_pton(AF_INET, "0.0.0.0", &p->nexthop_ip);
        }
        else {
            if(!dst_reach)
                p->in_label = htonl(100);
            inet_pton(AF_INET, nhip, &p->nexthop_ip);
        }
    } else {
        printf("No route to Source\n");
        return NULL;
    }

    return insert_node(resv_tree, p, compare_resv_insert);
}

