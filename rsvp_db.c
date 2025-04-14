#include "rsvp_db.h"
#include "rsvp_msg.h"
#include "timer-event.h"

struct session* sess = NULL;
struct session* head = NULL;
time_t now = 0;
char nhip[16];
char source_ip[16];
char destination_ip[16];
char next_hop_ip[16];
char dev[16];

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

/* Display path tree (inorder traversal) */
void display_tree(db_node *node, int msg) {
    if (!node) return;
    display_tree(node->left, msg);
    if(msg) {
        path_msg* p = node->data;
        inet_ntop(AF_INET, &p->src_ip, source_ip, 16);
        inet_ntop(AF_INET, &p->dest_ip, destination_ip, 16);
        inet_ntop(AF_INET, &p->nexthop_ip, next_hop_ip, 16);
        printf("Tunnel ID: %u, Src: %s, Dest: %s, Next Hop: %s\n",
                p->tunnel_id,
                source_ip,
                destination_ip,
                next_hop_ip);
    } else {
        resv_msg* r = node->data;
        inet_ntop(AF_INET, &r->src_ip, source_ip, 16);
        inet_ntop(AF_INET, &r->dest_ip, destination_ip, 16);
        inet_ntop(AF_INET, &r->nexthop_ip, next_hop_ip, 16);
        printf("Tunnel ID: %u, Src: %s, Dest: %s, Next Hop: %s, prefix_len: %d, In_label: %d, Out_label: %d\n",
                r->tunnel_id,
                source_ip,
                destination_ip,
                next_hop_ip,
                r->prefix_len,
                ntohl(r->in_label),
                ntohl(r->out_label));
    }
    display_tree(node->right, msg);
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
