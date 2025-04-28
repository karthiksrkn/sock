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

#include <sys/un.h>
#include "rsvp_db.h"
#include "rsvp_msg.h"
#include "timer-event.h"
#include "rsvp_sh.h"
#include "log.h"

#define SOCKET_PATH "/tmp/rsvp_socket"
#define MAX_BUFFER 4096

extern struct session* path_head;
extern struct session* resv_head;
extern db_node* resv_tree;
extern db_node* path_tree;

extern pthread_mutex_t path_tree_mutex;
extern pthread_mutex_t resv_tree_mutex;
extern pthread_mutex_t path_list_mutex;
extern pthread_mutex_t resv_list_mutex;

extern int sock;

static volatile sig_atomic_t sigint_received = 0;
static int in_config_mode = 0;

void sigint_handler(int sig) {
     sigint_received = 1;
     if (in_config_mode) {
         in_config_mode = 0;
     }
 }

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
    struct session* temp = NULL;

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
    path_tree = insert_node(path_tree, path, compare_path_insert, 1);
    if(path_tree == NULL)
	return;
    log_message("insert_node completed for tunnel %d path tree %d", path->tunnel_id,path_tree);

    // Add to path_head for timer refreshes
    char sender_ip[16], receiver_ip[16];
    inet_ntop(AF_INET, &path->src_ip, sender_ip, 16);
    inet_ntop(AF_INET, &path->dest_ip, receiver_ip, 16); 
    
    log_message("Calling insert_session for tunnel %d", path->tunnel_id);
    if(search_session(resv_head, path->tunnel_id) == NULL) {
	temp = insert_session(resv_head, path->tunnel_id, sender_ip, receiver_ip, 1);
	if(temp != NULL) {
		resv_head = temp;
	} else {
		log_message("insert for tunnel %d failed", path->tunnel_id);
       		return;
	}
    }

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
    struct session* temp1 = NULL;

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

    log_message("before delete node tunnel id %d path_tree = %d",tunnel_id,path_tree);
    if(search_node(path_tree, tunnel_id, compare_path_del) != NULL) {
    	db_node *temp = delete_node(path_tree, tunnel_id, compare_path_del, 1);
    	if(temp == NULL) {
		path_tree = temp;
		log_message(" last nodE delete tunnel = %d ", tunnel_id);
	} else {
		path_tree = temp;
		log_message(" tunne id = %d deleted", tunnel_id);
	}
    } else {
        log_message("Tunnel id = %d not found in path tree", tunnel_id);
	snprintf(response, response_size, " Tunnel id = %d not found in path tree\n", tunnel_id);
        return -1;
    }

    print_session(resv_head);
    log_message("Calling delete_session for tunnel %d", tunnel_id);
    if((temp1 = search_session(resv_head, tunnel_id)) != NULL) {
	temp1->del = 1;
    }

    snprintf(response, response_size, "Deleted tunnel %d\n", tunnel_id);
    return 0;
}
	

path_msg* create_path(const char *args, char *response, size_t response_size) {
    path_msg *path = malloc(sizeof(path_msg));
    char dev[16];
    if (!path) {
        snprintf(response, response_size, "Error: Memory allocation failed\n");
        return NULL;
    }

    // Initialize defaults
    path->tunnel_id = -1;
    path->src_ip.s_addr = 0;
    path->dest_ip.s_addr = 0;
    path->nexthop_ip.s_addr = 0;
    inet_pton(AF_INET, "0.0.0.0", &path->p_nexthop_ip);
    path->interval = 30;
    path->setup_priority = 7;
    path->hold_priority = 7;
    path->flags = 0;
    path->lsp_id = 1;
    path->IFH = 0;
    path->prefix_len = 0;
    strncpy(path->name, "Unnamed", sizeof(path->name) - 1);
    path->name[sizeof(path->name) - 1] = '\0';
    //path->path_type = 0; // Default to dynamic
    //path->num_hops = 0;

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
               /* if (strcmp(token, "dynamic") == 0) {
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
                }*/
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
    /*if (path->path_type == 1 && path->num_hops == 0) {
        snprintf(response, response_size, "Error: Explicit path requires at least one hop\n");
        free(path);
        return NULL;
    }*/
    if (path->setup_priority > 7 || path->hold_priority > 7) {
        snprintf(response, response_size, "Error: Setup and Hold priorities must be between 0 and 7\n");
        free(path);
        return NULL;
    }

    // Set nexthop based on path type
    char nhip[16];
    //if (path->path_type == 0) { // Dynamic
    if(get_nexthop(inet_ntoa(path->dest_ip), nhip, &path->prefix_len, dev, &path->IFH)) { 
	strcpy(path->dev, dev);
        if (strcmp(nhip, " ") == 0) {
		inet_pton(AF_INET, "0.0.0.0", &path->nexthop_ip);
       	} else {
		inet_pton(AF_INET, nhip, &path->nexthop_ip);
	}
    } else {
       	log_message("No route to destination\n");
       	return NULL;
    }

    /*} else { // Explicit
        if (path->num_hops > 0) {
            path->nexthop_ip = path->explicit_hops[0]; // First hop for ingress
        } else {
            inet_pton(AF_INET, "0.0.0.0", &path->nexthop_ip); // Shouldn’t happen due to validation
        }
    }*/

    return path;
}

int rsvpsh_main() {
    int sock;
    struct sockaddr_un addr;
    char input[256], response[MAX_BUFFER];
    int in_config_mode = 0;
    struct sigaction sa;
        sa.sa_handler = sigint_handler;
        sa.sa_flags = 0;
        sigemptyset(&sa.sa_mask);
        if (sigaction(SIGINT, &sa, NULL) == -1) {
           perror("sigaction failed");
           return 1;
        }

    printf("\033[1;32mRSVP Shell (OpenWrt)\033[0m\n");

    while (1) {
        if (sigint_received) {
             if (in_config_mode) {
                 printf("\nExiting config mode\n");
                 in_config_mode = 0;
             }else {
                 printf("\n");
             }
             sigint_received = 0;
             continue;
        }
        printf("%s> ", in_config_mode ? "(config)# " : "rsvp");
        fflush(stdout);
        if (fgets(input, sizeof(input), stdin) == NULL) continue;
        input[strcspn(input, "\n")] = 0;

        if (strcmp(input, "exit") == 0) {
            if (in_config_mode) {
                in_config_mode = 0;
            } else {
                printf("Exiting RSVP shell\n");
                break;
            }
            continue;
        }

        if (!in_config_mode && strcmp(input, "config") == 0) {
            in_config_mode = 1;
            continue;
        }

        sock = socket(AF_UNIX, SOCK_STREAM, 0);
        if (sock < 0) {
            perror("Socket creation failed");
            continue;
        }

        memset(&addr, 0, sizeof(addr));
        addr.sun_family = AF_UNIX;
        strncpy(addr.sun_path, SOCKET_PATH, sizeof(addr.sun_path) - 1);

        if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            perror("Connection to daemon failed");
            close(sock);
            continue;
        }

        if (in_config_mode) {
            if (strncmp(input, "rsvp add config ", 16) == 0) {
                snprintf(input, sizeof(input), "add %s", input + 16);
            } else if (strncmp(input, "rsvp delete config ", 19) == 0) {
                snprintf(input, sizeof(input), "delete %s", input + 19);
            } else {
                printf("Config commands: rsvp add config ..., rsvp delete config ..., exit, --help for manual\n");
                close(sock);
                continue;
            }
        } else if (strncmp(input, "rsvp show ", 10) == 0) {
            snprintf(input, sizeof(input), "show %s", input + 10);
        } else {
            printf("Commands: config, rsvp show [path | resv], exit\n");
            close(sock);
            continue;
        }

        send(sock, input, strlen(input), 0);
        int bytes = recv(sock, response, sizeof(response) - 1, 0);
        if (bytes > 0) {
            response[bytes] = '\0';
            printf("%s", response);
        }
        close(sock);
    }
    return 0;
}
