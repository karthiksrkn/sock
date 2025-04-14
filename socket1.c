// Document socket1.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <pthread.h>
#include "socket.h"
#include <linux/if.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <netdb.h>
#include <net/route.h>
#include <netinet/in.h>
#include "log.h"

#define LOG_FILE_PATH "/tmp/socket1.log"

struct src_dst_ip *ip = NULL;
pthread_mutex_t data_mutex = PTHREAD_MUTEX_INITIALIZER;
// extern struct session* path_head;
// extern struct session* resv_head;
// extern db_node *path_tree = NULL;
// extern db_node *resv_tree = NULL;

int sock = 0;

void* rsvp_shell(void* arg) {
    char input[256];
    char output[MAX_OUTPUT_BUFFER];
    int in_config_mode = 0;

    printf("\033[1;32mRSVP Shell (OpenWrt)\033[0m\n");
    while (1) {
        printf("%s> ", in_config_mode ? "(config)# " : "rsvp");
        fflush(stdout);
        if (fgets(input, sizeof(input), stdin) == NULL) continue;
        input[strcspn(input, "\n")] = 0;

        if (in_config_mode) {
            if (strcmp(input, "exit") == 0) {
                in_config_mode = 0;
                continue;
            }
            pthread_mutex_lock(&data_mutex);
            if (strncmp(input, "rsvp add config ", 16) == 0) {
                if (rsvp_add_config(input + 16, output, sizeof(output)) == 0) {
                    printf("%s", output);
                } else {
                    printf("%s", output);
                }
            } else if (strncmp(input, "rsvp delete config ", 19) == 0) {
                int result = rsvp_delete_config(input + 19, output, sizeof(output));
                if (result == 0) {
                    printf("%s", output);
                } else {
                    printf("%s", output);
                }
            } else {
                printf("Config commands: rsvp add config -t <id> -s <srcip> -d <dstip> -n <name> -p <policy> [-i <interval>] [-S <setup>] [-H <hold>] [-f <flags>], rsvp delete config -t <id>, exit\n"
                       "Use '-h' or '--help' with commands for more info.\n");
            }
            pthread_mutex_unlock(&data_mutex);
        } else {
            if (strcmp(input, "exit") == 0) {
                printf("\033[1;32mShutting down RSVP Daemon\033[0m\n");
                pthread_mutex_lock(&log_mutex);
                if (log_file) {
                    fclose(log_file);
                    log_file = NULL;
                }
                pthread_mutex_unlock(&log_mutex);
                exit(0);
            } else if (strcmp(input, "config terminal") == 0) {
                in_config_mode = 1;
            } else if (strncmp(input, "rsvp show ", 10) == 0) {
                pthread_mutex_lock(&data_mutex);
                char* type = input + 10;
                if (strcmp(type, "path") == 0) {
                    get_path_tree_info(output, sizeof(output));
                } else if (strcmp(type, "resv") == 0) {
                    get_resv_tree_info(output, sizeof(output));
                } else {
                    snprintf(output, sizeof(output), "Usage: rsvp show [path | resv]\n");
                }
                printf("%s", output);
                pthread_mutex_unlock(&data_mutex);
            } else {
                printf("Commands: config terminal, rsvp show [path | resv], exit\n");
            }
        }
    }
    return NULL;
}

void* receive_thread(void* arg) {
    struct sockaddr_in sender_addr;
    socklen_t addr_len = sizeof(sender_addr);
    char buffer[PACKET_SIZE];

    while (1) {
        int bytes_received = recvfrom(sock, buffer, sizeof(buffer), 0,
                                      (struct sockaddr*)&sender_addr, &addr_len);
        if (bytes_received < 0) {
            log_message("Receive failed");
            continue;
        }

        struct rsvp_header* rsvp = (struct rsvp_header*)buffer;
        char sender_ip[16], receiver_ip[16];
        pthread_mutex_lock(&data_mutex);
        switch (rsvp->msg_type) {
            case PATH_MSG_TYPE:
                receive_path_message(sock, buffer, sender_addr);
                break;
            case RESV_MSG_TYPE:
                get_ip(buffer, sender_ip, receiver_ip);
                log_message("insert_resv_session");
                if (resv_head == NULL) {
                    resv_head = insert_session(resv_head, sender_ip, receiver_ip);
                } else {
                    insert_session(resv_head, sender_ip, receiver_ip);
                }
                receive_resv_message(sock, buffer, sender_addr);
                break;
            default: {
                char msg[64];
                snprintf(msg, sizeof(msg), "Unknown RSVP message type: %d", rsvp->msg_type);
                log_message(msg);
            }
        }
        pthread_mutex_unlock(&data_mutex);
    }
    return NULL;
}

int main() {

    char srcip[16];
    char dstip[16];
    char nhip[16];
    uint16_t tunnel_id;
    int explicit = 0;
    char buffer[512];
    struct sockaddr_in sender_addr;
    socklen_t addr_len = sizeof(sender_addr);

    //struct sockaddr_in dest_addr;
    struct sockaddr_in addr;

    char sender_ip[16];
    char receiver_ip[16];
    struct in_addr send_ip, rece_ip;

    sock = socket(AF_INET, SOCK_RAW, RSVP_PROTOCOL);
    if (sock < 0) {
        perror("Socket creation failed");
        return 1;
    }

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
	perror("binding failed");
	close(sock);
	exit(EXIT_FAILURE);
    }

    // only in PE1 or PE2 where we configure the tunnel for RSVP.
    // ------------------------------------------------------
	
    //ip = (struct src_dst_ip *)malloc(sizeof(struct src_dst_ip ));
    // for (int i  = 0; i < 3; i++){
    // printf("Enter tunnel_id: \n");
    // scanf("%hd",&tunnel_id);
    // getchar();

    // printf("Enter src ip : \n");
    // fgets(srcip, 16, stdin);
	
    // printf("Enter dst ip: \n");
    // fgets(dstip, 16, stdin);

    //printf("Is Explicit enable 1-yes 0-NO\n");
    //scanf("%d ", &explicit);

    // int len = strlen(srcip);
    // if(srcip[len-1] == '\n') 
	// srcip[len-1] = '\0';

    // strlen(dstip);
    // if(dstip[len-1] == '\n')
    //     dstip[len-1] = '\0';


    path_msg *path = malloc(sizeof(path_msg));
    // path->tunnel_id = tunnel_id;
    // inet_pton(AF_INET, srcip, &path->src_ip);
    // inet_pton(AF_INET, dstip, &path->dest_ip);
    //path->src_ip.s_addr = inet_addr("192.168.11.10");
    //path->dest_ip.s_addr = inet_addr("192.168.11.11");

    //get and assign nexthop
    get_nexthop(inet_ntoa(path->dest_ip), nhip);
    if(strcmp(nhip, " ") == 0)
	inet_pton(AF_INET, "0.0.0.0", &path->nexthop_ip);
    else 
	inet_pton(AF_INET, nhip, &path->nexthop_ip);	

    path->interval = 30;
    path->setup_priority = 7;
    path->hold_priority = 7;
    path->flags = 0;
    path->lsp_id = 1;
    path->IFH = 123;
    strncpy(path->name, "Path1", sizeof(path->name) - 1);
    path->name[sizeof(path->name) - 1] = '\0';

    path_tree = insert_node(path_tree, (void*)path, compare_path_insert); 
    display_tree(path_tree, 1);

    inet_pton(AF_INET, srcip, &send_ip);
    inet_pton(AF_INET, dstip, &rece_ip);
	
    if(resv_head == NULL) {
	resv_head = insert_session(resv_head, tunnel_id, srcip, dstip, 1);
    } else {
        insert_session(resv_head, tunnel_id, srcip, dstip, 1);
    }

    // Send RSVP-TE PATH Message
    send_path_message(sock, send_ip, rece_ip, path->tunnel_id);
    //---------------------------------------------------------
    
    //path_event_handler(); //send path msg
    int reached = 0;
    
    close(sock);
    return 0;
}

