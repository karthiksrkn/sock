// rsvpd.c (replaces socket1.c)
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <pthread.h>
#include <signal.h>
#include "socket.h"
#include "log.h"
#include "rsvp_db.h"

#define SOCKET_PATH "/tmp/rsvp_socket"
#define LOG_FILE_PATH "/tmp/rsvpd.log"
int sock = 0;
int ipc_sock = 0;

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
        log_message("Received bytes in receive_thread");
        struct rsvp_header* rsvp = (struct rsvp_header*)buffer;
        char sender_ip[16], receiver_ip[16];
        uint16_t tunnel_id;

        //pthread_mutex_lock(&data_mutex);
        log_message("Mutex locked in receive_thread");
        switch (rsvp->msg_type) {
            case PATH_MSG_TYPE:
                receive_path_message(sock, buffer, sender_addr);
                break;
            case RESV_MSG_TYPE:
                get_ip(buffer, sender_ip, receiver_ip, &tunnel_id);
                log_message("insert_resv_session");
                if (resv_head == NULL) {
                    resv_head = insert_session(resv_head, tunnel_id, sender_ip, receiver_ip, 1);
                } else {
                    insert_session(resv_head, tunnel_id, sender_ip, receiver_ip, 1);
                }
                receive_resv_message(sock, buffer, sender_addr);
                break;
            default: {
                char msg[64];
                snprintf(msg, sizeof(msg), "Unknown RSVP message type: %d", rsvp->msg_type);
                log_message(msg);
            }
        }

        //pthread_mutex_unlock(&data_mutex);
        log_message("Mutex unlocking in receive_thread");
    }
    return NULL;
}

void* ipc_server_thread(void* arg) {
    struct sockaddr_un addr;
    int client_sock;
    char buffer[1024];
    char response[MAX_OUTPUT_BUFFER];

    ipc_sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (ipc_sock < 0) {
        log_message("IPC socket creation failed");
        exit(1);
    }

    unlink(SOCKET_PATH);
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, SOCKET_PATH, sizeof(addr.sun_path) - 1);

    if (bind(ipc_sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        log_message("IPC bind failed");
        close(ipc_sock);
        exit(1);
    }

    if (listen(ipc_sock, 5) < 0) {
        log_message("IPC listen failed");
        close(ipc_sock);
        exit(1);
    }

    log_message("IPC server started");

    while (1) {
        client_sock = accept(ipc_sock, NULL, NULL);
        if (client_sock < 0) {
            log_message("IPC accept failed");
            continue;
        }

        int bytes = recv(client_sock, buffer, sizeof(buffer) - 1, 0);
        log_message("bytes %d", bytes);
        if (bytes > 0) {
            buffer[bytes] = '\0';
            
            if (strncmp(buffer, "show path", 9) == 0) {
                get_path_tree_info(response, sizeof(response));
            } else if (strncmp(buffer, "show resv", 9) == 0) {
                get_resv_tree_info(response, sizeof(response));
            } else if (strncmp(buffer, "add ", 4) == 0) {
                rsvp_add_config(buffer + 4, response, sizeof(response));
            } else if (strncmp(buffer, "delete ", 7) == 0) {
                rsvp_delete_config(buffer + 7, response, sizeof(response));
            } else {
                snprintf(response, sizeof(response), "Unknown command\n");
            }
            
            send(client_sock, response, strlen(response), 0);
        }
        close(client_sock);
    }
    return NULL;
}

void daemonize() {
    pid_t pid = fork();
    if (pid < 0) exit(1);
    if (pid > 0) exit(0); // Parent exits
    setsid();
    pid = fork();
    if (pid < 0) exit(1);
    if (pid > 0) exit(0); // Second parent exits
    umask(0);
    chdir("/");
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);
}

int rsvpd_main(void) {
    struct sockaddr_in addr;
    pthread_t recv_tid, ipc_tid;

    // Initialize logging
    log_file = fopen(LOG_FILE_PATH, "a");
    if (!log_file) {
        perror("Failed to open log file");
        exit(1);
    }

    // Daemonize
    daemonize();
    log_message("RSVP daemon started");

    // Setup RSVP socket
    sock = socket(AF_INET, SOCK_RAW, RSVP_PROTOCOL);
    if (sock < 0) {
        log_message("Socket creation failed");
        exit(1);
    }

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    //addr.sin_port = htons(3455);
    if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        log_message("Binding failed");
        close(sock);
        exit(1);
    }
    log_message("RSVP daemon started, bound to port 3455");
    // Start threads
    pthread_create(&recv_tid, NULL, receive_thread, NULL);
    pthread_create(&ipc_tid, NULL, ipc_server_thread, NULL);

    // Start timers
    path_event_handler();
    resv_event_handler();

    pthread_join(recv_tid, NULL); // Keep main thread alive
    pthread_join(ipc_tid, NULL);

    close(sock);
    close(ipc_sock);
    fclose(log_file);
    return 0;
}