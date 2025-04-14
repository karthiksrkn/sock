// rsvpsh.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>

#define SOCKET_PATH "/tmp/rsvp_socket"
#define MAX_BUFFER 4096

int rsvpsh_main() {
    int sock;
    struct sockaddr_un addr;
    char input[256], response[MAX_BUFFER];
    int in_config_mode = 0;

    printf("\033[1;32mRSVP Shell (OpenWrt)\033[0m\n");

    while (1) {
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