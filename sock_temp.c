#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define NL_MSG_BUF_SIZE 8192

// Structure for parsing Netlink response
struct route_info {
    struct nlmsghdr nlh;
    struct rtmsg rtm;
    char buffer[NL_MSG_BUF_SIZE];
};

// Function to handle the response from the kernel
int parse_rtnetlink_response(int sockfd) {
    struct route_info route;
    struct nlmsghdr *nlh;
    struct rtmsg *rtm;
    struct rtattr *rta;
    int len;
    
    while (1) {
        // Receive message from the kernel
        len = recv(sockfd, &route, sizeof(route), 0);
        if (len < 0) {
            perror("Failed to receive Netlink message");
            return -1;
        }

        nlh = &route.nlh;
        rtm = (struct rtmsg *) NLMSG_DATA(nlh);
        
        // Only process the message if it's a route message
        if (nlh->nlmsg_type == RTM_NEWROUTE) {
            // Process the message: extract the destination and next hop info
            printf("Routing table entry found: \n");

            // Process the attributes in the message
            rta = (struct rtattr *) RTM_RTA(rtm);
            int rta_len = RTM_PAYLOAD(nlh);
            while (RTA_OK(rta, rta_len)) {
                if (rta->rta_type == RTA_GATEWAY) {
                    // Print next hop address (gateway)
                    struct sockaddr_in *gw = (struct sockaddr_in *) RTA_DATA(rta);
                    printf("Next hop (Gateway): %s\n", inet_ntoa(gw->sin_addr));
                }
                struct sockaddr_in *gw = (struct sockaddr_in *) RTA_DATA(rta);
                    printf("=========Next hop (Gateway): %s\n", inet_ntoa(gw->sin_addr));
                rta = RTA_NEXT(rta, rta_len);
            }
	    struct sockaddr_in *gw = (struct sockaddr_in *) RTA_DATA(rta);
                    printf("=========Next hop (Gateway): %s\n", inet_ntoa(gw->sin_addr));

        }

        struct sockaddr_in *gw = (struct sockaddr_in *) RTA_DATA(rta);
                    printf("=========Next hop (Gateway): %s\n", inet_ntoa(gw->sin_addr));


        if (nlh->nlmsg_flags & NLM_F_MULTI) {
            continue;
        } else {
            break;
        }
    }

    return 0;
}

int main(int argc, char *argv[]) {
    int sockfd;
    struct sockaddr_nl sa;
    struct nlmsghdr *nlh;
    struct rtmsg rtm;
    struct rtattr *rta;
    struct in_addr dest_addr;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <destination-ip>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    const char *dest_ip = argv[1];
    inet_pton(AF_INET, dest_ip, &dest_addr);

    // Create a Netlink socket
    sockfd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (sockfd < 0) {
        perror("Failed to create Netlink socket");
        exit(EXIT_FAILURE);
    }

    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;

    // Build the request message (RTM_GETROUTE)
    nlh = (struct nlmsghdr *) malloc(NLMSG_SPACE(sizeof(struct rtmsg)));
    memset(nlh, 0, NLMSG_SPACE(sizeof(struct rtmsg)));
    
    nlh->nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
    nlh->nlmsg_type = RTM_GETROUTE; // Requesting route information
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    nlh->nlmsg_seq = 1;
    nlh->nlmsg_pid = getpid();

    rtm = *(struct rtmsg *) NLMSG_DATA(nlh);
    rtm.rtm_family = AF_INET; // IPv4
    rtm.rtm_dst_len = 32; // Destination length (full prefix)
    rtm.rtm_table = RT_TABLE_MAIN;

    // Attach the destination IP address as the route filter
    rta = (struct rtattr *) RTM_RTA(&rtm);
    rta->rta_type = RTA_DST;
    rta->rta_len = RTA_LENGTH(sizeof(struct in_addr));
    memcpy(RTA_DATA(rta), &dest_addr, sizeof(struct in_addr));

    // Send the request
    if (sendto(sockfd, nlh, nlh->nlmsg_len, 0, (struct sockaddr *) &sa, sizeof(sa)) < 0) {
        perror("Failed to send Netlink message");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    // Parse the response
    parse_rtnetlink_response(sockfd);

    // Cleanup and close the socket
    close(sockfd);
    return 0;
}

