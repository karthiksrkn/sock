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

#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <unistd.h>
#include <time.h>
#include <stdio.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <linux/rtnetlink.h>

#include "log.h"

static char dest_ip[16], nh[16], DEv[16];
static uint32_t ifh;
uint8_t prefix_len = 0;
char src_ip[16];

// Function to check if an IP is in a subnet
int is_ip_in_subnet(const char *ip, const char *subnet, int prefix_len) {
    struct in_addr ip_addr, subnet_addr, mask;

    // Convert IP addresses from string to binary format
    inet_pton(AF_INET, ip, &ip_addr);
    inet_pton(AF_INET, subnet, &subnet_addr);

    // Create the subnet mask from prefix length (CIDR notation)
    mask.s_addr = htonl(~((1 << (32 - prefix_len)) - 1));

    // default route
    if(!(subnet_addr.s_addr & mask.s_addr))
        return 2;

    // Perform bitwise AND
    if ((ip_addr.s_addr & mask.s_addr) == (subnet_addr.s_addr & mask.s_addr)) {
        return 1; // IP is in the subnet
    }
    return 0; // IP is not in the subnet
}

static int rtnl_recvmsg(int fd, struct msghdr *msg, char **answer)
{
    struct iovec *iov = msg->msg_iov;
    char *buf;
    int len;

    iov->iov_base = NULL;
    iov->iov_len = 0;

    len = recv(fd, NULL, 0, MSG_PEEK | MSG_TRUNC);

    if (len < 0) {
        return len;
    }

    buf = malloc(len);

    if (!buf) {
        perror("malloc failed");
        return -ENOMEM;
    }

    iov->iov_base = buf;
    iov->iov_len = len;

    len = recv(fd, buf, len, 0);

    if (len < 0) {
        free(buf);
        return len;
    }

    *answer = buf;

    return len;
}

void parse_rtattr(struct rtattr *tb[], int max, struct rtattr *rta, int len)
{
    memset(tb, 0, sizeof(struct rtattr *) * (max + 1));

    while (RTA_OK(rta, len)) {
        if (rta->rta_type <= max) {
            tb[rta->rta_type] = rta;
        }

        rta = RTA_NEXT(rta,len);
    }
}

static inline int rtm_get_table(struct rtmsg *r, struct rtattr **tb)
{
    __u32 table = r->rtm_table;

    if (tb[RTA_TABLE]) {
        table = *(__u32 *)RTA_DATA(tb[RTA_TABLE]);
    }

    return table;
}

int print_route(struct nlmsghdr* nl_header_answer)
{
    struct rtmsg* r = NLMSG_DATA(nl_header_answer);
    int len = nl_header_answer->nlmsg_len;
    struct rtattr* tb[RTA_MAX+1];
    int table;
    char buf[256];
    char route[16], *dev;

    len -= NLMSG_LENGTH(sizeof(*r));

    if (len < 0) {
        perror("Wrong message length");
        return 0;
    }

    strcpy((char*)route, " ");
    strcpy(nh, " ");
    strcpy(src_ip, " ");

    parse_rtattr(tb, RTA_MAX, RTM_RTA(r), len);

    table = rtm_get_table(r, tb);

    if (r->rtm_family != AF_INET && table != RT_TABLE_MAIN) {
        return 0;
    }

    if(r->rtm_type != RTN_LOCAL && r->rtm_type != RTN_UNICAST)
        return 0;

    if (tb[RTA_DST]) {
        /*if ((r->rtm_dst_len != 24) && (r->rtm_dst_len != 16)) {
          return;
          }*/

        inet_ntop(r->rtm_family, RTA_DATA(tb[RTA_DST]), buf, sizeof(buf));
        strcpy(route, buf);
        prefix_len = r->rtm_dst_len;	
        //log_message("route = %s %d\n", route,prefix_len);
        //log_message("%s/%u ", inet_ntop(r->rtm_family, RTA_DATA(tb[RTA_DST]), buf, sizeof(buf)), r->rtm_dst_len);

    } else if (r->rtm_dst_len) {
        log_message("0/%u ", r->rtm_dst_len);
    } else {
        //log_message("default ");
        strcpy(route, "0.0.0.0");
        //route = "0.0.0.0";
    }

    if (tb[RTA_GATEWAY]) {
        inet_ntop(r->rtm_family, RTA_DATA(tb[RTA_GATEWAY]), buf, sizeof(buf));
        strcpy(nh, buf);
        //log_message("next hop for destination ip %s is -> %s\n", dest_ip, nh);
        //log_message("via %s", inet_ntop(r->rtm_family, RTA_DATA(tb[RTA_GATEWAY]), buf, sizeof(buf)));
    }

    if (tb[RTA_OIF]) {
        char if_nam_buf[IF_NAMESIZE];
        int ifidx = *(__u32 *)RTA_DATA(tb[RTA_OIF]);

	ifh = ifidx;
        dev = if_indextoname(ifidx, if_nam_buf);
        strcpy(DEv, dev);

        //log_message("dev -- %s ifidx = %d buf = %s\n", dev,ifidx,if_nam_buf);
        //log_message(" dev %s", if_indextoname(ifidx, if_nam_buf));
    }

    if (tb[RTA_SRC]) {
        //inet_ntop(r->rtm_family, RTA_DATA(tb[RTA_SRC]), buf, sizeof(buf));
        //strcpy(src, buf);

        //log_message("\n src -- %s\n", src);
        //log_message("src %s", inet_ntop(r->rtm_family, RTA_DATA(tb[RTA_SRC]), buf, sizeof(buf)));
    }

    if (tb[RTA_PREFSRC]) {
        inet_ntop(r->rtm_family, RTA_DATA(tb[RTA_PREFSRC]), buf, sizeof(buf));
        strcpy(src_ip, buf);
        //log_message("src_ip = %s\n",src_ip);	
        //log_message("src %s\n", inet_ntop(r->rtm_family, RTA_DATA(tb[RTA_PREFSRC]), buf, sizeof(buf)));
    }

    if(is_ip_in_subnet(dest_ip, route, prefix_len) == 1) {
	log_message("next hop for destination ip %s is -> %s prefix_len = %d dev = %s ifh = %d\n", dest_ip,nh,prefix_len, DEv, ifh);
        return 1;
    } else {
        return 0;
    }

    //log_message("\n");
}

int open_netlink()
{
    struct sockaddr_nl saddr;

    int sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);

    if (sock < 0) {
        perror("Failed to open netlink socket");
        return -1;
    }

    memset(&saddr, 0, sizeof(saddr));

    saddr.nl_family = AF_NETLINK;
    saddr.nl_pid = getpid();

    if (bind(sock, (struct sockaddr *)&saddr, sizeof(saddr)) < 0) {
        perror("Failed to bind to netlink socket");
        close(sock);
        return -1;
    }

    return sock;
}

int do_route_dump_requst(int sock)
{
    struct {
        struct nlmsghdr nlh;
        struct rtmsg rtm;
    } nl_request;

    memset(&nl_request, 0, sizeof(nl_request));
    nl_request.nlh.nlmsg_type = RTM_GETROUTE;
    nl_request.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    nl_request.nlh.nlmsg_len = sizeof(nl_request);
    nl_request.nlh.nlmsg_seq = time(NULL);
    nl_request.rtm.rtm_family = AF_INET;
    //nl_request.rtm.rtm_table = RT_TABLE_LOCAL;

    return send(sock, &nl_request, sizeof(nl_request), 0);
}

int get_route_dump_response(int sock)
{
    struct sockaddr_nl nladdr;
    struct iovec iov;
    struct msghdr msg = {
        .msg_name = &nladdr,
        .msg_namelen = sizeof(nladdr),
        .msg_iov = &iov,
        .msg_iovlen = 1,
    };

    char *buf;
    int dump_intr = 0;

    int status = rtnl_recvmsg(sock, &msg, &buf);

    struct nlmsghdr *h = (struct nlmsghdr *)buf;
    int msglen = status;

    //log_message("Main routing table IPv4\n");

    while (NLMSG_OK(h, msglen)) {
        if (h->nlmsg_flags & NLM_F_DUMP_INTR) {
            fprintf(stderr, "Dump was interrupted\n");
            free(buf);
            return -1;
        }

        //if (nladdr.nl_pid != 0) {
        //    continue;
        //}

        if (h->nlmsg_type == NLMSG_ERROR) {
            perror("netlink reported error");
            free(buf);
        }

        if(print_route(h)) { 
            return 1;
        }


        h = NLMSG_NEXT(h, msglen);
    }

    free(buf);

    return status;
}

int get_nexthop(const char *dst_ip, char *nh_ip, uint8_t *pref_len, char* Dev, int *Ifh)
{

    int temp = 0;

    strcpy(dest_ip, dst_ip);
    int nl_sock = open_netlink();

    if (do_route_dump_requst(nl_sock) < 0) {
        perror("Failed to perfom request");
        close(nl_sock);
        return -1;
    }

    temp = get_route_dump_response(nl_sock);

    strcpy(nh_ip, nh);
    strcpy(Dev, DEv);
    *Ifh = ifh;
    *pref_len = prefix_len;

    close (nl_sock);

    if(temp)
        return 1;

    return 0;
}
