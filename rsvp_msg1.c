#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/ip.h>
#include "rsvp_msg.h"

#define IP_ADDRLEN 16
extern char nhip[16];

// Function to send an RSVP-TE RESV message with label assignment
void send_resv_message(int sock, struct in_addr sender_ip, struct in_addr receiver_ip) {
    struct sockaddr_in dest_addr;
    char resv_packet[256];

    struct rsvp_header *resv = (struct rsvp_header*)resv_packet;
    //struct class_obj *class_obj = (struct class_obj*)(resv_packet + sizeof(struct rsvp_header));
    struct session_object *session_obj = (struct session_object*)(resv_packet + START_SENT_SESSION_OBJ);
    struct hop_object *hop_obj = (struct hop_object*)(resv_packet + START_SENT_HOP_OBJ);
    struct time_object *time_obj = (struct time_object*)(resv_packet + START_SENT_TIME_OBJ);
    struct label_object *label_obj = (struct label_object*)(resv_packet + START_SENT_LABEL);

    // Populate RSVP RESV header
    resv->version_flags = 0x10;  // RSVP v1
    resv->msg_type = RESV_MSG_TYPE;
    resv->length = htons(sizeof(resv_packet));
    resv->checksum = 0;
    resv->ttl = 255;
    resv->reserved = 0;
    //resv->sender_ip = receiver_ip;
    //resv->receiver_ip = sender_ip;

    //session object for RESV msg
    session_obj->class_obj.class_num = 1;
    session_obj->class_obj.c_type = 7;
    session_obj->class_obj.length = htons(sizeof(struct session_object));
    session_obj->dst_ip = receiver_ip;
    session_obj->tunnel_id = 1;
    session_obj->src_ip = sender_ip;

    //hop object for PATH?RESV msg
    hop_obj->class_obj.class_num = 3;
    hop_obj->class_obj.c_type = 1;
    hop_obj->class_obj.length = htons(sizeof(struct hop_object));
    get_nexthop(inet_ntoa(sender_ip), nhip); //ip->dst_ip, ip->nhip);
    inet_pton(AF_INET, nhip, &hop_obj->next_hop);
    hop_obj->IFH = 123; //dummy

    time_obj->class_obj.class_num = 5;
    time_obj->class_obj.c_type = 1;
    time_obj->class_obj.length = htons(sizeof(struct time_object));
    time_obj->interval = 123; //dummy

    // Populate Label Object
    label_obj->class_obj.class_num = 16;  // Label class
    label_obj->class_obj.c_type = 1;  // Generic Label
    label_obj->class_obj.length = htons(sizeof(struct label_object));
    label_obj->label = htonl(1001);  // Assigned Label (1001)

    // Set destination (ingress router)
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_addr = sender_ip;
    dest_addr.sin_port = 0;

    // Send RESV message
    if (sendto(sock, resv_packet, sizeof(resv_packet), 0, 
               (struct sockaddr*)&dest_addr, sizeof(dest_addr)) < 0) {
        perror("Send failed");
    } else {
        printf("Sent RESV message to %s with Label 1001\n", inet_ntoa(sender_ip));
    }
}

void get_path_class_obj(int class_obj_arr[]) {
	printf("getting calss obj arr\n");
	class_obj_arr[0] = START_RECV_SESSION_OBJ;
        class_obj_arr[1] = START_RECV_HOP_OBJ;
  	class_obj_arr[2] = START_RECV_TIME_OBJ;
        class_obj_arr[3] = START_RECV_LABEL_REQ;
        class_obj_arr[4] = START_RECV_SESSION_ATTR_OBJ;
        class_obj_arr[5] = START_RECV_SENDER_TEMP_OBJ; 	
}

// Function to receive RSVP-TE PATH messages
void receive_path_message(int sock, char buffer[], struct sockaddr_in sender_addr) {
    //char buffer[1024];
    struct class_obj *class_obj;
    int class_obj_arr[10]; 
    int i = 0;
    printf("Listening for RSVP-TE PATH messages...\n");
	
	struct rsvp_header *rsvp = (struct rsvp_header*)(buffer+20);
        printf("Received PATH message from %s\n", inet_ntoa(sender_addr.sin_addr));

        /*struct in_addr sender_ip = rsvp->sender_ip;
        struct in_addr receiver_ip = rsvp->receiver_ip;

        memset(class_obj_arr, 0, sizeof(class_obj_arr));
 	get_path_class_obj(class_obj_arr);
        
	while(class_obj_arr[i] != 0) {
		class_obj = (struct class_obj*) (buffer + class_obj_arr[i]);
		switch(class_obj->class_num) {
			case SESSION:
				printf("session obj %d\n",class_obj->class_num);
				break;
			case HOP:
				printf("hoP obj %d\n",class_obj->class_num);
				break;
			case TIME:
				printf("time obj %d\n",class_obj->class_num);
				break;
			case LABEL_REQUEST: 
            			// Send a RESV message in response
		        	send_resv_message(sock, sender_ip, receiver_ip);
				break;
			case SESSION_ATTRIBUTE:
				printf("session attr obj %d\n",class_obj->class_num);
				break;
			case SENDER_TEMPLATE:
				printf("sender temp obj %d\n",class_obj->class_num);
				break;
		}
		i++;
        }*/
}




//Function to send PATH message for label request
void send_path_message(int sock, struct in_addr sender_ip, struct in_addr receiver_ip) {
    struct sockaddr_in dest_addr;
    char path_packet[256]; // = packet;// + sizeof(struct iphdr);

    struct rsvp_header *path = (struct rsvp_header*)path_packet;
    //struct class_obj *class_obj = (struct class_obj*)(path_packet + START_SENT_CLASS_OBJ); 
    struct session_object *session_obj = (struct session_object*)(path_packet + START_SENT_SESSION_OBJ);
    struct hop_object *hop_obj = (struct hop_object*)(path_packet + START_SENT_HOP_OBJ);
    struct time_object *time_obj = (struct time_object*)(path_packet + START_SENT_TIME_OBJ);
    struct label_req_object *label_req_obj = (struct label_req_object*)(path_packet + START_SENT_LABEL_REQ); 
    struct session_attr_object *session_attr_obj = (struct session_attr_object*)(path_packet + START_SENT_SESSION_ATTR_OBJ); 
    struct sender_temp_object *sender_temp_obj = (struct sender_temp_object*)(path_packet + START_SENT_SENDER_TEMP_OBJ);

    // Populate RSVP PATH header
    path->version_flags = 0x10;  // RSVP v1
    path->msg_type = PATH_MSG_TYPE;
    path->length = htons(sizeof(path_packet));
    path->checksum = 0;
    path->ttl = 255;
    path->reserved = 0;
    //path->sender_ip = sender_ip;
    //path->receiver_ip = receiver_ip;

    //session object for PATH msg
    session_obj->class_obj.class_num = 1;
    session_obj->class_obj.c_type = 7;
    session_obj->class_obj.length = htons(sizeof(struct session_object));
    session_obj->dst_ip = receiver_ip;
    session_obj->tunnel_id = 1;
    session_obj->src_ip = sender_ip;

    //hop object for PATH and RESV msg
    hop_obj->class_obj.class_num = 3;
    hop_obj->class_obj.c_type = 1;
    hop_obj->class_obj.length = htons(sizeof(struct hop_object));
    get_nexthop(inet_ntoa(receiver_ip), nhip); //ip->dst_ip, ip->nhip);
    inet_pton(AF_INET, nhip, &hop_obj->next_hop);
    hop_obj->IFH = 123; //dummy

    time_obj->class_obj.class_num = 5;
    time_obj->class_obj.c_type = 1;
    time_obj->class_obj.length = htons(sizeof(struct time_object));
    time_obj->interval = 123; //dummy

    // Populate Label Object                                        
    label_req_obj->class_obj.class_num = 19;  // Label Request class
    label_req_obj->class_obj.c_type = 1;  // Generic Label                   
    label_req_obj->class_obj.length = htons(sizeof(struct label_req_object));
    label_req_obj->L3PID = htonl(0x0800);  // Assigned Label (1001)

    //session attribute object for PATH msg
    session_attr_obj->class_obj.class_num = 207;
    session_attr_obj->class_obj.c_type = 1;
    session_attr_obj->class_obj.length = htons(sizeof(struct session_attr_object));
    session_attr_obj->setup_prio = 7;
    session_attr_obj->hold_prio = 7;
    session_attr_obj->flags = 0;
    session_attr_obj->name_len = sizeof("PE1");
    //strcpy("PE1", session_attr_obj->Name);
    
    //Sender template object for PATH msg
    sender_temp_obj->class_obj.class_num = 11;
    sender_temp_obj->class_obj.c_type = 7;
    sender_temp_obj->class_obj.length = htons(sizeof(struct sender_temp_object));    
    //inet_pton(AF_INET, sender_ip, &sender_temp_obj->src_ip);
    sender_temp_obj->src_ip = sender_ip;
    sender_temp_obj->Reserved = 0;
    sender_temp_obj->LSP_ID = 2;

    // Set destination (egress router)
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_addr = hop_obj->next_hop;
    dest_addr.sin_port = 0;

     printf(" sending message1 = %d\n",sock);
    // Send PATH message
    if (sendto(sock, path_packet, sizeof(path_packet), 0,
               (struct sockaddr*)&dest_addr, sizeof(dest_addr)) < 0) {
        perror("Send failed");
    } else {
        printf("Sent PATH message to %s\n", inet_ntoa(hop_obj->next_hop));
    }
}



void get_resv_class_obj(int class_obj_arr[]) {
	printf("getting calss obj arr\n");
	class_obj_arr[0] = START_RECV_SESSION_OBJ;
        class_obj_arr[1] = START_RECV_HOP_OBJ;
  	class_obj_arr[2] = START_RECV_TIME_OBJ;
	class_obj_arr[3] = START_RECV_FILTER_SPEC_OBJ;
        class_obj_arr[4] = START_RECV_LABEL;
}


// Function to receive an RSVP-TE RESV message
void receive_resv_message(int sock, char buffer[], struct sockaddr_in sender_addr) {

    struct class_obj *class_obj;
    int class_obj_arr[10]; 
    int i = 0;

    printf("Listening for RSVP-TE RESV messages...\n");

    memset(class_obj_arr, 0, sizeof(class_obj_arr));
    get_resv_class_obj(class_obj_arr);
    struct label_object *label_obj;
    
    while(class_obj_arr[i] != 0) {
	class_obj = (struct class_obj*) (buffer + class_obj_arr[i]);
    	switch(class_obj->class_num) {

		case SESSION:
			break;
		case HOP:
			break;
		case TIME:
			break;	
		case FILTER_SPEC:
			break;
		case RSVP_LABEL: 
			label_obj = (struct label_object*)(buffer + START_RECV_LABEL);
            		printf("Received RESV message from %s with Label %d\n", 
				inet_ntoa(sender_addr.sin_addr), ntohl(label_obj->label));	
			break;
        }
	i++;
    } 
}



//get src and dst ip from session object
void get_ip(char buffer[], char *sender_ip, char *receiver_ip) {

        struct session_object *temp = (struct session_object*)(buffer+START_RECV_SESSION_OBJ);
        //inet_pton(AF_INET, "192.168.13.2", &sender_ip);
        inet_ntop(AF_INET, &temp->src_ip, sender_ip, IP_ADDRLEN);
        inet_ntop(AF_INET, &temp->dst_ip, receiver_ip, IP_ADDRLEN);

        printf(" ip is %s %s\n", sender_ip,receiver_ip);
}

