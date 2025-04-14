#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>

#include "timer-event.h"
#include "rsvp_msg.h"
#include "rsvp_db.h"

extern int sock;
struct in_addr sender_ip, receiver_ip;

extern struct session* path_head;
extern struct session* resv_head;
extern db_node* resv_tree;
extern db_node* path_tree;

#define TIMEOUT 90
#define INTERVAL 30

static timer_t path_timer;
static timer_t resv_timer;

void delete_timer(timer_t *timer_id) {
    if(timer_delete(*timer_id)) {
        perror("timer delete failed\n");
        exit(EXIT_FAILURE);
    }
    free(timer_id);
    printf(" timer delete sucessfully %p \n", timer_id);
}

//Timer event handler for seding PATH message
//it will chk for RESV message every IntervaL
//no RESV message received for TIMEOUT sec
//session will expire
void path_timer_handler(union sigval sv) {

    time_t now = time(NULL);
    struct session* temp = NULL;
    temp = resv_head;

    printf("++++++++path timer handler \n");
    if(temp ==  NULL)
        printf("temp is nuLL");
    while(temp != NULL) {

	if(temp->dest) {
            printf("--------sending  path message\n");

            //inet_pton(AF_INET, temp->sender, &sender_ip);
            //inet_pton(AF_INET, temp->receiver, &receiver_ip);

            // Send RSVP-TE PATH Message
            send_path_message(sock, temp->tunnel_id);
        }


        if((now - temp->last_path_time) > TIMEOUT) {
		if(!temp->dest) {
			printf("RSVP path session expired: %s\t-->%s\n",temp->sender, temp->receiver);
			resv_head = delete_session(temp, temp->sender, temp->receiver);
		}
		resv_tree = delete_node(resv_tree, temp->tunnel_id, compare_resv_del, 0);
                display_tree(resv_tree, 0);
        } else if((now - temp->last_path_time) < INTERVAL) {
            printf(" less than 30 sec\n");
            temp = temp->next;
            continue;
        } else {
                printf("not received resv msg\n");
        }
        temp = temp->next;
    }
    if(resv_head == NULL) {
        if(sv.sival_ptr == NULL)
            return;

        timer_t *id = (timer_t*)sv.sival_ptr;
        delete_timer(id);
        sv.sival_ptr = NULL;
    }
}

//Timer event handler for seding RESV message
//it will chk for PATH message every IntervaL 
//no PATH message received for TIMEOUT sec
//session will expire
void resv_timer_handler(union sigval sv) {
    time_t now = time(NULL);
    struct session* temp = NULL;
    temp = path_head;

    printf("timer handler \n");
    while(temp != NULL) {
        if((now - temp->last_path_time) > TIMEOUT) {
            printf("RSVP resv session expired: %s\t-->%s\n",temp->sender, temp->receiver);
            path_head = delete_session(temp, temp->sender, temp->receiver);
            path_tree = delete_node(path_tree, temp->tunnel_id, compare_path_del, 1);
            display_tree(path_tree, 1);
        } else if((now - temp->last_path_time) < INTERVAL) {
            printf(" less than 30 sec\n");
            temp = temp->next;
            continue;
        } else {
            if(temp->dest) {
                printf("--------sending resv message\n");

                inet_pton(AF_INET, temp->sender, &sender_ip);
                inet_pton(AF_INET, temp->receiver, &receiver_ip);

                // Send RSVP-TE RESV Message
                send_resv_message(sock, temp->tunnel_id);
            } else {
                printf("not received path msg\n");
            }

        }
        temp = temp->next;
    }
    if(path_head == NULL) {
        if(sv.sival_ptr == NULL)
            return;

        timer_t *id = (timer_t*)sv.sival_ptr;	
        delete_timer(id);
        sv.sival_ptr = NULL;
    }
}

// Function to create a timer that triggers every 30 seconds
timer_t create_timer(void (*handler)(union sigval)) {
    struct sigevent sev;
    timer_t *timerid = malloc(sizeof(timer_t));

    memset(&sev, 0, sizeof(struct sigevent));
    sev.sigev_notify = SIGEV_THREAD;
    sev.sigev_notify_function = handler;
    sev.sigev_value.sival_ptr = timerid;

    if (timer_create(CLOCK_REALTIME, &sev, timerid) < 0) {
        perror("Timer creation failed");
        exit(EXIT_FAILURE);
    }
    return *timerid;
}


// Function to start a timer with a 30-second interval
void start_timer(timer_t timerid) {
    struct itimerspec its;
    its.it_value.tv_sec = 30;   // Initial delay
    its.it_value.tv_nsec = 0;
    its.it_interval.tv_sec = INTERVAL; // Repeating interval
    its.it_interval.tv_nsec = 0;

    if (timer_settime(timerid, 0, &its, NULL) < 0) {
        perror("Timer start failed");
        exit(EXIT_FAILURE);
    }
}

int is_timer_active(timer_t *timer) {
    struct itimerspec ts;
    if(*timer == 0)
        return 0;

    if(timer_gettime(*timer, &ts) == 0) {	
        return (ts.it_value.tv_sec > 0 || ts.it_value.tv_nsec > 0);
    } else {
        *timer = 0;
        return 0;
    }
}

void path_event_handler() {
    if(is_timer_active(&path_timer)) {
        return;
    }
    path_timer = create_timer(path_timer_handler);
    start_timer(path_timer);
}

void resv_event_handler() {
    if(is_timer_active(&resv_timer)) {
        return;
    }
    resv_timer = create_timer(resv_timer_handler);
    start_timer(resv_timer);
}

