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

extern pthread_mutex_t path_tree_mutex;
extern pthread_mutex_t resv_tree_mutex;
extern pthread_mutex_t path_list_mutex;
extern pthread_mutex_t resv_list_mutex;

#define TIMEOUT 90
#define INTERVAL 30

static timer_t path_timer;
static timer_t resv_timer;

void delete_timer(timer_t *timer_id) {
    if(timer_delete(*timer_id)) {
        perror("timer delete failed\n");
        exit(EXIT_FAILURE);
    }
    timer_id = 0;
    log_message(" timer delete sucessfully %p \n", timer_id);
}

//Timer event handler for seding PATH message
//it will chk for RESV message every IntervaL
//no RESV message received for TIMEOUT sec
//session will expire
void path_timer_handler(union sigval sv) {
    time_t now = time(NULL);
    struct session* temp = NULL;
    struct session* prev = NULL;
    temp = resv_head;

    log_message("++++++++path timer handler \n");
    while(temp != NULL) {

        log_message(" temp->dest = %d tunnel_id = %d\n", temp->dest, temp->tunnel_id);
        if(temp->dest && !temp->del) {
            send_path_message(sock, temp->tunnel_id);
        }

        if((now - temp->last_path_time) > TIMEOUT) {
            pthread_mutex_lock(&resv_tree_mutex);
            log_message("RSVP path session expired delete tunnel id %d from resv tree", temp->tunnel_id);
            display_tree_debug(resv_tree, 0);
            if(search_node(resv_tree, temp->tunnel_id, compare_resv_del) != NULL){
                resv_tree = delete_node(resv_tree, temp->tunnel_id, compare_resv_del, 0);
                display_tree_debug(resv_tree, 0);
            }
            pthread_mutex_unlock(&resv_tree_mutex);

            if(!temp->dest || temp->del) {		
                log_message("RSVP path session expired: %s\t-->%s\n",temp->sender, temp->receiver);
                pthread_mutex_lock(&resv_list_mutex);
                resv_head = delete_session(resv_head, temp, prev);
                print_session(resv_head);
                pthread_mutex_unlock(&resv_list_mutex);
            }
        } else if((now - temp->last_path_time) < INTERVAL) {
            log_message(" less than 30 sec\n");
            prev = temp;
            temp = temp->next;
            continue;
        } else {
            log_message("not received resv msg\n");
        }
        prev = temp;
        temp = temp->next;
    }
}

//Timer event handler for seding RESV message
//it will chk for PATH message every IntervaL 
//no PATH message received for TIMEOUT sec
//session will expire
void resv_timer_handler(union sigval sv) {
    time_t now = time(NULL);
    struct session* temp = NULL;
    struct session* prev = NULL;
    temp = path_head;

    log_message("timer handler \n");
    while(temp != NULL) {
        if((now - temp->last_path_time) > TIMEOUT) {
            log_message("RSVP resv session expired:  tunnel id %d %s\t-->%s\n",temp->tunnel_id, temp->sender, temp->receiver);

            //delete node
            pthread_mutex_lock(&path_tree_mutex);
            if(search_node(path_tree, temp->tunnel_id, compare_path_del) != NULL) {
                path_tree = delete_node(path_tree, temp->tunnel_id, compare_path_del, 1);
                display_tree_debug(path_tree, 1);
            }
            pthread_mutex_unlock(&path_tree_mutex);

            //delete session
            pthread_mutex_lock(&path_list_mutex);
            path_head = delete_session(path_head, temp, prev);
            if(path_head != NULL)
                print_session(path_head);
            pthread_mutex_unlock(&path_list_mutex);

            if(temp->dest) {
                pthread_mutex_lock(&resv_tree_mutex);
                log_message("deleteing node and sess for tunnel id %d from resv tree", temp->tunnel_id);
                display_tree_debug(resv_tree, 0);
                if(search_node(resv_tree, temp->tunnel_id, compare_resv_del) != NULL){
                    resv_tree = delete_node(resv_tree, temp->tunnel_id, compare_resv_del, 0);
                    display_tree_debug(resv_tree, 0);
                }
                pthread_mutex_unlock(&resv_tree_mutex);

                log_message("RSVP resv session expired: %s\t-->%s\n",temp->sender, temp->receiver);
                pthread_mutex_lock(&resv_list_mutex);
                struct session *temp1 = resv_head;
                struct session *prev1 = NULL;
                while(temp1 != NULL){
                    if (temp->tunnel_id == temp1->tunnel_id){
                        resv_head = delete_session(resv_head, temp1, prev1);
                        if(resv_head != NULL)
                            print_session(resv_head);
                        break;
                    }
                    prev1 = temp1;
                    temp1 = temp1->next;
                }

                pthread_mutex_unlock(&resv_list_mutex);
            }
        } else if((now - temp->last_path_time) < INTERVAL) {
            log_message(" less than 30 sec\n");
            prev = temp;
            temp = temp->next;
            continue;
        } else {
            if(temp->dest) {
                log_message("--------sending resv message\n");
                send_resv_message(sock, temp->tunnel_id);
            } else {
                log_message("not received path msg\n");
            }
        }
        prev = temp;
        temp = temp->next;
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

