/*
 * =====================================================================================
 *
 *       Filename:  inotify.h
 *
 *    Description:
 *
 *        Version:  1.0
 *        Created:  12/03/2018 12:43:23 PM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  Benedict Lo & Aing Ragunathan
 *   Organization:
 *
 * =====================================================================================
 */

#ifndef INOTIFY_H
#define INOTIFY_H

#include <sys/inotify.h>
#include <sys/epoll.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include "epoll.h"
#include "covert_wrappers.h"
#include "libpcap.h"
#include <stdbool.h>
#include <stdio.h>

#define EVENT_SIZE (sizeof (struct inotify_event))
#define BUFLEN (1024 * (EVENT_SIZE + 16))

void watch_directory(char *targetip, char* localip, char *directory, char* file, bool tcp);
int initInotify();
int addWatch(int socket, char *directory);


#endif
