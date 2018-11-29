/*
 * =====================================================================================
 *
 *       Filename:  epoll.h
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

#define _GNU_SOURCE
#ifndef EPOLL_H
#define EPOLL_H

#include <sys/epoll.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/epoll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <limits.h>
#include <fcntl.h>
#include "socketwrappers.h"


int createEpollFd();
void addEpollSocket(const int epollfd, const int sock, struct epoll_event *ev);
int waitForEpollEvent(const int epollfd, struct epoll_event *events);
#endif
