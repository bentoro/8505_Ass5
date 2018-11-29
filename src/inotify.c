
/*
 * =====================================================================================
 *
 *       Filename:  inotify.c
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

#include "inotify.h"



/*
 * =====================================================================================
 *
 *       function: initInotify
 *
 *         return: int
 *
 *       Parameters:
 *                    void
 *
 *       Notes:
 *              creates a inotify socket
 * =====================================================================================
 */
int initInotify(){
    int socket;
    if((socket = inotify_init1(IN_NONBLOCK)) < 0){
        perror("Could not initilize inotify");
        exit(1);
    }
    return socket;
}



/*
 * =====================================================================================
 *
 *       function: addWatch
 *
 *         return: int
 *
 *       Parameters:
 *                    int socket - socket
 *                    char *directory - directory to watch
 *
 *       Notes:
 *              creates a inotify socket
 * =====================================================================================
 */
int addWatch(int socket, char *directory){
    int watch;
    if((watch = inotify_add_watch(socket, directory, IN_MODIFY)) < 0){
        perror("Could not iniitilize watch descriptor");
    }
    return watch;
}


/*
 * =====================================================================================
 *
 *       function: addWatch
 *
 *         return: void
 *
 *       Parameters:
 *                    char *targetip - target ip to use
 *                    char *localip - machines local ip
 *                    char *directory - directory to watch
 *                    char *file - file to watch
 *                    bool tcp - tcp or udp
 *
 *       Notes:
 *              creates a inotify socket
 * =====================================================================================
 */
void watch_directory(char *targetip, char* localip, char *directory, char* file, bool tcp){
    int socket, epollfd;
    struct epoll_event event;
    struct epoll_event *events;
    char buffer[BUFLEN];
    int k, len;

    socket = initInotify();
    addWatch(socket, directory);
    epollfd = createEpollFd();

    event.events = EPOLLIN | EPOLLOUT | EPOLLET;
    event.data.fd = socket;
    addEpollSocket(epollfd, socket, &event);
    events = calloc(64, sizeof(event));

    while(1){
        int ret = waitForEpollEvent(epollfd, events);
        for(int i = 0; i < ret; ++i){
            if(ret > 0){
                k =0;
                printf("Modificaitons were made to the file\n");
                len = read(socket, buffer, BUFLEN);
                while(k < len){
                    struct inotify_event *ievent;
                    ievent = (struct inotify_event *) &buffer[k];
                    printf("wd=%d, mask=%u cookie=%u len=%u\n", ievent->wd, ievent->mask, ievent->cookie, ievent->len);
                    if(ievent->len){
                        printf("name=%s\n", ievent->name);
                        if(strcmp(ievent->name, file) == 0){
                            char filename[BUFSIZ];
                            strncat(filename, directory, BUFSIZ);
                            strncat(filename, file, BUFSIZ);
                            printf("Filename: %s\n", filename);
			    send_results(localip, targetip, UPORT, UPORT, filename, tcp, INOTIFY);
                            printf("File was created\n");
                            close(socket);
                            free(events);
                            return;
                        }
                    }

                    k+= EVENT_SIZE + ievent->len;
                }
            } else if(ret < 0){
                perror("Epoll wait error");
                exit(1);
            }
        }
    }
    free(events);
}

