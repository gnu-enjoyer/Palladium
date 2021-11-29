#include "palladium.h"
#include <cstdio>
#include <iostream>
#include <fstream>
#include <string>
#include <windows.h>
#include <mmsystem.h>

#define SIO_RCVALL _WSAIOW(IOC_VENDOR,1)

void palladium::sniffer::build_telemetry(char *Buffer, int Size) {

    /**
     * wip
     */

    ip_hdr *iphdr = (IPV4_HDR *) Buffer;
    unsigned long cached_ip = iphdr->ip_destaddr;
    auto remote_host = gethostbyaddr((const char *) &cached_ip, sizeof(cached_ip), AF_INET);

    if (remote_host) {
        printf("%s\n ", remote_host->h_name);
        this->cached_entries.push_back(cached_ip);
    }
}

void palladium::sniffer::check_telemetry(char *Buffer, int Size) {

    ip_hdr *iphdr = (IPV4_HDR *) Buffer;

    if (this->ip_set_ptr->count(iphdr->ip_destaddr)) {
        PlaySoundA((LPCSTR) "palladium.wav", NULL, SND_FILENAME | SND_ASYNC | SND_NOSTOP);
    }


}

palladium::sniffer::sniffer() {
    if (this->load_entries() == 0) {
        this->status = -1;
        return;
    }

    iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != NO_ERROR) {
        this->status = 1;
        return;
    }
    if (gethostname(hostname, sizeof(hostname)) != SOCKET_ERROR) {

        this->localHost.sin_family = AF_INET;
        memcpy(&this->localHost.sin_addr.s_addr,
               gethostbyname(hostname)->h_addr, sizeof(this->localHost.sin_addr)
        );

    } else {
        this->status = 1;
        return;
    }

    this->socky = socket(AF_INET, SOCK_RAW, IPPROTO_IP);

    if (this->socky == INVALID_SOCKET) {
        WSACleanup();
        this->status = 2;
        return;
    }

    if (bind(this->socky, (struct sockaddr *) &this->localHost, sizeof(this->localHost)) == SOCKET_ERROR) {
        this->status = 3;
        return;
    }

    if (status == 0) {
        std::unordered_set<unsigned long> static ip_set(this->parsed_entries.begin(), this->parsed_entries.end());
        this->ip_set_ptr = &ip_set;
        this->startsniffing();
    }

}

palladium::sniffer::~sniffer() {
    switch (this->status) {
        case -1:
            printf("naughty_ips.txt not found, or could not be parsed. \n");
            break;

        case 0:
            printf("No problems mate. \n");
            break;

        case 1:
            printf("WSAStartup failed. \n");
            break;

        case 2:
            printf("Socket permission issue, try running as admin. \n");
            break;

        case 3:
            printf("WSAIoctl() failed. \n");
            break;

    }

}


int palladium::sniffer::load_entries() {
    std::string line;
    std::ifstream entries("naughty_ips.txt");
    int invalid = 0;

    if (entries.is_open()) {
        while (std::getline(entries, line)) {
           if(unsigned long addy = inet_addr(line.c_str()); addy != INADDR_NONE)
               this->parsed_entries.push_back(addy);
           else
               invalid++;
        }
        entries.close();
        if(invalid)
            printf("Invalid IP count: %d\n", invalid);

    }
    printf("Valid IP count: %d\n", this->parsed_entries.size());
    return this->parsed_entries.size();
}

void palladium::sniffer::startsniffing() {
    //(c) Silver Moon (m00n.silv3r@gmail.com)

    int j=1;
    int in;

    if (WSAIoctl(this->socky, SIO_RCVALL, &j, sizeof(j), 0, 0, (LPDWORD) &in , 0 , 0) == SOCKET_ERROR)
    {
        this->status = 2;
        return;
    }

    printf("Sniffing... \n");
    char *Buffer = (char *)malloc(65536);
    int mangobyte;

    if (Buffer == NULL)
    {
        printf("malloc() failed. \n");
        return;
    }

    do
    {
        mangobyte = recvfrom(this->socky , Buffer , 65536 , 0 , 0 , 0);

        if(mangobyte > 0)
        {
            this->check_telemetry(Buffer, mangobyte);
            //this->build_telemetry(Buffer, mangobyte);
        }
        else
        {
            printf( "recvfrom() failed. \n");
        }
    }
    while (mangobyte > 0);

    free(Buffer);

}