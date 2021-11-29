#ifndef PALLADIUM_PALLADIUM_H
#define PALLADIUM_PALLADIUM_H

#include <Winsock2.h>
#include <vector>
#include <unordered_set>


namespace palladium {

    typedef struct ip_hdr {
        unsigned char ip_header_len: 4;
        unsigned char ip_version: 4;
        unsigned char ip_tos;
        unsigned short ip_total_length;
        unsigned short ip_id;

        unsigned char ip_frag_offset: 5;

        unsigned char ip_more_fragment: 1;
        unsigned char ip_dont_fragment: 1;
        unsigned char ip_reserved_zero: 1;

        unsigned char ip_frag_offset1;

        unsigned char ip_ttl;
        unsigned char ip_protocol;
        unsigned short ip_checksum;
        unsigned int ip_srcaddr;
        unsigned int ip_destaddr;
    } IPV4_HDR;

    class sniffer {

        int status = 0;
        WSADATA wsaData;
        int iResult;
        char hostname[100];
        SOCKET socky = INVALID_SOCKET;
        struct sockaddr_in localHost;
        std::unordered_set<unsigned long> *ip_set_ptr;
        std::vector<unsigned long> parsed_entries;
        std::vector<unsigned long> cached_entries;

        int load_entries();

        void startsniffing();

        void check_telemetry(char *Buffer, int Size);

        void build_telemetry(char *Buffer, int Size); //wip


    public:

        sniffer();

        ~sniffer();

    };

}


#endif //PALLADIUM_PALLADIUM_H