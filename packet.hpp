//
//  packet.h
//  data_encapsulation
//
//  Created by Tangrizzly on 2018/4/13.
//  Copyright © 2018 Tangrizzly. All rights reserved.
//

#ifndef packet_hpp
#define packet_hpp

#include "header.hpp"






void packet_handler(u_char* user, const struct pcap_pkthdr* pkt_header, const u_char* pkt_data);


class Packet {
private:
    pcap_if_t* alldevs, *dev;
    pcap_t* adhandle;
public:
    pcap_if_t* r;
    u_char * c;
    void findalldevs();
    void choosedev(int );
    Packet capturePacket(int num, char filter[],Packet w);
    void filter(char filter[]);
    int send_single(
            //char *src_ip_str,
              //      char *dst_ip_str,
                //    u_int8_t src_mac[6]
            Dialog *
            );
    int send_single_tcp(
            //char *src_ip_str,
              //      char *dst_ip_str,
                //    u_int8_t src_mac[6]
            Dialog *
            );
};

#endif /* packet_h */
