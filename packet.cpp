//
//  packet.cpp
//  data_encapsulation
//
//  Created by Tangrizzly on 2018/4/13.
//  Copyright © 2018 Tangrizzly. All rights reserved.
//

#include "packet.hpp"
#include <stdlib.h>
#include<libnet.h>
void Packet::findalldevs() {
    pcap_if_t *_alldevs, *d;
    int i=0;
    char errbuf[PCAP_ERRBUF_SIZE];
    if (pcap_findalldevs(&_alldevs, errbuf) == -1) {
        fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
        pcap_freealldevs(alldevs);
        return ;
    }
    r=_alldevs;
    for (d = _alldevs; d; d = d->next)
        i++;
      //  printf("\t%d. %s", ++i, d->name);
      //  if (d->description){
           // pass;
      //     printf(" (%s)\n", d->description);
      //  }
      //  else {
      //      pass;
      //      printf(" (No description available)\n");
    //    }
  //  }
    if (i==0) {
        printf("\nNo interfaces found! \n");
        return  ;
    }
     pcap_freealldevs(alldevs);
    alldevs = _alldevs;

}

void Packet::choosedev(int num) {
    //printf("Please select a dev by inputting the number of the dev: ");
    //int num;
    pcap_if_t *d = alldevs;
    //scanf("%d", &num);
    for (int j = 1; j < num; j++) {
        d = d->next;
    }
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *_adhandle = pcap_open_live(d->name,  // device name
                                       65535,    // snaplen
                                       1,        // promisc
                                       1000,     // to_ms
                                       errbuf);  // *ebuf
    if (_adhandle == NULL) {
        fprintf(stderr,"Error in pcap_open_live: %s\n", errbuf);
        pcap_freealldevs(alldevs);
        exit(1);
    }
    dev = d;
    adhandle = _adhandle;
}

void packet_handler(u_char* user, const struct pcap_pkthdr* pkt_header, const u_char* pkt_data) {
    struct tm *ltime;
     char timestr[16];
     u_char timestr1[16];
     //u_char test='w';
     //*user=test;
     //user =timestr1;
    time_t local_tv_sec;
    local_tv_sec = pkt_header->ts.tv_sec;
    ltime=localtime(&local_tv_sec);
    strftime( timestr, sizeof timestr, "%H:%M:%S", ltime);
    int i;
    for(i=0;i<16;i++){
          timestr1[i]=(unsigned char)timestr[i];
    }
    int jj;
    //jjj[0]=pkt_header->ts.tv_usec;
    //printf("\n%d\n",jjj[0]);
    for(jj=0;jj<16;jj++)
    {
        user[jj]=(unsigned char)timestr[jj];
    }
    int kk=pkt_header->ts.tv_usec;
    for (jj=21;jj>15;jj--)
    {
       user[jj]= (unsigned char)('0'+kk%10);
       kk=kk/10;
    }
    kk=pkt_header->len;
    for (jj=26;jj>22;jj--)
    {
        user[jj]=(unsigned char)('0'+kk%10);
        kk=kk/10;
    }


    //printf("%s.%.6d len:%d ", timestr, pkt_header->ts.tv_usec, pkt_header->len);

    Ether_header ethhdr;

    ethhdr = *(Ether_header*)(pkt_data);

   unsigned short bb= ntohs(ethhdr.ether_type);
    kk=(bb%10);
    user[31]='0'+kk;
    kk=((bb/10)%10);
    user[30]='0'+kk;
    kk=((bb/100)%10);
    user[29]='0'+kk;
    kk=((bb/1000)%10);
    user[28]='0'+kk;



    switch (ntohs(ethhdr.ether_type)) {
        case ETH_ARP:
            Arp_header arphdr;
            arphdr = *(Arp_header*)(pkt_data + 14);
            arphdr.arp_parse(user);
            break;
        case ETH_IP:
            Ipv4_header ipv4hdr;
            ipv4hdr = *(Ipv4_header*)(pkt_data + 14);
            ipv4hdr.ipv4_parse(pkt_data,user);
            break;
        default:
            break;
    }
    printf("\n");
}

Packet Packet::capturePacket(int num, char filter[],Packet w) {
    pcap_loop(adhandle, num,packet_handler,w.c);
   //printf("%c",*w.c);
    return w;
}

void Packet::filter(char filter[]) {
    u_int netmask, netip;
    char errbuf[PCAP_ERRBUF_SIZE];
    char* packet_filter = filter;
    struct bpf_program fcode;
    if (dev->addresses != NULL) {
        if (pcap_lookupnet(dev->name, &netip, &netmask, errbuf) == -1) {
            fprintf(stderr,"Error in pcap_lookupnet: %s\n", errbuf);
            pcap_freealldevs(alldevs);
            exit(1);
        }
    }
    else {
        netmask=0xffffff;
    }
    if (pcap_compile(adhandle, &fcode, packet_filter, 0, netmask) < 0) {
        fprintf(stderr,"\nUnable to compile the filter. Check the syntax.\n");
        pcap_freealldevs(alldevs);
        exit(-1);
    }
    if (pcap_setfilter(adhandle, &fcode)<0) {
        fprintf(stderr,"\nError setting the filter.\n");
        pcap_freealldevs(alldevs);
        exit(-1);
    }
}

int Packet::send_single(//char *src_ip_str,
                         //char *dst_ip_str,
                         //u_int8_t src_mac[6]
                        Dialog * dialog1
                        ) {

    libnet_t *handle;        /* Libnet句柄 */
    int packet_size;
    char *device = this->dev->name;   /* 设备名字,也支持点十进制的IP地址,会自己找>到匹配的设备 */
    char *src_ip_str=dialog1->src_ip_str;
    //char *src_ip_str = "192.168.128.200";       /* 源IP地址字符串 */
    //u_int8_t
    char *dst_ip_str=dialog1->dst_ip_str;
    //char *dst_ip_str = "192.168.128.88";        /* 目的IP地址字符串 */
   // u_int8_t src_mac[6] = {0x33, 0x17, 0xeb, 0x8d, 0xcf, 0xbf};/* 源MAC */
    //u_int8_t *src_mac=dialog1->src_mac;
    u_int8_t dst_mac[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};/* 目的MAC,>广播地址 */
    /* 接收方MAC,ARP请求目的就是要询问对方MAC,所以这里填写0 */
    u_int8_t rev_mac[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    u_int32_t dst_ip, src_ip;              /* 网路序的目的IP和源IP */
    char error[LIBNET_ERRBUF_SIZE];        /* 出错信息 */
    libnet_ptag_t arp_proto_tag, eth_proto_tag;

    /* 把目的IP地址字符串转化成网络序 */
    dst_ip = libnet_name2addr4(handle, dst_ip_str, LIBNET_RESOLVE);
    /* 把源IP地址字符串转化成网络序 */
    src_ip = libnet_name2addr4(handle, src_ip_str, LIBNET_RESOLVE);

    if ( dst_ip == -1 || src_ip == -1 ) {
        printf("ip address convert error\n");
        exit(-1);
    };
    /* 初始化Libnet,注意第一个参数和TCP初始化不同 */
    if ( (handle = libnet_init(LIBNET_LINK_ADV, device, error)) == NULL ) {
        printf("libnet_init: error [%s]\n", error);
        exit(-2);
    };
    arp_proto_tag = libnet_build_arp(
                ARPHRD_ETHER,        /* 硬件类型,1表示以太网硬件地址 */
                ETHERTYPE_IP,        /* 0x0800表示询问IP地址 */
                6,                   /* 硬件地址长度 */
                4,                   /* IP地址长度 */
                ARPOP_REQUEST,       /* 操作方式:ARP请求 */
                dialog1->src_mac,             /* source MAC addr */
                (u_int8_t *)&src_ip, /* src proto addr */
                rev_mac,             /* dst MAC addr */
                (u_int8_t *)&dst_ip, /* dst IP addr */
                NULL,                /* no payload */
                0,                   /* payload length */
                handle,              /* libnet tag */
                0                    /* Create new one */
    );
    if (arp_proto_tag == -1)    {
        printf("build IP failure\n");
        exit(-3);
    };

    /* 构造一个以太网协议块
    You should only use this function when
    libnet is initialized with the LIBNET_LINK interface.*/
    eth_proto_tag = libnet_build_ethernet(
        dst_mac,         /* 以太网目的地址 */
        dialog1->src_mac,         /* 以太网源地址 */
        ETHERTYPE_ARP,   /* 以太网上层协议类型，此时为ARP请求 */
        NULL,            /* 负载，这里为空 */
        0,               /* 负载大小 */
        handle,          /* Libnet句柄 */
        0                /* 协议块标记，0表示构造一个新的 */
    );
    if (eth_proto_tag == -1) {
        printf("build eth_header failure\n");
        return (-4);
    };

    packet_size = libnet_write(handle);    /* 发送已经构造的数据包*/

    libnet_destroy(handle);                /* 释放句柄 */
    return 0;








    /*bool loop = true;
    printf("1111\n");
    u_char* packet;

        printf("Please input the packet length of the data you would like to send or type \"*\" to send the default packet: ");
      //  scanf("%s", length);
        if (length[0] == '*') {
            packet = new u_char[100];
            for (int i = 0; i < 100; i++) {
                if (i < 6) {
                    packet[i] = 1;
                } else if (i < 12) {
                    packet[i] = 2;
                } else {
                    packet[i] = i % 256;
                }
            }
            if (pcap_sendpacket(adhandle, packet, 100) != 0) {
                fprintf(stderr, "\nError sending the packet: %s\n", pcap_geterr(adhandle));
            }
            else
            {
                printf("\nsend sucess");
            }
        } else {
            int len = atoi(length);
            if (len > MAXLENGTH) {
                printf("Wrong length.\n");
            } else {
                int flag = 0;
                packet = new u_char[len];
                u_char tmp = 0;
                char ch;
                while((ch=getchar())!='\n'&&ch!=EOF);
                printf("Please input data: ");
                int i;
                for (i = 0; i < len*2; i++) {
                    char w;
                    scanf("%c", &w);
                    if (('0' <= w && w <= '9') || ('a' <= w && w <= 'f') || w == '\n' || w == ' ') {
                        if (i%2 == 0) {
                            if ('0' <= w && w <= '9') {
                                tmp = w - '0';
                            } else if ('a' <= w && w <= 'f') {
                                tmp = 10 + w - 'a';
                            } else {
                                i--;
                            }
                        } else {
                            packet[i/2] = tmp * 16 + w - '0';
                        }
                    } else {
                        printf("Wrong data.\n");
                        flag = 1;
                        break;
                    }
                }

                if (pcap_sendpacket(adhandle, packet, len) != 0) {
                    fprintf(stderr, "Error sending the packet: %s\n", pcap_geterr(adhandle));
                }
            }
        }
        char ch;
        //while((ch=getchar())!='\n'&&ch!=EOF);
       // printf("Sending one packet more? (please input 1/0) ");*/


}
int Packet::send_single_tcp(
        //char *src_ip_str,
          //      char *dst_ip_str,
            //    u_int8_t src_mac[6]
        Dialog * dialog1
        ){



    libnet_t *handle; /* Libnet句柄 */
    int packet_size; /* 构造的数据包大小 */
    char *device =this->dev->name; /* 设备名字,也支持点十进制的IP地址,会自己找到匹配的设备 */
    char *src_ip_str =dialog1->src_ip_str;// "192.168.2.148"; /* 源IP地址字符串 */
    char *dst_ip_str =dialog1->dst_ip_str;// "192.168.2.170"; /* 目的IP地址字符串 */
    //u_char src_mac[6] = {0x00, 0x0c, 0x29, 0xba, 0xee, 0xdd}; /* 源MAC */
    u_char dst_mac[6] = {0x00, 0x0c, 0x29, 0x6d, 0x4d, 0x5c}; /* 目的MAC */
    u_long dst_ip, src_ip; /* 网路序的目的IP和源IP */
    char error[LIBNET_ERRBUF_SIZE]; /* 出错信息 */
    libnet_ptag_t eth_tag, ip_tag, tcp_tag, tcp_op_tag; /* 各层build函数返回值 */
    u_short proto = IPPROTO_TCP; /* 传输层协议 */
    u_char payload[255] = {0}; /* 承载数据的数组，初值为空 */
    u_long payload_s = 0; /* 承载数据的长度，初值为0 */

    /* 把目的IP地址字符串转化成网络序 */
    dst_ip = libnet_name2addr4(handle, dst_ip_str, LIBNET_RESOLVE);
    /* 把源IP地址字符串转化成网络序 */
    src_ip = libnet_name2addr4(handle, src_ip_str, LIBNET_RESOLVE);

    /* 初始化Libnet */
    if ( (handle = libnet_init(LIBNET_LINK, device, error)) == NULL ) {
        printf("libnet_init failure\n");
        return (-1);
    };

    strncpy((char *)payload, "test", sizeof(payload)-1); /* 构造负载的内容 */
    payload_s = strlen((const char*)payload); /* 计算负载内容的长度 */

#if 0
    /* 构建TCP的选项,通常在第一个TCP通信报文中设置MSS */
    tcp_op_tag = libnet_build_tcp_options(
                payload,
                payload_s,
                handle,
                0
    );
    if (tcp_op_tag == -1) {
        printf("build_tcp_options failure\n");
        return (-2);
           };
       #endif

           tcp_tag = libnet_build_tcp(
                       dialog1->src_port,                    /* 源端口 */
                       dialog1->des_port,                    /* 目的端口 */
                       dialog1->serial_num,                    /* 序列号 */
                       dialog1->con_num,                    /* 确认号 */
                       TH_PUSH | TH_ACK,        /* Control flags */
                       14600,                    /* 窗口尺寸 */
                       0,                        /* 校验和,0为自动计算 */
                       0,                        /* 紧急指针 */
                       LIBNET_TCP_H + payload_s, /* 长度 */
                       payload,                    /* 负载内容 */
                       payload_s,                /* 负载内容长度 */
                       handle,                    /* libnet句柄 */
                       0                        /* 新建包 */
           );
           if (tcp_tag == -1) {
               printf("libnet_build_tcp failure\n");
               return (-3);
           };

           /* 构造IP协议块，返回值是新生成的IP协议快的一个标记 */
           ip_tag = libnet_build_ipv4(
               LIBNET_IPV4_H + LIBNET_TCP_H + payload_s, /* IP协议块的总长,*/
               0, /* tos */
               (u_short) libnet_get_prand(LIBNET_PRu16), /* id,随机产生0~65535 */
               0, /* frag 片偏移 */
               (u_int8_t)libnet_get_prand(LIBNET_PR8), /* ttl,随机产生0~255 */
               proto, /* 上层协议 */
               0, /* 校验和，此时为0，表示由Libnet自动计算 */
               src_ip, /* 源IP地址,网络序 */
               dst_ip, /* 目标IP地址,网络序 */
               NULL, /* 负载内容或为NULL */
               0, /* 负载内容的大小*/
               handle, /* Libnet句柄 */
               0 /* 协议块标记可修改或创建,0表示构造一个新的*/
           );
           if (ip_tag == -1) {
                 printf("libnet_build_ipv4 failure\n");
                 return (-4);
             };

             /* 构造一个以太网协议块,只能用于LIBNET_LINK */
             eth_tag = libnet_build_ethernet(
                 dst_mac, /* 以太网目的地址 */
                 dialog1->src_mac, /* 以太网源地址 */
                 ETHERTYPE_IP, /* 以太网上层协议类型，此时为IP类型 */
                 NULL, /* 负载，这里为空 */
                 0, /* 负载大小 */
                 handle, /* Libnet句柄 */
                 0 /* 协议块标记，0表示构造一个新的 */
             );
             if (eth_tag == -1) {
                 printf("libnet_build_ethernet failure\n");
                 return (-5);
             };

             packet_size = libnet_write(handle); /* 发送已经构造的数据包*/

             libnet_destroy(handle); /* 释放句柄 */

             return (0);
         }



