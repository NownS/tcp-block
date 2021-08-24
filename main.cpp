#include <libnet.h>
#include <pcap.h>
#include <string>
#include <string.h>
#include <list>
#include <vector>
#include <functional>
#include <stdio.h>
#include "mac.h"
#include "ip.h"
#include "strnstr.h"

#pragma pack(push, 1)

struct EthIpTcp{
    libnet_ethernet_hdr eth_;
    libnet_ipv4_hdr ip_;
    libnet_tcp_hdr tcp_;
};

struct EthIpTcpPayload{
    EthIpTcp header_;
    uint8_t payload_[100] = {0};
};

struct Pseudohdr{
    in_addr sip_;
    in_addr dip_;
    uint8_t reserved_;
    uint8_t protocol_;
    uint16_t tcplen_;
};

struct PseudoTcpData{
    Pseudohdr pseudo_;
    libnet_tcp_hdr tcp_;
    uint8_t data_[100] = {0};
};

#pragma pack(pop)

Mac getMyMac(char *interfaceName){
    char fileName[100] = "/sys/class/net/";
    if(sizeof(interfaceName) > 80){
        fprintf(stderr, "interface name is too long\n");
        return Mac::nullMac();
    }
    strcat(fileName, interfaceName);
    strncat(fileName, "/address", 9);
    FILE *my_net_file = fopen(fileName, "rt");
    char addr[18];
    int ret = fscanf(my_net_file, "%s", addr);
    if(ret == EOF){
        fprintf(stderr, "cannot find address file");
        return Mac::nullMac();
    }
    return Mac(addr);
}

bool isContainPattern(uint8_t *data, const char *str, unsigned int dataLength){
    /*
    std::list<std::string> methodList{"GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH"};
    std::list<std::string>::iterator it;
    bool isMethod = false;
    for(it = methodList.begin();it != methodList.end();it++){
        if (strncmp((char *)data, it->c_str(), sizeof(it->c_str())) == 0){
            isMethod = true;
            break;
        }
    if(!isMethod) return false;
    */

    char *match = strnstr((char *)data, str, dataLength);
    if(match == NULL) return false;
    return true;

}

uint16_t Checksum(uint16_t *buffer, int size){
    unsigned long cksum=0;

    while(size >1) {
        cksum+=*buffer++;
        size -=sizeof(unsigned short);
    }

    if(size)
        cksum += *(unsigned short*)buffer;
    cksum = (cksum >> 16) + (cksum & 0xffff);
    cksum += (cksum >>16);
    return (unsigned short)(~cksum);
}


void sendForward(pcap_t *handle, Mac myMac, libnet_ethernet_hdr *eth, libnet_ipv4_hdr *ip, libnet_tcp_hdr *tcp){
    EthIpTcp headers;
    memcpy(headers.eth_.ether_dhost, eth->ether_dhost, sizeof(Mac));
    memcpy(headers.eth_.ether_shost, (uint8_t *)myMac, sizeof(Mac));
    headers.eth_.ether_type = eth->ether_type;

    memcpy(&(headers.ip_), ip, sizeof(*ip));

    headers.tcp_.th_sport = tcp->th_sport;
    headers.tcp_.th_dport = tcp->th_dport;
    headers.tcp_.th_seq = htonl(ntohl(tcp->th_seq) + ntohs(ip->ip_len) - (ip->ip_hl + tcp->th_off) * 4);
    headers.tcp_.th_ack = tcp->th_ack;
    headers.tcp_.th_off = tcp->th_off;
    headers.tcp_.th_flags = 0b00000100;

    Pseudohdr pseudo;
    pseudo.dip_ = headers.ip_.ip_dst;
    pseudo.sip_ = headers.ip_.ip_src;
    pseudo.protocol_ = headers.ip_.ip_p;
    pseudo.reserved_ = 0;
    pseudo.tcplen_ = (uint8_t)(sizeof(*tcp)/4);

    uint16_t *buffer = reinterpret_cast<uint16_t*>(&pseudo);
    headers.tcp_.th_sum = Checksum(buffer, sizeof(Pseudohdr));

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&headers), sizeof(EthIpTcp));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }
}

void sendBackward(pcap_t *handle, Mac myMac, libnet_ethernet_hdr *eth, libnet_ipv4_hdr *ip, libnet_tcp_hdr *tcp){
    EthIpTcp headers;
    uint8_t tcpData[] = "HTTP/1.0 302 Redirect\r\nLocation: http://warning.or.kr\r\n";

    memcpy(headers.eth_.ether_dhost, eth->ether_shost, sizeof(Mac));
    memcpy(headers.eth_.ether_shost, (uint8_t *)myMac, sizeof(Mac));
    headers.eth_.ether_type = eth->ether_type;

    memcpy(&(headers.ip_), ip, sizeof(*ip));
    headers.ip_.ip_dst = ip->ip_src;
    headers.ip_.ip_src = ip->ip_dst;
    headers.ip_.ip_ttl = 128;
    headers.ip_.ip_len = htons(sizeof(*ip) + sizeof(*tcp) + sizeof(tcpData));

    uint16_t *buffer = reinterpret_cast<uint16_t*>(&(headers.ip_));
    buffer[5] = 0x0000;
    headers.ip_.ip_sum = Checksum(buffer, sizeof(libnet_ipv4_hdr));

    headers.tcp_.th_sport = tcp->th_dport;
    headers.tcp_.th_dport = tcp->th_sport;
    headers.tcp_.th_seq = tcp->th_ack;
    headers.tcp_.th_ack = tcp->th_seq;
    headers.tcp_.th_off = (uint8_t)(sizeof(*tcp)/4);
    headers.tcp_.th_flags = 0b00011001;
    headers.tcp_.th_sum = 0;
    headers.tcp_.th_urp = 0;
    headers.tcp_.th_x2 = 0;
    headers.tcp_.th_win = tcp->th_win;

    Pseudohdr pseudo;
    pseudo.dip_ = headers.ip_.ip_dst;
    pseudo.sip_ = headers.ip_.ip_src;
    pseudo.reserved_ = 0;
    pseudo.protocol_ = headers.ip_.ip_p;
    pseudo.tcplen_ = htons(headers.tcp_.th_off * 4 + sizeof(tcpData));

    PseudoTcpData pseuTcp;
    pseuTcp.pseudo_ = pseudo;
    pseuTcp.tcp_ = headers.tcp_;
    memcpy(pseuTcp.data_, tcpData, sizeof(tcpData));

    buffer = reinterpret_cast<uint16_t*>(&pseuTcp);
    headers.tcp_.th_sum = Checksum(buffer, sizeof(Pseudohdr) + sizeof(pseuTcp.tcp_) + sizeof(tcpData));

    EthIpTcpPayload packet;
    packet.header_ = headers;
    memcpy(packet.payload_, tcpData, sizeof(tcpData));
    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthIpTcpPayload));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }
}

void usage() {
    printf("syntax: arp-spoof <interface> <pattern>\n");
    printf("sample : arp-spoof wlan0 \"Host: test.gilgil.net\"\n");
}

int main(int argc, char *argv[])
{
    if (argc != 3) {
        usage();
        return -1;
    }

    char *dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }

    Mac myMac = getMyMac(argv[1]);

    libnet_ethernet_hdr *PEthernetHdr;
    libnet_ipv4_hdr *PIpHdr;
    libnet_tcp_hdr *PTcpHdr;
    uint8_t *PtcpData;

    while(1){
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }

        PEthernetHdr = (libnet_ethernet_hdr *)packet;
        uint16_t type = ntohs(PEthernetHdr->ether_type);
        if(type != 0x0800){
            continue;
        }
        packet += sizeof(*PEthernetHdr);
        PIpHdr = (libnet_ipv4_hdr *)packet;
        if(PIpHdr->ip_p != 0x06){
            continue;
        }
        packet += PIpHdr->ip_hl * 4;
        PTcpHdr = (libnet_tcp_hdr *)packet;
        if(ntohs(PTcpHdr->th_dport) != 80){
            continue;
        }
        packet += PTcpHdr->th_off * 4;
        PtcpData = (uint8_t *)packet;
        unsigned int length = ntohs(PIpHdr->ip_len) - (PIpHdr->ip_hl * 4 + PTcpHdr->th_off * 4);

        if(isContainPattern(PtcpData, argv[2], length)){
            printf("match!\n");
            sendForward(handle, myMac, PEthernetHdr, PIpHdr, PTcpHdr);
            sendBackward(handle, myMac, PEthernetHdr, PIpHdr, PTcpHdr);
        }
    }
    return 0;
}
