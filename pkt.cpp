#include "pkt.h"

Pkt::Pkt(const u_char *_pkt){
    this->pkt = const_cast<u_char *>(_pkt);
    this->ethhdr = reinterpret_cast<struct libnet_ethernet_hdr*>(pkt);
}

Pkt::~Pkt(){

}

bool Pkt::isIp(){
    if(ntohs(ethhdr->ether_type) == ETHERTYPE_IP) {
        this->iphdr = reinterpret_cast<struct libnet_ipv4_hdr*>(pkt + ETH_HDR_LEN);
        return true;
    }
    return false;
}

bool Pkt::isTcp(){
    if(isIp()){
        if(iphdr->ip_p == IPPROTO_TCP){
            this->tcphdr = reinterpret_cast<struct libnet_tcp_hdr *>(reinterpret_cast<uint64_t>(iphdr) + 4*(iphdr->ip_hl));
            return true;
        }
    }
    return false;
}

bool Pkt::isHttp(){
    if(isTcp()){
        if(ntohs(tcphdr->th_dport) == TCP_PORT_HTTP || ntohs(tcphdr->th_sport) == TCP_PORT_HTTP){
            return true;
        }
    }
    return false;
}

void Pkt::printMac(uint8_t* mac) {
    int i;
    for (i=0;i<6;i++){
        printf("%02x", mac[i]);
        if (i != 5) printf(":");
        if (i == 5) printf("\n");
    }
}

void Pkt::printIp(struct in_addr *ip){
    char buf[16]={0,};
    inet_ntop(AF_INET, ip, buf, sizeof(buf));
    printf("%s\n", buf);
}

void Pkt::printTcp(uint16_t tcp){
    printf("%d\n", ntohs(tcp));
}

void Pkt::printTcpData(){
    int len = ntohs(iphdr->ip_len)-(iphdr->ip_hl*4)-(tcphdr->th_off*4);
    u_char* data = reinterpret_cast<u_char*>(reinterpret_cast<uint64_t>(tcphdr)+(tcphdr->th_off)*4);
    printf("http data: ");
    if(len < 16) printf("%.*s\n", len, data);
    else printf("%.*s\n", 16, data);
}
