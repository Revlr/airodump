#include <netinet/if_ether.h>
#include <pcap.h>
#include <stdio.h>

#include "pkt.h"

#define IEEE80211_STYPE_ASSOC_REQ       0x0000
#define IEEE80211_STYPE_ASSOC_RESP      0x0010
#define IEEE80211_STYPE_REASSOC_REQ     0x0020
#define IEEE80211_STYPE_REASSOC_RESP	0x0030
#define IEEE80211_STYPE_PROBE_REQ       0x0040
#define IEEE80211_STYPE_PROBE_RESP      0x0050
#define IEEE80211_STYPE_BEACON          0x0080  // 0000 0000 1000 0000
#define IEEE80211_STYPE_ATIM            0x0090
#define IEEE80211_STYPE_DISASSOC        0x00A0
#define IEEE80211_STYPE_AUTH            0x00B0
#define IEEE80211_STYPE_DEAUTH          0x00C0
#define IEEE80211_STYPE_ACTION          0x00D0

#define IEEE80211_STYPE_DATA			0x0000
#define IEEE80211_STYPE_DATA_CFACK		0x0010
#define IEEE80211_STYPE_DATA_CFPOLL		0x0020
#define IEEE80211_STYPE_DATA_CFACKPOLL		0x0030
#define IEEE80211_STYPE_NULLFUNC		0x0040
#define IEEE80211_STYPE_CFACK			0x0050
#define IEEE80211_STYPE_CFPOLL			0x0060
#define IEEE80211_STYPE_CFACKPOLL		0x0070
#define IEEE80211_STYPE_QOS_DATA		0x0080
#define IEEE80211_STYPE_QOS_DATA_CFACK		0x0090
#define IEEE80211_STYPE_QOS_DATA_CFPOLL		0x00A0
#define IEEE80211_STYPE_QOS_DATA_CFACKPOLL	0x00B0
#define IEEE80211_STYPE_QOS_NULLFUNC		0x00C0
#define IEEE80211_STYPE_QOS_CFACK		0x00D0
#define IEEE80211_STYPE_QOS_CFPOLL		0x00E0
#define IEEE80211_STYPE_QOS_CFACKPOLL		0x00F0

struct ieee80211_hdr {
    uint16_t frame_control;
    uint16_t duration_id;
    uint8_t addr1[ETH_ALEN];
    uint8_t addr2[ETH_ALEN];
    uint8_t addr3[ETH_ALEN];
    uint16_t seq_ctrl;
};

struct ieee80211_radiotap_header {
        u_int8_t        it_version;     /* set to 0 */
        u_int8_t        it_pad;
        u_int16_t       it_len;         /* entire length */
        u_int64_t       it_present;     /* fields present */
} __attribute__((__packed__));

struct an_rx_radiotap_header {
        struct ieee80211_radiotap_header        ar_ihdr;
        u_int8_t        ar_flags;
        u_int8_t        ar_rate;
        u_int16_t       ar_chan_freq;
        u_int16_t       ar_chan_flags;
        u_int8_t        ar_antsignal;
        u_int8_t        ar_antnoise;
} __attribute__((__packed__));

void usage() {
    printf("syntax: airodump <interface>\n");
    printf("sample: airodump wlan0\n");
}

static inline bool ieee80211_is_beacon(uint16_t fc)
{
    return ((fc & 0x00f0) ^ IEEE80211_STYPE_BEACON);
}

static inline bool ieee80211_is_probereq(uint16_t fc)
{
    return ((fc & 0x00f0) ^ IEEE80211_STYPE_PROBE_REQ);
}

static inline bool ieee80211_is_proberes(uint16_t fc)
{
    return ((fc & 0x00f0) ^ IEEE80211_STYPE_PROBE_RESP);
}

void pkt_print(u_char* pkt){
    struct an_rx_radiotap_header* rad_hdr;
    rad_hdr = reinterpret_cast<struct an_rx_radiotap_header *>(pkt);
    struct ieee80211_hdr* ieee80211_header;
    printf("%d\n", rad_hdr->ar_antsignal-0xff);
    ieee80211_header = reinterpret_cast<struct ieee80211_hdr *>(pkt + rad_hdr->ar_ihdr.it_len);
    //printf("%x\t%x\t%x\n", ieee80211_header->frame_control, ieee80211_header->frame_control & 0x00f0, (ieee80211_header->frame_control & 0x00f0) ^ 0x0080);
    if(!ieee80211_is_beacon(ieee80211_header->frame_control))
        printf("beacon frame occurred\n");
    else if(!ieee80211_is_probereq(ieee80211_header->frame_control))
        printf("probe request occurred\n");
    else if(!ieee80211_is_proberes(ieee80211_header->frame_control))
        printf("probe response occurred\n");
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return -1;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
        return -1;
    }

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) break;
        pkt_print(const_cast<u_char*>(packet));
    }

    pcap_close(handle);
    return 0;
}
