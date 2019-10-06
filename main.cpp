#include <netinet/if_ether.h>
#include <pcap.h>
#include <iostream>
#include <iomanip>
#include <cstring>
#include <map>
#include <thread>
#include <time.h>
#include <unistd.h>

#include "pkt.h"

using namespace std;

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
#define IEEE80211_STYPE_DATA_CFACKPOLL	0x0030
#define IEEE80211_STYPE_NULLFUNC		0x0040
#define IEEE80211_STYPE_CFACK			0x0050
#define IEEE80211_STYPE_CFPOLL			0x0060
#define IEEE80211_STYPE_CFACKPOLL		0x0070
#define IEEE80211_STYPE_QOS_DATA		0x0080
#define IEEE80211_STYPE_QOS_DATA_CFACK	0x0090
#define IEEE80211_STYPE_QOS_DATA_CFPOLL	0x00A0
#define IEEE80211_STYPE_QOS_DATA_CFACKPOLL	0x00B0
#define IEEE80211_STYPE_QOS_NULLFUNC	0x00C0
#define IEEE80211_STYPE_QOS_CFACK		0x00D0
#define IEEE80211_STYPE_QOS_CFPOLL		0x00E0
#define IEEE80211_STYPE_QOS_CFACKPOLL	0x00F0

static int cnl = 1;
static time_t st;
static time_t cu;

#pragma pack(push, 1)

struct mac_t{
    uint64_t mac:48;
} __attribute__((__packed__));

struct air_data {
    /*TODO
     * The initialized data is what needs to be implemented.
     */
    uint8_t pwr;
    int beacons;
    int sData = 0;
    int ss = 0;
    uint16_t channel;
    int mb = 0;
    char enc[5] = "WPA2";
    char cipher[6] = "CCMP";
    char auth[4] = "PSK";
    char essid[32]; //max essid length is 32bytes
};
#pragma pack(pop)

bool operator<(mac_t const& m1, mac_t const& m2){
    return m1.mac < m2.mac;
}

struct tmp_struct{
    uint8_t timestamp[12];
    uint8_t tag_n;
    uint8_t tag_len;
};

struct ieee80211_hdr {
    uint16_t frame_control;
    uint16_t duration_id;
    mac_t addr1;
    mac_t addr2;
    mac_t addr3;
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

static map<mac_t, air_data> m;

void usage() {
    cout << "syntax: airodump <interface>" << endl;
    cout << "sample: airodump wlan0" << endl;
}

static inline bool ieee80211_is_beacon(uint16_t fc)
{
    return !((fc & 0x00f0) ^ IEEE80211_STYPE_BEACON);
}

static inline bool ieee80211_is_probereq(uint16_t fc)
{
    return !((fc & 0x00f0) ^ IEEE80211_STYPE_PROBE_REQ);
}

static inline bool ieee80211_is_proberes(uint16_t fc)
{
    return !((fc & 0x00f0) ^ IEEE80211_STYPE_PROBE_RESP);
}

void pkt_checker(u_char* pkt){
    /*TODO
     * sorting by pwr
     * if/else --> switch/case
     * dealing with probe request/response
     */

    struct an_rx_radiotap_header* rad_hdr;
    rad_hdr = reinterpret_cast<struct an_rx_radiotap_header *>(pkt);
    struct ieee80211_hdr* ieee80211_header;
    //printf("%d\n", rad_hdr->ar_antsignal-0xff);
    ieee80211_header = reinterpret_cast<struct ieee80211_hdr *>(pkt + rad_hdr->ar_ihdr.it_len);
    //printf("%x\t%x\t%x\n", ieee80211_header->frame_control, ieee80211_header->frame_control & 0x00f0, (ieee80211_header->frame_control & 0x00f0) ^ 0x0080);
    //printf("channel : %d\n", (rad_hdr->ar_chan_freq-2407)/5);

    if(ieee80211_is_beacon(ieee80211_header->frame_control)) {
        struct tmp_struct* ts = reinterpret_cast<tmp_struct*>(pkt + rad_hdr->ar_ihdr.it_len + 24);

        auto it = m.find(ieee80211_header->addr3);
        if(it == m.end()){ //addr3 is not exist
            air_data ad;
            ad.channel = (rad_hdr->ar_chan_freq - 2407) / 5;
            ad.pwr = rad_hdr->ar_antsignal;
            ad.beacons = 1;
            memcpy(ad.essid, (pkt + rad_hdr->ar_ihdr.it_len + 38), ts->tag_len);
            m[ieee80211_header->addr3] = ad;
        }
        else{
            it->second.pwr = rad_hdr->ar_antsignal;
            it->second.beacons++;
        }
    }
    else if(ieee80211_is_probereq(ieee80211_header->frame_control))
        printf("probe request occurred\n");
    else if(ieee80211_is_proberes(ieee80211_header->frame_control))
        printf("probe response occurred\n");
}

void print_mac(mac_t mac) {
    for (int i = 0; i < 6; i++) {
        printf("%02X", static_cast<u_char>(mac.mac >> (i*8)));
        if (i != 5) printf(":");
    }
}

void air_print(){
    time(&cu);
    cout << endl << " CH " << cnl << " ][ Elapsed: " << cu - st << " s ][ " << ctime(&cu) << endl;
    cout << " BSSID              PWR  Beacons    #Data, #/s  CH  MB   ENC  CIPHER AUTH ESSID" << endl << endl;
    map<mac_t, air_data>::iterator it;
    for(it = m.begin(); it != m.end(); it++){
        cout << " ";
        print_mac(it->first);
        cout << setw(3) << "-"<< (int)(0xffffffff - (char)it->second.pwr)
             << setw(9) << it->second.beacons
             << setw(9) << it->second.sData
             << setw(5) << it->second.ss
             << setw(4) << it->second.channel
             << setw(5) << it->second.mb
             << setw(6) << it->second.enc
             << setw(5) << it->second.cipher
             << setw(6) << it->second.auth << "  "
             << it->second.essid
             << endl;
    }
}

void channel_hopping(char* dev){
    /*TODO
     * fix this thread
     */
    while (true) {
        char cmd[32] = "iwconfig ";
        strcat(cmd, dev);
        strcat(cmd, " channel ");
        sprintf(cmd + 23, "%d", cnl);
        system(cmd);
        sleep(1000);
        cnl += 6;
        cnl %= 13;
        if(!cnl) cnl = 13;
    }
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
    time(&st);
    thread t(channel_hopping, dev);
    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) break;

        pkt_checker(const_cast<u_char*>(packet));
        air_print();
        for(int i = 0; i < 34-static_cast<int>(m.size()); i++) cout << endl;
    }

    pcap_close(handle);
    return 0;
}
