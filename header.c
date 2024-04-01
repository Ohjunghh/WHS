#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>

/* Ethernet header */
struct ethheader {
    u_char ether_dhost[6]; /* destination host address */
    u_char ether_shost[6]; /* source host address */
    u_short ether_type;    /* protocol type (IP, ARP, RARP, etc) */
};

/* IP Header */
struct ipheader {
    unsigned char iph_ihl : 4, //IP header length
        iph_ver : 4;            //IP version
    unsigned char iph_tos;      //Type of service
    unsigned short int iph_len; //IP Packet length (data + header)
    unsigned short int iph_ident;   //Identification
    unsigned short int iph_flag : 3, //Fragmentation flags
        iph_offset : 13;              //Flags offset
    unsigned char iph_ttl;            //Time to Live
    unsigned char iph_protocol;       //Protocol type
    unsigned short int iph_chksum;    //IP datagram checksum
    struct in_addr iph_sourceip;      //Source IP address
    struct in_addr iph_destip;        //Destination IP address
};

/* TCP Header */
struct tcpheader {
    unsigned short int tcph_srcport; // source port
    unsigned short int tcph_destport; // destination port
    unsigned int tcph_seqnum; // sequence number
    unsigned int tcph_acknum; // acknowledgement number
    unsigned char tcph_reserved : 4, tcph_offset : 4; // data offset
    unsigned char tcph_flags; // control flags
    unsigned short int tcph_win; // window
    unsigned short int tcph_chksum; // checksum
    unsigned short int tcph_urgptr; // urgent pointer
};

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    struct ethheader *eth = (struct ethheader *)packet;

    if (ntohs(eth->ether_type) == 0x0800) // 0x0800 is IP type
    {
        struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));
        unsigned int ip_header_len = ip->iph_ihl * 4;

        if (ip->iph_protocol == IPPROTO_TCP) // Check if TCP protocol
        {
            struct tcpheader *tcp = (struct tcpheader *)(packet + ip_header_len + sizeof(struct ethheader));
            if (ntohs(tcp->tcph_destport) == 8080) // Check if destination port is 8080
            {
                printf("Ethernet Header\n");
                printf("   Source MAC: %02X:%02X:%02X:%02X:%02X:%02X\n", eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2], eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
                printf("   Destination MAC: %02X:%02X:%02X:%02X:%02X:%02X\n", eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2], eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);

                printf("IP Header\n");
                printf("   Source IP: %s\n", inet_ntoa(ip->iph_sourceip));
                printf("   Destination IP: %s\n", inet_ntoa(ip->iph_destip));

                printf("TCP Header\n");
                printf("   Source Port: %u\n", ntohs(tcp->tcph_srcport));
                printf("   Destination Port: %u\n", ntohs(tcp->tcph_destport));
            }
        }
    }
}

int main()
{
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "tcp port 8080"; // Filter expression to capture TCP traffic on port 8080
    bpf_u_int32 net;

    // Open live pcap session on NIC with name eth0
    handle = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL)
    {
        fprintf(stderr, "Could not open device eth0: %s\n", errbuf);
        return 2;
    }

    // Compile filter_exp into BPF psuedo-code
    pcap_compile(handle, &fp, filter_exp, 0, net);
    if (pcap_setfilter(handle, &fp) != 0)
    {
        pcap_perror(handle, "Error:");
        exit(EXIT_FAILURE);
    }

    // Start capturing packets
    pcap_loop(handle, -1, got_packet, NULL);

    pcap_close(handle); //Close the handle
    return 0;
}