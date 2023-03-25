#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <pcap.h>
#include <pthread.h>

#define MAX_PACKET_SIZE 65536

void *packet_capture_thread(void *arg);
void process_packet(unsigned char *buffer, int size);

int main(int argc, char *argv[])
{
    char *device;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    struct bpf_program fp;
    bpf_u_int32 net, mask;
    pcap_if_t *devices;
    pthread_t capture_thread;
    int ret;

    if (argc < 2)
    {
        printf("Usage: %s <filter expression>\n", argv[0]);
        return 1;
    }

    ret = pcap_findalldevs(&devices, errbuf);
    if (ret == -1)
    {
        printf("Error finding devices: %s\n", errbuf);
        return 1;
    }

    device = devices->name;

    if (pcap_lookupnet(device, &net, &mask, errbuf) == -1)
    {
        printf("Error getting network address: %s\n", errbuf);
        pcap_freealldevs(devices);
        return 1;
    }

    handle = pcap_open_live(device, MAX_PACKET_SIZE, 1, 1000, errbuf);
    if (handle == NULL)
    {
        printf("Error opening device: %s\n", errbuf);
        pcap_freealldevs(devices);
        return 1;
    }

    if (pcap_compile(handle, &fp, argv[1], 0, net) == -1)
    {
        printf("Error compiling filter expression: %s\n", pcap_geterr(handle));
        pcap_freealldevs(devices);
        pcap_close(handle);
        return 1;
    }

    if (pcap_setfilter(handle, &fp) == -1)
    {
        printf("Error setting filter: %s\n", pcap_geterr(handle));
        pcap_freecode(&fp);
        pcap_freealldevs(devices);
        pcap_close(handle);
        return 1;
    }

    if (pthread_create(&capture_thread, NULL, packet_capture_thread, handle) != 0)
    {
        printf("Error creating capture thread: %s\n", strerror(errno));
        pcap_freecode(&fp);
        pcap_freealldevs(devices);
        pcap_close(handle);
        return 1;
    }

    pthread_join(capture_thread, NULL);
    pcap_freecode(&fp);
    pcap_freealldevs(devices);
    pcap_close(handle);

    return 0;
}

void *packet_capture_thread(void *arg)
{
    pcap_t *handle = (pcap_t *)arg;
    struct pcap_pkthdr header;
    const unsigned char *packet;

    while (1)
    {
        packet = pcap_next(handle, &header);
        if (packet != NULL)
        {
            process_packet((unsigned char *)packet, header.len);
        }
    }

    return NULL;
}

void process_packet(unsigned char *buffer, int size)
{
    struct iphdr *iph = (struct iphdr *)buffer;
    if (iph->protocol == IPPROTO_TCP)
    {
        struct tcphdr *tcph = (struct tcphdr *)(buffer + sizeof(struct iphdr));
        printf("Source IP: %s\n", inet_ntoa(*(struct in_addr *)&iph->saddr));
        printf("Destination IP: %s\n", inet_ntoa(*(struct in_addr *)&iph->daddr));
        printf("Source Port: %d\n", ntohs(tcph->source));
        printf("Destination Port: %d\n", ntohs(tcph->dest));
        printf("Data: %s\n", buffer + sizeof(struct iphdr) + sizeof(struct tcphdr));
        printf("\n");
    }
}