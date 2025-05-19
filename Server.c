#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>

#define SYN_THRESHOLD 10  // Lower threshold for detecting SYN flood attacks
#define SCAN_THRESHOLD 10 // Threshold for detecting port scans
#define RESET_INTERVAL 1  // Short time interval (in seconds) to reset SYN counts

// Data structure to track SYN counts by source IP
struct syn_tracker {
    unsigned long ip;
    unsigned long syn_count;
};

struct syn_tracker syn_counters[1000]; // Array to track multiple IPs
int syn_counter_index = 0;
time_t last_reset_time = 0; // Timestamp for last reset

// Function prototypes
void handle_syn_flood_detection(unsigned long source_ip);
void handle_port_scan_detection(unsigned long source_ip, unsigned short dest_port);
int find_or_add_syn_counter(unsigned long source_ip);
void reset_syn_counts_if_needed();

int main() {
    int raw_socket;
    char packet_buffer[65536];
    struct sockaddr_in source_address;
    socklen_t source_address_len = sizeof(source_address);

    // Create a raw socket to listen for TCP packets
    raw_socket = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (raw_socket < 0) {
        perror("Error creating raw socket");
        exit(EXIT_FAILURE);
    }

    printf("Server is up and monitoring incoming packets...\n");
    last_reset_time = time(NULL); // Initialize reset timer

    while (1) {
        // Reset SYN counts periodically
        reset_syn_counts_if_needed();

        // Receive incoming packets
        int received_bytes = recvfrom(raw_socket, packet_buffer, sizeof(packet_buffer), 0, 
                                      (struct sockaddr *)&source_address, &source_address_len);
        if (received_bytes < 0) {
            perror("Error receiving packets");
            close(raw_socket);
            exit(EXIT_FAILURE);
        }

        // Parse the IP and TCP headers from the packet
        struct iphdr *ip_header = (struct iphdr *)packet_buffer;
        struct tcphdr *tcp_header = (struct tcphdr *)(packet_buffer + (ip_header->ihl * 4));

        // Display source IP and destination port
        printf("Packet received from IP: %s to Port: %d\n",
               inet_ntoa(*(struct in_addr *)&ip_header->saddr),
               ntohs(tcp_header->dest));

        // Check if the packet is a SYN packet
        if (tcp_header->syn == 1 && tcp_header->ack == 0) {
            handle_syn_flood_detection(ntohl(ip_header->saddr));
        }

        // Detect potential port scanning
        handle_port_scan_detection(ntohl(ip_header->saddr), ntohs(tcp_header->dest));
    }

    close(raw_socket);
    return 0;
}

// Function to detect SYN flood attacks based on source IP
void handle_syn_flood_detection(unsigned long source_ip) {
    int index = find_or_add_syn_counter(source_ip);
    syn_counters[index].syn_count++;

    printf("SYN packet count for IP %lu: %lu\n", source_ip, syn_counters[index].syn_count); // Debugging output

    // Check if SYN flood threshold is exceeded
    if (syn_counters[index].syn_count >= SYN_THRESHOLD) {
        printf("SYN flood attack detected from IP: %lu\n", source_ip);
        syn_counters[index].syn_count = 0; // Reset count (for demonstration purposes)
    }
}

// Function to detect port scans based on source IP and destination port
void handle_port_scan_detection(unsigned long source_ip, unsigned short dest_port) {
    static unsigned short port_scan_count = 0;

    port_scan_count++;
    printf("Port scan count for IP %lu and Port %d: %d\n", source_ip, dest_port, port_scan_count); // Debugging output

    // Check if port scan threshold is exceeded
    if (port_scan_count >= SCAN_THRESHOLD) {
        printf("Port scanning activity detected from IP: %lu on Port: %d\n", source_ip, dest_port);
        port_scan_count = 0; // Reset count (for demonstration purposes)
    }
}

// Function to find or add a SYN counter for a source IP
int find_or_add_syn_counter(unsigned long source_ip) {
    for (int i = 0; i < syn_counter_index; i++) {
        if (syn_counters[i].ip == source_ip) {
            return i;
        }
    }

    // Add new source IP if not found
    syn_counters[syn_counter_index].ip = source_ip;
    syn_counters[syn_counter_index].syn_count = 0;
    return syn_counter_index++;
}

// Function to reset SYN counts periodically
void reset_syn_counts_if_needed() {
    time_t current_time = time(NULL);
    if (difftime(current_time, last_reset_time) >= RESET_INTERVAL) {
        for (int i = 0; i < syn_counter_index; i++) {
            if (syn_counters[i].syn_count > 0) {
                printf("Resetting SYN count for IP: %lu\n", syn_counters[i].ip);
            }
            syn_counters[i].syn_count = 0;
        }
        last_reset_time = current_time;
    }
}