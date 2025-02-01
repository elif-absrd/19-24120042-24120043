#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <string.h>
#include <unordered_map>
#include <iostream>
#include <fstream>
#include <climits>

#define MAX_CAPTURE_PACKETS 806012

using namespace std;

unordered_map<string, int> source_ip_flow;
unordered_map<string, int> destination_ip_flow;
unordered_map<string, int> bytes_transferred;
unordered_map<string, bool> communication_pairs;

int packet_count = 0;
int total_bytes = 0;
int smallest_packet = INT_MAX;
int largest_packet = 0;
double average_packet_size = 0;
double capture_start_time = 0;
double capture_end_time = 0;

ofstream packet_log("packet_data_log.txt");

void analyze_packet(const struct pcap_pkthdr *packet_header, const u_char *packet_data) {
    struct ip *ip_header = (struct ip *)(packet_data + 14);
    struct tcphdr *tcp_header = (struct tcphdr *)(packet_data + 14 + (ip_header->ip_hl * 4));

    int packet_size = packet_header->len;
    packet_count++;
    total_bytes += packet_size;

    smallest_packet = min(smallest_packet, packet_size);
    largest_packet = max(largest_packet, packet_size);
    average_packet_size = (double)total_bytes / packet_count;

    if (packet_log.is_open()) {
        packet_log << packet_size << endl;
    }

    char source_ip[INET_ADDRSTRLEN], destination_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip_header->ip_src), source_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->ip_dst), destination_ip, INET_ADDRSTRLEN);

    int source_port = ntohs(tcp_header->th_sport);
    int destination_port = ntohs(tcp_header->th_dport);

    string source_endpoint = string(source_ip) + ":" + to_string(source_port);
    string destination_endpoint = string(destination_ip) + ":" + to_string(destination_port);
    string connection_pair = source_endpoint + " -> " + destination_endpoint;

    communication_pairs[connection_pair] = true;
    source_ip_flow[source_ip]++;
    destination_ip_flow[destination_ip]++;
    bytes_transferred[connection_pair] += packet_size;

    if (packet_count == 1) {
        capture_start_time = packet_header->ts.tv_sec + packet_header->ts.tv_usec / 1e6;
    }
    capture_end_time = packet_header->ts.tv_sec + packet_header->ts.tv_usec / 1e6;
}

void display_statistics() {
    printf("\nQuestion 1.1\n");
    printf("\nPacket Capture Results:\n");
    printf("  - Total Packets Captured from wireshark: %d\n", packet_count);
    printf("  - Total Data Transferred from wireshark: %d bytes\n", total_bytes);
    printf("  - Smallest Packet Size from wireshark: %d bytes\n", smallest_packet);
    printf("  - Largest Packet Size from wireshark: %d bytes\n", largest_packet);
    printf("  - Average Packet Size from wireshark: %.2f bytes\n", average_packet_size);

    printf("\nQuestion 1.2\n");
    printf("\nUnique Source-Destination Pairs: %lu\n", communication_pairs.size());
    for (const auto &pair : communication_pairs) {
        printf("  %s\n", pair.first.c_str());
    }

    printf("\nQuestion 1.3\n");
    printf("\nSource IP Flows:\n");
    for (const auto &entry : source_ip_flow) {
        printf("  %s: %d flows\n", entry.first.c_str(), entry.second);
    }

    printf("\nDestination IP Flows:\n");
    for (const auto &entry : destination_ip_flow) {
        printf("  %s: %d flows\n", entry.first.c_str(), entry.second);
    }

    string top_data_pair;
    int highest_transfer = 0;

    for (const auto &entry : bytes_transferred) {
        if (entry.second > highest_transfer) {
            highest_transfer = entry.second;
            top_data_pair = entry.first;
        }
    }

    printf("\nQuestion 1.4 1) With same VM \n");
    printf("\nTop Data Transferred Pair:\n");
    printf("  - Pair: %s\n", top_data_pair.c_str());
    printf("  - Data: %d bytes\n", highest_transfer);

    double capture_duration = capture_end_time - capture_start_time;
    double packets_per_second = packet_count / capture_duration;
    double megabits_per_second = (total_bytes * 8) / (capture_duration * 1e6);

    printf("\nSpeed Analysis:\n");
    printf("  - Packets Per Second (PPS): %.2f\n", packets_per_second);
    printf("  - Capture Rate: %.2f Mbps\n", megabits_per_second);

    printf("\n------------Packets capturing and analysis has completed.------------\n");
}

void start_packet_capture(const char *network_interface) {
    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_t *packet_capture_handle;

    packet_capture_handle = pcap_open_live(network_interface, BUFSIZ, 1, 1000, error_buffer);

    if (!packet_capture_handle) {
        fprintf(stderr, "Error opening interface %s: %s\n", network_interface, error_buffer);
        exit(EXIT_FAILURE);
    }

    printf("Starting packet capture on interface: %s\n", network_interface);

    while (packet_count < MAX_CAPTURE_PACKETS) {
        struct pcap_pkthdr packet_header;
        const u_char *packet_data = pcap_next(packet_capture_handle, &packet_header);
        if (!packet_data) continue;
        analyze_packet(&packet_header, packet_data);
    }

    pcap_close(packet_capture_handle);
    packet_log.close();
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <network_interface>\n", argv[0]);
        return EXIT_FAILURE;
    }

    const char *interface_name = argv[1];

    start_packet_capture(interface_name);
    display_statistics();

    return EXIT_SUCCESS;
}
