#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include "forward.h"
#include "common.h"

#pragma comment(lib, "ws2_32.lib")

// 将 IP 地址转换为字符串 (函数定义不变)
char *ip_to_str(unsigned int ip) {
    struct in_addr addr;
    addr.s_addr = ip;
    return inet_ntoa(addr);
}

// 查找路由 (函数定义不变)
RouteEntry *find_route(RouteEntry *head, unsigned int dest_ip) {
    RouteEntry *current = head->next;
    RouteEntry *best_match = NULL;
    while (current != NULL) {
        if ((dest_ip & current->subnet_mask) == current->destination_ip) {
            if (best_match == NULL || current->subnet_mask > best_match->subnet_mask) {
                best_match = current;
            }
        }
        current = current->next;
    }
    return best_match;
}

// 计算校验和 (简化示例，实际应使用正确的计算方法) (函数定义不变)
unsigned short calculate_checksum(IPv4Packet *packet) {
    unsigned short sum = 0;
    unsigned short *ptr = (unsigned short *) packet;
    int length = sizeof(IPv4Packet);

    for (int i = 0; i < length / 2; i++) {
        sum = sum + ptr[i];
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (unsigned short) (~sum);
}

void handle_ipv4_packet(RouteEntry *rt, IPv4Packet *packet) {
    if (packet->source_ip == packet->destination_ip) {
        printf("环回地址，不进行路由：源地址 %s, 目标地址 %s\n", ip_to_str(packet->source_ip), ip_to_str(packet->destination_ip));
        return;
    }
    if (packet->ttl == 0) {
        printf("TTL为0，丢弃分组\n");
        return;
    }
    packet->ttl--;
    packet->checksum = 0;
    packet->checksum = calculate_checksum(packet);
    // 查找路由
    RouteEntry *route = find_route(rt, packet->destination_ip);
    if (route != NULL) {
        printf("找到路由，转发分组\n");
        printf("转发到下一跳： %s\n", ip_to_str(route->next_hop_ip));
    } else {
        printf("没有找到路由，丢弃分组\n");
    }
}

// 从pcap文件读取数据包并处理 (函数定义不变)
void process_pcap_file(char *pcap_file_path, RouteEntry *rt) {
    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t *handle = pcap_open_offline(pcap_file_path, errbuf);
    if (handle == NULL) {
        printf("%s", errbuf);
        fprintf(stderr, "Error opening pcap file: %s\n", errbuf);
        return;
    }

    struct pcap_pkthdr header;
    const unsigned char *packet;

    while ((packet = pcap_next(handle, &header)) != NULL) {
        struct ether_header *ether = (struct ether_header *) packet;

        if (ntohs(ether->ether_type) != ETHERTYPE_IP) {
            printf("非IP分组，丢弃\n\n");
            continue;
        }

        const unsigned char *ip_packet_data = packet + sizeof(struct ether_header);
        struct ip *ip_header = (struct ip *) ip_packet_data;
        struct tm *ltime;
        char timestr[26];
        time_t local_tv_sec;
        local_tv_sec = header.ts.tv_sec;
        ltime = localtime(&local_tv_sec);
        strftime(timestr, sizeof(timestr), "%Y-%m-%d %H:%M:%S", ltime);
        //提取IP数据包相关信息
        char source_ip_str[INET_ADDRSTRLEN];
        char destination_ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &ip_header->ip_src.s_addr, source_ip_str, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &ip_header->ip_dst.s_addr, destination_ip_str, INET_ADDRSTRLEN);

        IPv4Packet ipv4_packet;
        ipv4_packet.source_ip = ntohl(ip_header->ip_src.s_addr);
        ipv4_packet.destination_ip = ntohl(ip_header->ip_dst.s_addr);
        ipv4_packet.ttl = ip_header->ip_ttl;
        ipv4_packet.checksum = ntohs(ip_header->ip_sum);

        int ip_header_len = (ip_header->ip_v & 0x0F) * 4;
        int payload_len = ntohs(ip_header->ip_len) - ip_header_len;

        if (payload_len > sizeof(ipv4_packet.data)) {
            printf("数据部分过长，丢弃\n\n");
            continue;
        }

        memcpy(ipv4_packet.data, ip_packet_data + ip_header_len, payload_len);
        ipv4_packet.length = payload_len;
        handle_ipv4_packet(rt, &ipv4_packet);
        printf("数据包捕获时间: %s.%06ld IP数据包长度: %d字节 源IP地址: %s 目的IP地址: %s TTL: %d 协议类型: %d \n\n",
               timestr, header.ts.tv_usec, ntohs(ip_header->ip_len), source_ip_str,
               destination_ip_str, ip_header->ip_ttl, ip_header->ip_p);
    }
    pcap_close(handle);
}
