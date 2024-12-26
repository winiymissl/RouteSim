#ifndef FORWARD_H
#define FORWARD_H
#include "common.h"
#include <netinet/in.h>

// 手动声明 struct ether_header 结构体
struct ether_header {
    u_int8_t ether_dhost[6]; // 目的MAC地址
    u_int8_t ether_shost[6]; // 源MAC地址
    u_int16_t ether_type; // 以太网类型（标识上层协议，如IPv4、IPv6、ARP等）
};

// 手动声明 struct ip 结构体，为了兼容 netinet/ip.h
struct ip {
#if BYTE_ORDER == LITTLE_ENDIAN
    u_int8_t ip_hl: 4; // 首部长度（以4字节为单位）
    u_int8_t ip_v: 4; // 版本号（IPv4为4）
#elif BYTE_ORDER == BIG_ENDIAN
    u_int8_t    ip_v:4;         // 版本号（IPv4为4）
    u_int8_t    ip_hl:4;        // 首部长度（以4字节为单位）
#endif
    u_int8_t ip_tos; // 服务类型
    u_int16_t ip_len; // 总长度（首部 + 数据部分）
    u_int16_t ip_id; // 标识符
    u_int16_t ip_off; // 标志位和片偏移
    u_int8_t ip_ttl; // 生存时间
    u_int8_t ip_p; // 协议（如TCP是6，UDP是17等）
    u_int16_t ip_sum; // 校验和
    struct in_addr ip_src; // 源IP地址
    struct in_addr ip_dst; // 目的IP地址
};

// 定义 IP 数据包的结构体
typedef struct ip_packet {
    unsigned int source_ip;
    unsigned int destination_ip;
    unsigned char ttl;
    unsigned short checksum;
    unsigned char data[1500];
    int length;
} IPv4Packet;

// 将 IP 地址转换为字符串
char *ip_to_str(unsigned int ip);

// 查找路由
RouteEntry *find_route(RouteEntry *rt, unsigned int dest_ip);

// 处理 IPv4 分组
void handle_ipv4_packet(RouteEntry *rt, IPv4Packet *packet);

// 从pcap文件读取数据包并处理
void process_pcap_file(char *pcap_file_path, RouteEntry *rt);

#endif
