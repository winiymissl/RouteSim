#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "rip.h"

#include <arpa/inet.h>
#define MAX_LENGTH 100

#include "common.h"

// 初始化路由表 (函数定义不变)
RouteEntry *init_route_table() {
    RouteEntry *rt = (RouteEntry *) malloc(sizeof(RouteEntry));
    if (rt == NULL) {
        perror("Failed to allocate memory for route table");
        exit(EXIT_FAILURE);
    }
    rt->next = NULL;
    return rt;
}

// 添加路由表项 (函数定义不变)
void add_route_entry(RouteEntry *head, RouteEntry *tail, unsigned int dest_ip, unsigned int mask, unsigned int next_hop,
                     int metric) {
    RouteEntry *new_entry = (RouteEntry *) malloc(sizeof(RouteEntry));
    if (new_entry == NULL) {
        perror("Failed to allocate memory for route entry");
        exit(EXIT_FAILURE);
    }
    new_entry->destination_ip = dest_ip;
    new_entry->subnet_mask = mask;
    new_entry->next_hop_ip = next_hop;
    new_entry->metric = metric;
    new_entry->next = NULL;

    (tail)->next = new_entry;
    tail = new_entry;
    free(new_entry);
}

// 释放路由表内存 (函数定义不变)
void free_route_table(RouteEntry *rt) {
    RouteEntry *current = rt;
    while (current != NULL) {
        RouteEntry *temp = current;
        current = current->next;
        free(temp);
    }
    free(rt);
}

void handle_route_item(RouteEntry *rt, RouteEntry *tail, char *dest_ip_str, char *mask_str, char *next_hop_str,
                       int metric) {
    struct in_addr dest_ip;
    struct in_addr subnet_mask;
    struct in_addr next_hop;

    // 将点分十进制字符串形式的目的IP地址转换为网络字节序的二进制形式
    if (inet_pton(AF_INET, dest_ip_str, &dest_ip) != 1) {
        perror("目的IP地址转换出错");
        return;
    }

    // 将点分十进制字符串形式的子网掩码转换为网络字节序的二进制形式
    if (inet_pton(AF_INET, mask_str, &subnet_mask) != 1) {
        perror("子网掩码转换出错");
        return;
    }

    // 将点分十进制字符串形式的下一跳IP地址转换为网络字节序的二进制形式
    if (inet_pton(AF_INET, next_hop_str, &next_hop) != 1) {
        perror("下一跳IP地址转换出错");
        return;
    }
    add_route_entry(rt, tail, dest_ip.s_addr, subnet_mask.s_addr, next_hop.s_addr, metric);
    printf("添加路由 Dest: %s, Mask: %s, NextHop: %s, Metric: %d\n\n",
           dest_ip_str, mask_str, next_hop_str, metric);
}
