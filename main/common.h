#ifndef COMMON_H
#define COMMON_H

#define ETHERTYPE_IP 0x0800
#include <stdio.h>

// 定义路由表项结构体
typedef struct route_entry {
    unsigned int destination_ip;
    unsigned int subnet_mask;
    unsigned int next_hop_ip;
    int metric;
    struct route_entry *next;
} RouteEntry;


// 输出路由表到文件
void print_route_table_to_file(RouteEntry *rt, FILE *file);

void print_route_table(RouteEntry *rt, RouteEntry *tail );
#endif
