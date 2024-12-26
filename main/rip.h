#ifndef RIP_H
#define RIP_H
#include "common.h"

// 初始化路由表
RouteEntry *init_route_table();
// 添加路由表项
void add_route_entry(RouteEntry *rt, RouteEntry *tail,unsigned int dest_ip, unsigned int mask, unsigned int next_hop, int metric);
// 释放路由表内存
void free_route_table(RouteEntry *rt);
// 模拟 RIP 报文处理
void handle_route_item(RouteEntry *rt, RouteEntry *tail,char *dest_ip_str, char *mask_str, char *next_hop_str, int metric);

#endif