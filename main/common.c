#include "common.h"

#include <stdio.h>
#include <arpa/inet.h>

// 输出路由表到文件
void print_route_table_to_file(RouteEntry *head, FILE *file) {
    RouteEntry *current = head->next;
    while (current != NULL) {
        char dest_str[INET_ADDRSTRLEN];
        char mask_str[INET_ADDRSTRLEN];
        char next_hop_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &current->destination_ip, dest_str, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &current->subnet_mask, mask_str, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &current->next_hop_ip, next_hop_str, INET_ADDRSTRLEN);
        fprintf(file, "Dest:%s, Mask:%s, NextHop:%s, Metric:%d\n",
                dest_str, mask_str, next_hop_str, current->metric);
        printf("Dest:%s, Mask:%s, NextHop:%s, Metric:%d\n",
              dest_str, mask_str, next_hop_str, current->metric);
        current = current->next;
    }
}

void print_route_table(RouteEntry *head, RouteEntry *tail) {
    RouteEntry *current = head->next;
    if (head == NULL) {
        printf("Route Table is empty\n");
    }
    while (current != NULL) {
        char dest_str[INET_ADDRSTRLEN];
        char mask_str[INET_ADDRSTRLEN];
        char next_hop_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &current->destination_ip, dest_str, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &current->subnet_mask, mask_str, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &current->next_hop_ip, next_hop_str, INET_ADDRSTRLEN);
        printf("Dest:%s, Mask:%s, NextHop:%s, Metric:%d\n",
               dest_str, mask_str, next_hop_str, current->metric);
        current = current->next;
    }
}
