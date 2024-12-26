#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#include "rip.h"
#include "forward.h"
#include "common.h"

int main() {
    char pcap_file_path[256];
    RouteEntry *head = init_route_table();
    RouteEntry *tail = head;
    // 添加路由信息
    handle_route_item(head, tail, "10.0.0.1", "255.255.255.0", "10.0.0.2", 2);
    handle_route_item(head, tail, "10.0.0.1", "255.255.255.0", "10.0.0.2", 2);
    handle_route_item(head, tail, "10.0.0.1", "255.255.255.0", "10.0.0.2", 2);
    print_route_table(head, tail);

    printf("请输入pcap文件名称：\n");
    if (fgets(pcap_file_path, sizeof(pcap_file_path), stdin) == NULL) {
        fprintf(stderr, "Error reading input.\n");
        return EXIT_FAILURE;
    }
    pcap_file_path[strcspn(pcap_file_path, "\n")] = 0;
    // 处理 IPv4 分组
    process_pcap_file(pcap_file_path, head);
    // 打印路由表
    FILE *route_file = fopen("route_table.txt", "w");
    if (route_file == NULL) {
        perror("打开路由表文件失败");
        free_route_table(head);
        return EXIT_FAILURE;
    }
    print_route_table_to_file(head, route_file);
    fclose(route_file);
    // 清理
    printf("模拟结束\n");
    return EXIT_SUCCESS;
}
