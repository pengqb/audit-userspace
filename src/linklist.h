//
// Created by 彭强兵 on 2021/5/27.
//

#ifndef HELLO_LINKLIST_H
#define HELLO_LINKLIST_H
#define MAX_WIN_LEN 16
#define LINK_MAX_LEN 5
#include "read_audit.h"

/**
 * 带有头节点的单链表
 */
typedef struct node {
    int user;
    int ses;
    int s_index;//snapshot index
    char **snapshots;//存放系统调用快照，只能单进程操作
    int rules_num;
    Rule ** crules;
    struct node *next;
} LinkList;

LinkList *create_node(int user, int ses, int num, Rule *rules);
void head_insert(LinkList *head, LinkList *node);
void tail_insert(LinkList *head, LinkList *node);
void print_nodes(LinkList *head);
LinkList *get_node_ifnull_add(LinkList *head, int user, int ses, int rule_num, Rule *rules);
LinkList *get_node_move_first(LinkList *head, int ses);
void tail_del(LinkList *head);
int length(LinkList *head);


#endif //HELLO_LINKLIST_H
