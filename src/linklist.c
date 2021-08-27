//
// Created by 彭强兵 on 2021/5/27.
//
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "linklist.h"
#include "read_audit.h"

Rule** copy_rules(int num, Rule *rules){
    Rule ** crules =(Rule **)malloc(sizeof(Rule*)*num);
    int i;
    for(i = 0; i < num; i++){
        crules[i] = (Rule *) malloc(sizeof(Rule));
        crules[i]->mod = rules[i].mod;
        crules[i]->type = rules[i].type;
        crules[i]->len = rules[i].len;
        memcpy(crules[i]->title, rules[i].title, sizeof(rules[i].title));
        memcpy(crules[i]->syscalls, rules[i].syscalls,sizeof(rules[i].syscalls));
        crules[i]->i = 0;
        crules[i]->array = (short *) calloc(rules[i].mod, sizeof(short));
    }
    return crules;
}
void free_snapshots(int num, char** snapshots){
   int i;
   for(i = 0; i < num; i++){
       free(snapshots[i]);
   }
   free(snapshots);
}

void free_rules(int num, Rule ** rules){
    int i;
    for(i = 0; i < num; i++) {
        free(rules[i]->array);
        free(rules[i]);
    }
    free(rules);
}

LinkList *create_node(int user, int ses, int rule_num, Rule *rules) {
    LinkList *cur =(LinkList *) malloc(sizeof(LinkList));
    if (NULL == cur) {
        printf("malloc error!\n");
        return NULL;
    }
    memset(cur, 0, sizeof(LinkList));
    cur->user = user;
    cur->ses = ses;
    cur->s_index = 0;
    cur->snapshots =(char **)malloc(sizeof(char*) * SNAPSHOT_LEN);
    for(int i = 0; i < SNAPSHOT_LEN; i++){
        cur->snapshots[i] = (char *)malloc(sizeof(char) * SIMPLE_MAXSTR);
    }
    cur->rules_num = rule_num;
    cur->crules = copy_rules(rule_num, rules);
    cur->next = NULL;
    return cur;
}

void head_insert(LinkList *head, LinkList *node) {
    LinkList *cur = head;
    node->next = cur->next;
    cur->next = node;

}

//链表的尾插
void tail_insert(LinkList *head, LinkList *node) {
    LinkList *cur = head;
    while (NULL != cur->next) {
        cur = cur->next;
    }
    cur->next = node;
}

//LinkList *get_node(LinkList *head, int ses) {
//    LinkList *cur = head;
//    while (NULL != cur->next) {
//        cur = cur->next;
//        if (cur->ses == ses) {
//            return cur;
//        }
//    }
//    return NULL;
//}

void print_nodes(LinkList *head) {
    LinkList *cur = head->next;
    while (NULL != cur) {
        printf("ses=%d\n", cur->ses);
        cur = cur->next;
    }
}

LinkList *get_node_ifnull_add(LinkList *head, int user, int ses, int rule_num, Rule *rules) {
    LinkList *cur = get_node_move_first(head, ses);
    if (cur == NULL) {
        cur = create_node(user, ses, rule_num, rules);
        head_insert(head, cur);
        if(length(head) > LINK_MAX_LEN)
            tail_del(head);
    }
    return cur;
}

LinkList *get_node_move_first(LinkList *head, int ses) {
    LinkList *cur = head->next;
    if (cur == NULL) {
        return NULL;
    }
    if (cur->ses == ses) {
        return cur;
    }
    LinkList *prev = NULL;
    while (NULL != cur->next) {
        prev = cur;
        cur = cur->next;
        if (cur->ses == ses) {
            if (cur->next != NULL) {
                prev->next = cur->next;
                cur->next = head->next;
                head->next = cur;
            } else {
                prev->next = NULL;
                cur->next = head->next;
                head->next = cur;
            }
            return cur;
        }
    }
    return NULL;
}

void tail_del(LinkList *head) {
    LinkList *cur = head;
    if (cur == NULL) {
        return ;
    }
    LinkList *prev = NULL;
    while (NULL != cur->next) {//只有一个节点时不删除
        prev = cur;
        cur = cur->next;
        if (cur->next == NULL) {
            prev->next = NULL;
            free_snapshots(SNAPSHOT_LEN, cur->snapshots);
            free_rules(cur->rules_num, cur->crules);
            free(cur);
        }
    }
}

int length(LinkList *head){
    LinkList *cur = head->next;
    int i = 0;
    while (NULL != cur) {
        i++;
        cur = cur->next;
    }
    return i;
}
//删除符合条件的第一个node，return 1表示成功删除，0表示未删除
//int del_node(LinkList *head, int ses) {
//    LinkList *cur = head;
//    if (cur->ses == ses && cur->next != NULL) {//当只有一个node时不能删除
//        head = head->next;
//        free(cur);
//        return 1;
//    }
//    LinkList *prev = NULL;
//    while (NULL != cur->next) {
//        prev = cur;
//        cur = cur->next;
//        if (cur->ses == ses) {
//            if (cur->next != NULL) {
//                prev->next = cur->next;
//                free(cur);
//            } else {
//                prev->next = NULL;
//                free(cur);
//            }
//            return 1;
//        }
//    }
//    printf("nothing to delete!\n");
//    return 0;
//}

