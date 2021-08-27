//
// Created by 彭强兵 on 2021/3/29.
//
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <sys/stat.h>
#include <stdlib.h>
#include "syscall.h"



int main(int argc, char *argv[]) {
    char header[MAX_HEADER] = {'\0'};
    char type[MAX_TYPE] = {'\0'};
    Sysdump *sys =  (Sysdump *) malloc(sizeof(Sysdump));
    memset(sys, 0, sizeof(Sysdump));
    char buffer[OS_MAXSTR] = {0};
    char cache[OS_MAXSTR] = {0};
    int icache = 0;
    size_t total_len = 0, len = 0;
    char *id;
    char *p;
    size_t z;
    int64_t offset = 0;
    int64_t rbytes = 0;
    int maximum_lines = 100000;

    LinkList * head = create_node(0, 0, RULE_NUM, rules);

    char *file = "/Users/pengqiangbing/work/opensource/cncs/audit_log/web_shell_jsp/noent.txt";
    FILE *fp = file_open(0,file);
    if (fp == NULL)
        return 0;

    int lines = 0;
    for (offset = w_ftell(fp);
         fgets(buffer, OS_MAXSTR, fp) && (!maximum_lines || lines < maximum_lines) &&
         offset >= 0; offset += rbytes) {
        rbytes = w_ftell(fp) - offset;

        /* Flow control */
        if (rbytes <= 0) {
            break;
        }
        lines++;

        if (buffer[rbytes - 1] == '\n') {
            buffer[rbytes - 1] = '\0';

            if ((int64_t) strlen(buffer) != rbytes - 1) {
                printf("Line in '%s' contains some zero-bytes (valid=%ld / total=%ld). Dropping line.",
                       file, (int64_t) strlen(buffer), (int64_t) rbytes - 1);
                continue;
            }
        } else {
            if (rbytes == OS_MAXSTR - 1) {
                // Message too large, discard line
                for (offset += rbytes; fgets(buffer, OS_MAXSTR, fp); offset += rbytes) {
                    rbytes = w_ftell(fp) - offset;
                    /* Flow control */
                    if (rbytes <= 0) {
                        break;
                    }
                    if (buffer[rbytes - 1] == '\n') {
                        break;
                    }
                }
            } else if (feof(fp)) {
                printf("Message not complete. Trying again: '%s'\n", buffer);
                if (fseek(fp, offset, SEEK_SET) < 0) {
                    printf(FSEEK_ERROR, file, errno, strerror(errno));
                    break;
                }
            }
            break;
        }
        // Extract header: "type=\.* msg=audit(\d+.\d+:\d+):"
        if (strncmp(buffer, "type=", 5) ||
            !((id = strstr(buffer + 5, "msg=audit(")) && (p = strstr(id += 10, "): ")))) {
            printf("Discarding audit message because of invalid syntax.\n");
            break;
        }
        z = p - id;

        sscanf(buffer, "type=%s ", &type);
        len = strlen(type);
        if (strncmp(id, header, z)) {
            // Current message belongs to another event: send cached messages
            if (icache > 0) {
                cache[total_len] = '\0';
                LinkList *cur = get_node_ifnull_add(head, 0, sys->ses, RULE_NUM, rules);
                dump(sys, header, cache, icache, cur);
                memset(cache, 0, sizeof(cache));
                memset(sys, 0, sizeof(Sysdump));
            }
            strncpy(cache, type, len);
            total_len = len;
            icache = 1;
            strncpy(header, id, z < MAX_HEADER ? z : MAX_HEADER - 1);
        } else {
            // The header is the same: store
            if (icache == MAX_CACHE)
                printf("Discarding audit message because cache is full.");
            else {
                if (total_len + len + 1 < OS_MAXSTR) {
                    cache[total_len++] = ' ';
                    strncpy(cache + total_len, type, len);
                    total_len += len;
                    icache++;
                }
            }
        }
        if (!strncmp(type, "SYSCALL", 6)) {
            if(strstr(buffer,"per=400000") == NULL) {//execution domains
                sscanf(buffer,
                       "type=%*s msg=audit(%*s arch=%*s syscall=%hd success=%*s exit=%d a0=%*s a1=%*s a2=%*s a3=%*s "
                       "items=%*d ppid=%d pid=%d auid=%*d uid=%hd gid=%*d euid=%*d suid=%*d fsuid=%*d egid=%*d sgid=%*d "
                       "fsgid=%*d tty=%*s ses=%d comm=%255s exe=%255s ", &(sys->id), &(sys->exit), &(sys->ppid), &(sys->pid), &(sys->user), &(sys->ses), &(sys->comm), &(sys->exe));
            }else{
                sscanf(buffer,
                       "type=%*s msg=audit(%*s arch=%*s syscall=%hd per=%*d success=%*s exit=%d a0=%*s a1=%*s a2=%*s a3=%*s "
                       "items=%*d ppid=%d pid=%d auid=%*d uid=%hd gid=%*d euid=%*d suid=%*d fsuid=%*d egid=%*d sgid=%*d "
                       "fsgid=%*d tty=%*s ses=%d comm=%255s exe=%255s ", &(sys->id), &(sys->exit), &(sys->ppid), &(sys->pid), &(sys->user), &(sys->ses), &(sys->comm), &(sys->exe));
            }
            sys->alias = sys->id;
            if(sys->id == 57)
                sys->alias = 56;
        } else if (!strncmp(type, "EXECVE", 6)) {//拼接full cmd到audit日志
            full_cmd(buffer, sys->attr);
//            strcat(buffer, sys->attr);
//            int buf_size = strlen(buffer);
//            if (buf_size > OS_MAXSTR) {
//                //增加逻辑，两个长度相加 >65535,则也丢弃。
//                printf("length of encoded buffer greater than os_maxstr. id ");
//            }
        } else if (!strncmp(type, "SOCKADDR", 8)) {
            sscanf(buffer, "type=%*s msg=audit(%*s saddr=%255s", &(sys->attr));
        } else if(!strncmp(type, "CWD", 3)){
            sscanf(buffer, "type=%*s msg=%*s cwd=%255s", &(sys->cwd));
        } else if(!strncmp(type, "PATH", 4)){
            sscanf(buffer, "type=%*s msg=%*s item=%*d name=%255s", &(sys->path));
        }
    }
    if (icache > 0) {
        cache[total_len] = '\0';
        LinkList *cur = get_node_ifnull_add(head, 0, sys->ses, RULE_NUM, rules);
        dump(sys, header, cache, icache, cur);
    }
    free(sys);
    printf("Read %d lines from %s\n", lines, file);

    while(head->next != NULL){
        tail_del(head);
    }
    free(head);
    return 0;
}