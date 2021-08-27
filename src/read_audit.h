//
// Created by 彭强兵 on 2021/4/6.
//
#include <stdarg.h>
#include <sys/stat.h>

#ifndef HELLO_READ_AUDIT_H
#define HELLO_READ_AUDIT_H

#define SIMPLE_MAXSTR 1024
#define STR_LEN 256
#define SNAPSHOT_LEN 28
#define MAX_RULE_LEN 16
#define RULE_NUM 15

#define FOPEN_ERROR   "(1103): Could not open file '%s' due to [(%d)-(%s)]."
#define FSTAT_ERROR   "(1117): Could not retrieve information of file '%s' due to [(%d)-(%s)]."
#define FREAD_ERROR   "(1115): Could not read from file '%s' due to [(%d)-(%s)]."
#define FSEEK_ERROR   "(1116): Could not set position in file '%s' due to [(%d)-(%s)]."
#define FIRST_PARAM_INDEX 3
//0200091E 0A321ACE0000000000000000
//02001538 570933B70000000000000000
//01002F64 65762F6C6F67
//02000035 DF0505050000000000000000
//0200 0035 0A147896 0828C5F06B7F0000  //fam=inet laddr=10.20.120.150 lport=53
//0200 1F91 AC1002C9 0000000000000000
//02000BB87F0000010000000000000000
#define IPV4_LOCAL "020000007F0000010000000000000000"
#define IPV6_LOCAL "0A000000000000000000000000000000000000000000000100000000"
#define INET_53 "02000035"

typedef struct Sysdump{
    short id;//syscall
    short user;
    int alias;
    int exit;
    int ppid;
    int pid;
    unsigned int ses;//session
    char cwd[SIMPLE_MAXSTR];//上下文
    char comm[STR_LEN];
    char exe[STR_LEN];
    char path[STR_LEN];
    char attr[OS_MAXSTR];//参数传递时，栈空间数组被回收，用指针传递,如connect的saddr，execve的fcmd，FD_PAIR的fd0=5 fd1=6,PATH的name
} Sysdump ;

struct syscall {
    short id;
    char min_len;//特征系统调用后至少跟min_len个非特征系统调用
    char attr[32];//如connect的raddress，execve的fcmd，dup3的a1参数
};

/*数组移位很慢，链表也很慢，使用ring实现快速移位，
为了更快速移位，ring的长度支持8，16，32，64，128...
array[k]值表示规则的前array[k]个元素满足匹配 */
typedef struct rule {
    char title[64];
    unsigned char len;//规则长度,最大长度256
    short mod;//窗口长度
    int type;
    struct syscall syscalls[MAX_RULE_LEN];//规则的每一个元素
    short i;//窗口的当前索引，0---ring.mod-1
    short *array;//记录每个位置已经匹配的系统调用数
} Rule;
static FILE *sys_file = NULL;
#endif //HELLO_READ_AUDIT_H
