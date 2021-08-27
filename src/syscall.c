//
// Created by 彭强兵 on 2021/5/10.
//
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <stdarg.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include "linklist.h"

static inline short index_plus_plus(short mod, short i) {
    if (i < mod - 1)
        i = i + 1;
    else
        i = i + 1 - mod;
    return i;
}

static inline short index_sub_sub(short mod, short i) {
    if (i > 0)
        i = i - 1;
    else
        i = mod + i - 1;
    return i;
}

/*16进制转字符串*/
static inline int hex2str(const char *hex, char *lpstr) {
    int i = 0, v;
    while (1) {
        if (1 != sscanf(hex + i * 2, "%2x", &v))
            break;
        lpstr[i] = (char) v;
        i++;
    }
    lpstr[i] = 0;
    return 1;
}

static void pprintf(const char *format, ...) {
    va_list args;
    va_start(args, format);
    vfprintf(sys_file,format,args);
    va_end(args);
}
/*匹配是否成功及匹配成功后的清理现场，return 0 不匹配；return 1 匹配成功
 * match_len 已经匹配的序列长度
 * m 总规则数
 * ses session
 */
int maching_suc(int match_len, Rule cur_rule, LinkList *node, int m, int ses) {
    int ret = 0;
    if (match_len == cur_rule.len) {
        //clean up
        pprintf("规则%s匹配一次\n", cur_rule.title);
        int x;
//        for(x = 0; x < SNAPSHOT_LEN; x++){//打印最近SNAPSHOT_LEN条系统调用
//            pprintf("%s",node->snapshots[node->s_index]);//是s_index而不是x，因为ring的首位置在s_index
//            node->s_index = index_plus_plus(SNAPSHOT_LEN,node->s_index);
//        }
        for (x = 0; x < m; x++) {
            memset(node->crules[x]->array, 0, 2 * node->crules[x]->mod);//clear ring
            node->crules[x]->i =0; //i清零，好像i不清零也可以的
        }
        ret = 1;
    }
    return ret;
}

// 1 至少有一条属性匹配成功，0不匹配
int compare_attr(const char *attr, const char *cmd) {
    char *copy = strdup(attr);
    char *free_copy = copy;
    char *token;
    int ret = 0;//不相等
    for (token = strsep(&copy, "|"); token != NULL; token = strsep(&copy, "|")) {
        if (!strncmp(token, cmd, strlen(token))) {
            ret = 1;//相等
            break;
        }
    }
    free(free_copy);//copy指向为NULL，所以释放free_copy
    return ret;
}

/*合并参数*/
void full_cmd(const char *buffer, char *fcmd) {
    char *copy = strdup(buffer);
    char *free_copy = copy;
    char *token;
    int i = 0;
    for (token = strsep(&copy, " "); token != NULL; token = strsep(&copy, " ")) {
        if (i >= FIRST_PARAM_INDEX) {//参数拼接full cmd
            token += 3;//删除字符"a*="
            if (token[0] == '\"') {//audit日志格式假设，以双引号开头的不需要解码，否则要解码
                token++;
                token[strlen(token) - 1] = ' ';
            } else {
                char str[OS_MAXSTR] = {0};
                hex2str(token, str);
                token = str;
            }
            strcat(fcmd, token);
        }
        i++;
    }
    int fcmd_len = strlen(fcmd);
    if (fcmd[fcmd_len - 1] == ' ')
        fcmd[fcmd_len - 1] = '\0';

    free(free_copy);
}

int64_t w_ftell(FILE *x) {
#ifndef WIN32
    int64_t z = ftell(x);
#else
    int64_t z = _ftelli64(x);
#endif
    if (z < 0) {
        printf("Ftell function failed due to [(%d)-(%s)]", errno, strerror(errno));
        return -1;
    } else {
        return z;
    }
}

//return NULL 文件打开错误
FILE *file_open(int do_fseek, char *file) {
    FILE *in = fopen(file, "r");
    if (!in) {
        printf(FOPEN_ERROR, file, errno, strerror(errno));
        return NULL;
    }
    /* Get inode number for fp */
    int fd = fileno(in);
    struct stat stat_fd = {.st_mode = 0};
    if (fstat(fd, &stat_fd) == -1) {
        printf(FSTAT_ERROR, file, errno, strerror(errno));
        fclose(in);
        in = NULL;
        return NULL;
    }
    /* Only seek the end of the file if set to */
    if (do_fseek == 1 && S_ISREG(stat_fd.st_mode)) {
        /* Windows and fseek causes some weird issues */
        if (fseek(in, 0, SEEK_END) < 0) {
            printf(FSEEK_ERROR, file, errno, strerror(errno));
            fclose(in);
            in = NULL;
            return NULL;
        }
    }
    return in;
}

/*return 1 匹配成功；return 0，匹配不成功或者还未匹配结束。
 * m 总规则数
 */
static int is_sub_sequence(Sysdump *a, LinkList *node) {
    int j = 0;
    Rule ** rules= node->crules;
    while (j < node->rules_num) {//j对应第j个规则
        //反弹shell，不需要比较102系统调用。2.某些类型的日志不参与部分规则的匹配
        if((rules[j]->type & 1) && (a->id == 102 || a->id == 2 || a->id == 4)){
            j++;
            continue;
        }
        short k = rules[j]->i;//k从ring的第一个元素（index=0）开始
        short *array = rules[j]->array;
        array[k] = 0;//ring的第一个元素,还未比较时,没有元素满足匹配。
        short z = 0;//窗口的总长度，窗口的第一元素不是0，而是k
        while (z < rules[j]->mod) {
            if( (z == 0 && a->alias == rules[j]->syscalls[0].id) ||//dump和规则的第0个元素相等,此时array[k]就是第0个元素
                (z > 0 && array[k] && a->alias == rules[j]->syscalls[array[k]].id)){////窗口的第k个元素不为零，且dump和规则的第array[k]元素相等
                //需要比较扩展属性的，目前只比较59的扩展属性
                char *attr = rules[j]->syscalls[array[k]].attr;
                if (a->id == 59 && strlen(attr) > 0) {
                    if (compare_attr(attr, a->attr)) {
                        array[k]++;//array[k]值表示规则的前array[k]个元素满足匹配
                        if(maching_suc(array[k], *rules[j], node, node->rules_num, a->ses))
                            return 1;
                    }
                } else if(a->id == 33 && strlen(attr) > 0){
                    int exit = attr[0] -48;
                    if (exit == a->exit) {
                        array[k]++;//array[k]值表示规则的前array[k]个元素满足匹配
                        if(maching_suc(array[k], *rules[j], node, node->rules_num, a->ses))
                            return 1;
                    }
                }else{
                    array[k]++;//array[k]值表示规则的前array[k]个元素满足匹配
                    if(maching_suc(array[k], *rules[j], node, node->rules_num, a->ses))
                        return 1;
                }
            }
            z++;
            k = index_plus_plus(rules[j]->mod, k);
        }
        rules[j]->i = index_sub_sub(rules[j]->mod, rules[j]->i);
        j++;
    }
    return 0;
}

void dump(Sysdump *sys, char*header, char *cache, int icache, LinkList *node) {
//    if(-1 == sys->ses)
//        return;
//1.某些类型的日志不参与所有规则的匹配
    int syscall = sys->id;
    if(
            syscall != 2 &&
            syscall != 4 &&
            syscall != 22 &&
            syscall != 32 &&
            syscall != 33 &&
    syscall != 42 && syscall != 56 && syscall != 57 && syscall != 58 && syscall != 59 &&
    syscall != 102 &&
    syscall != 132 && syscall != 235 &&
    syscall != 280 && syscall != 292 && syscall != 293){
        return;
//    } else if (syscall == 42) {
//    if (syscall == 0 || syscall == 1
//    || syscall == 2 || syscall == 3
//    || syscall == 4 || syscall == 5 || syscall == 6
//    || syscall == 8 || syscall == 9
//    || syscall == 10 || syscall == 13 || syscall == 11 || syscall == 12 || syscall == 14
//        || syscall == 16 || syscall == 23 || syscall == 72
//        || syscall == 104 || syscall == 107 || syscall == 108
//        || syscall == 202 || syscall == 232
//        ) {
//        return;//必须去掉的
//    } else if ( syscall == 21 || syscall == 41 || syscall == 79 ||syscall == 80
//    || syscall == 97 || syscall == 104 || syscall == 107 || syscall == 108 || syscall == 110 || syscall == 111
//    || syscall == 158 || syscall == 273) {//
//        return;//可能去掉
//    } else if(syscall == 59){
//        if (sys->exit == -ENOENT)
//            return;
    }else if (syscall == 42) {
        if (sys->exit == -ENOENT)
            return;
        int fam = sys->attr[1] - 48;//字符串转整数
        if (fam != AF_INET)
            return;
        if (!strncmp(IPV4_LOCAL, sys->attr, 32) || !strncmp(IPV6_LOCAL, sys->attr, 56)
            || !strncmp(INET_53, sys->attr, 8))
            return;
    }else if(syscall == 4){
        int len = 0;
        if(sys->path[0] == '"'){
            len = strlen(sys->path) -6;//如果有单引号，需要删除单引号。
            char *cur =&(sys->path[(len > 0) ? len : 0]);
            if (strncmp(cur, "class", 5))
                return;
        }else{
            len = strlen(sys->path) -10;
            char *cur =&(sys->path[(len > 0) ? len : 0]);
            if (strncmp(cur, "636C617373", 10))//class的16进制表示
                return;
        }
    }else if (syscall == 2){
        if (strncmp(sys->comm, "\"php\"", 5) && strncmp(sys->comm, "\"httpd\"", 7))
            return;
    }

    char snapshot[SIMPLE_MAXSTR];
    if (syscall == 59) {
        snprintf(snapshot,sizeof(snapshot),"sc=%03d,%s %d,%d,%d,%d,%d,%s,%s %s, cwd=%s, %s,total %d line\n", syscall, header,
                 sys->exit, sys->ppid, sys->pid, sys->user, sys->ses, sys->comm, sys->exe, sys->attr, sys->cwd, cache, icache);
    } else if (syscall == 42){
        snprintf(snapshot,sizeof(snapshot),"sc=%03d,%s %d,%d,%d,%d,%d,%s,%s %s, %s,total %d line\n", syscall, header,
                 sys->exit, sys->ppid, sys->pid, sys->user, sys->ses, sys->comm, sys->exe, sys->attr, cache, icache);
    } else if (syscall == 2 || syscall == 4){
        snprintf(snapshot,sizeof(snapshot),"sc=%03d,%s %d,%d,%d,%d,%d,%s,%s,%s %s, %s,total %d line\n", syscall, header,
                 sys->exit, sys->ppid, sys->pid, sys->user, sys->ses, sys->comm, sys->exe, sys->path, sys->attr, cache, icache);
    } else {
        snprintf(snapshot,sizeof(snapshot),"sc=%03d,%s %d,%d,%d,%d,%d,%s,%s %s,total %d line\n", syscall, header,
                 sys->exit, sys->ppid, sys->pid, sys->user, sys->ses, sys->comm, sys->exe, cache, icache);
    }

//    if (syscall == 59) {
//        snprintf(snapshot,sizeof(snapshot),"sc=%03d %s, cwd=%s, %s,total %d line\n", syscall, sys->attr, sys->cwd, cache, icache);
//    } else if (syscall == 42){
//        snprintf(snapshot,sizeof(snapshot),"sc=%03d %s, %s,total %d line\n", syscall, sys->attr, cache, icache);
//    } else if (syscall == 33){
//        snprintf(snapshot,sizeof(snapshot),"sc=%03d %d, %s,total %d line\n", syscall, sys->exit, cache, icache);
//    } else if (syscall == 2){
//        snprintf(snapshot,sizeof(snapshot),"sc=%03d %s, %s,total %d line\n", syscall, sys->attr, cache, icache);
//    } else {
//        snprintf(snapshot,sizeof(snapshot),"sc=%03d %s,total %d line\n", syscall, cache, icache);
//    }

    //只保留最近SNAPSHOT_LEN个快照
    memset(node->snapshots[node->s_index], 0,SIMPLE_MAXSTR);
    strcpy(node->snapshots[node->s_index],snapshot);
    node->s_index = index_plus_plus(SNAPSHOT_LEN,node->s_index);
    pprintf("%s",snapshot);
    is_sub_sequence(sys, node);//rules 数组的名字就是数组的地址, &rules ,&rules[0]都可以？

    fflush(sys_file);
}

