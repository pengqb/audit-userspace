//
// Created by 彭强兵 on 2021/5/10.
//

#ifndef HELLO_ABNORMAL_H
#define HELLO_ABNORMAL_H

#include "linklist.h"

#define MAX_CACHE 16

#define MAX_TYPE 32

#define MAX_WIN_LEN 16


void full_cmd(const char *buffer, char *fcmd);
void dump(Sysdump *sys, char*header, char *cache, int icache, LinkList *node);

int64_t w_ftell(FILE *x);
FILE *file_open(int do_fseek, char *file);
#endif //HELLO_ABNORMAL_H
