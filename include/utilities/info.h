#ifndef INFO
#define INFO
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#define MAXINFO 512
#define MAXFTIME 15
#define MAXHOSTNAME 256
#define MAXPID 8
#define MAXOSNAME 10
char *getinfo(void);
void free_getinfo(char *info);
#endif
