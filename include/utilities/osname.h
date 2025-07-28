#ifndef OSNAME
#define OSNAME
#include <stdio.h>
#include <string.h>
#include <sys/utsname.h>
void init_osname(void);
void get_osname(char *name);
void get_nodename(char *name);
int islinux(void);
int isbsd(void);
extern struct utsname osname;
extern int status;
#endif
