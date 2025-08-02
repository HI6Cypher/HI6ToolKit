#ifndef UTILITIES
#define UTILITIES
#include <unistd.h>
#include <net/if.h>
#include <stdio.h>
#include <time.h>
#include "iface.h"
#include "osname.h"
#include "info.h"

#define ISROOT (getuid() == 0)
#define TIME time(NULL)
#define ISOS (islinux() || isbsd())
#define IFACES ifaces
#define COUNTER (long int)
#define SLASH '/'
#define RED(text) "\e[31m" #text "\e[0m"
#define GREEN(text) "\e[32m" #text "\e[0m"
#define YELLOW(text) "\e[33m" #text "\e[0m"
char *SYSINFO;

unsigned char *handle_progress_bar(const unsigned long x, const unsigned long y);
void free_progress_bar(unsigned char *bar);

#endif
