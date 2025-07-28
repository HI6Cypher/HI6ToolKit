#include "utilities/osname.h"

struct utsname osname;
int status;

void init_osname(void) {
    status = uname(&osname);
    return;
}

void get_osname(char *name) {
    sprintf(name, (status == 0) ? osname.sysname : "unknown");
    return;
}

void get_nodename(char *name) {
    sprintf(name, (status == 0) ? osname.nodename : "unknown");
    return;
}

int islinux(void) {
    return ((strcmp(osname.sysname, "Linux") == 0) ? 1 : 0);
}

int isbsd(void) {
    return ((strstr(osname.sysname, "BSD") != NULL) ? 1 : 0);
}
