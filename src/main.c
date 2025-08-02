#include "utilities/utilities.h"

unsigned char *handle_progress_bar(const unsigned long x, const unsigned long y) {}

void free_progress_bar(unsigned char *bar) {}

void free_all(void) {
    free_getifaces();
    free_getinfo(SYSINFO);
    return;
}

int main() {
    init_osname();
    init_iface();
    SYSINFO = getinfo();
    printf("%s\n", SYSINFO);
    printf("%s%s%s\n", RED("h"), GREEN("hello"), YELLOW("h"));
    printf("%d\n", ISROOT);
    printf("%d\n", ISOS);
    free_all();
    return 0;
}
