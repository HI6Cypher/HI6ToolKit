#include "utilities/utilities.h"

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
