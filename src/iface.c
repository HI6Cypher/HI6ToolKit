#include <stdlib.h>
#include <string.h>
#include "utilities/iface.h"

struct if_nameindex *ifaces;

void init_iface(void) {
    ifaces = if_nameindex();
    return;
}

struct if_nameindex *getifaces(void) {
    return ifaces;
}

void free_getifaces(void) {
    if_freenameindex(ifaces);
    return;
}
