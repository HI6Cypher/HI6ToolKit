#ifndef IFACE
#define IFACE
#include <net/if.h>
void init_iface(void);
struct if_nameindex *getifaces(void);
void free_getifaces(void);
extern struct if_nameindex *ifaces;
#endif
