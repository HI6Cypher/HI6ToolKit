#include <time.h>
#include "utilities/info.h"
#include "utilities/osname.h"

static void get_formatted_time(char *formatted_time) {
    char ftime[MAXFTIME];
    time_t timep = time(NULL);
    strftime(formatted_time, MAXFTIME, "%Y %T", localtime(&timep));
    return;
}

void get_pid(char *pid) {
    snprintf(pid, MAXPID, "%d", getpid());
    return;
}

char *getinfo(void) {
    char *info = (char *) calloc(MAXINFO, sizeof (char));
    if (info == NULL)
        return NULL;
    char _osname[MAXOSNAME];
    char formatted_time[MAXFTIME];
    char hostname[MAXHOSTNAME];
    char pid[MAXPID];
    get_formatted_time(formatted_time);
    get_osname(_osname);
    gethostname(hostname, MAXHOSTNAME);
    get_pid(pid);
    sprintf(
        info,
        "[System] : [%.10s, %.15s]\n[Hostname] : [%.256s, PID %.8s]\n[GitHub] : [github.com/HI6Cypher]\n",
        _osname,
        formatted_time,
        hostname,
        pid
    );
    return info;
}

void free_getinfo(char *info) {
    free(info);
    return;
}
