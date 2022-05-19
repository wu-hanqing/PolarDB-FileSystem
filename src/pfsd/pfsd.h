#ifndef PFSD_H
#define PFSD_H

int pfsd_start(int allow_daemon);
int pfsd_stop(void);
int pfsd_is_started(void);
int pfsd_wait_stop(void);

#endif
