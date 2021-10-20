#ifndef RLBOX_CLAMD_CALLBACKS_H
#define RLBOX_CLAMD_CALLBACKS_H

#ifdef __cplusplus
extern "C" 
{
#endif

#include "clamav.h"

void * getfptr_t_pre();
void * getfptr_t_meta();
void * getfptr_t_post();
void * getfptr_t_clamscan_virus_found_cb();

#ifdef __cplusplus
}
#endif

#endif