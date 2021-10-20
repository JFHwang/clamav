#ifndef RLBOX_CLAMD_CALLBACKS_H
#define RLBOX_CLAMD_CALLBACKS_H

#ifdef __cplusplus
extern "C" 
{
#endif

#ifdef _WIN32
void * getfptr_t_svc_checkpoint();
#endif

void * getfptr_t_clamd_virus_found_cb();
void * getfptr_t_hash_callback();

#ifdef __cplusplus
}
#endif

#endif