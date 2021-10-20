#ifndef RLBOX_SCANNER_H
#define RLBOX_SCANNER_H

#ifdef __cplusplus
extern "C" 
{
#endif 
#include "scanners.h"

    void create_sandbox();
    void destroy_sandbox();

    // Functions to sandbox engine and 
    cl_error_t invoke_cl_load(const char *path, struct cl_engine *engine, unsigned int *signo, unsigned int dboptions);
    cl_error_t invoke_cl_engine_addref(const struct cl_engine * engine);
    cl_error_t invoke_cl_engine_compile(const struct cl_engine * engine);
    cl_error_t invoke_cl_engine_free(const struct cl_engine * engine);
    struct cl_engine * invoke_cl_engine_new(void);
    cl_error_t invoke_cl_engine_set_num(const struct cl_engine * engine, enum cl_engine_field field, long long num);
    long long invoke_cl_engine_get_num(const struct cl_engine *engine, enum cl_engine_field field, int *err);
    cl_error_t invoke_cl_engine_set_str(const struct cl_engine *engine, enum cl_engine_field field, const char *str);

    // For transferring engine settings
    cl_error_t invoke_cl_engine_settings_apply(const struct cl_engine *engine, const struct cl_settings *settings);
    struct cl_settings *invoke_cl_engine_settings_copy(const struct cl_engine *engine);
    cl_error_t invoke_cl_engine_settings_free(const struct cl_settings *settings);
    
    // Setting engine's callback functions
/*
    void invoke_cl_engine_set_clcb_pre_cache(const struct cl_engine *engine, clcb_pre_cache callback);
    void invoke_cl_engine_set_clcb_pre_scan(const struct cl_engine *engine, clcb_pre_scan callback);
    void invoke_cl_engine_set_clcb_post_scan(const struct cl_engine *engine, clcb_post_scan callback);
    void invoke_cl_engine_set_clcb_virus_found(const struct cl_engine *engine, clcb_virus_found callback);
    void invoke_cl_engine_set_clcb_sigload(const struct cl_engine *engine, clcb_sigload callback, void *context);
    void invoke_cl_engine_set_clcb_hash(const struct cl_engine *engine, clcb_hash callback);
    void invoke_cl_engine_set_clcb_meta(const struct cl_engine *engine, clcb_meta callback);
    void invoke_cl_engine_set_clcb_file_props(const struct cl_engine *engine, clcb_file_props callback);
*/
    void invoke_cl_engine_set_clcb_pre_cache(const struct cl_engine *engine, void * callback);
    void invoke_cl_engine_set_clcb_pre_scan(const struct cl_engine *engine, void * callback);
    void invoke_cl_engine_set_clcb_post_scan(const struct cl_engine *engine, void * callback);
    void invoke_cl_engine_set_clcb_virus_found(const struct cl_engine *engine, void * callback);
    void invoke_cl_engine_set_clcb_sigload(const struct cl_engine *engine, void * callback, void *context);
    void invoke_cl_engine_set_clcb_hash(const struct cl_engine *engine, void * callback);
    void invoke_cl_engine_set_clcb_meta(const struct cl_engine *engine, void * callback);
    void invoke_cl_engine_set_clcb_file_props(const struct cl_engine *engine, void * callback);
    const char *invoke_cl_engine_get_str(const struct cl_engine *engine, enum cl_engine_field field, int *err);
    int invoke_mpool_getstats(const struct cl_engine *eng, size_t *used, size_t *total);

    // Only define rlbox's non-macros. 
    cl_error_t invoke_cl_scanfile_callback(const char *filename, const char **virname, unsigned long int *scanned, const struct cl_engine *engine, struct cl_scan_options *scanoptions, void *context);
    cl_error_t invoke_cl_scandesc_callback(int desc, const char *filename, const char **virname, unsigned long int *scanned, const struct cl_engine *engine, struct cl_scan_options *scanoptions, void *context);

#ifdef __cplusplus
}
#endif

#endif // RLBOX_SCANNER_H

