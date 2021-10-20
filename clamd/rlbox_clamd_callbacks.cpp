#include <iostream>
#include "clamav_rlbox.h"
#include "rlbox_clamd_callbacks.h"

extern "C" {
#include "scanner.h"
}

#ifdef _WIN32

static tainted_clamav<int> t_svc_checkpoint(
      rlbox_sandbox_clamav& s, 
      tainted_clamav<const char *> t_type, 
      tainted_clamav<const char *> t_name, 
      tainted_clamav<unsigned int> t_custom, 
      tainted_clamav<void *> t_context)
{
    auto type = t_type.UNSAFE_unverified();
    auto name = t_name.UNSAFE_unverified();
    
    unsigned int custom = t_custom.UNSAFE_unverified();
    void * context = s.lookup_app_ptr(t_context);
    return svc_checkpoint(type, name, custom, context);
}

void * getfptr_t_svc_checkpoint() {
    return (void *)&t_svc_checkpoint;
}

#endif


static void t_clamd_virus_found_cb(
    rlbox_sandbox_clamav& s, 
    tainted_clamav<int> t_fd, 
    tainted_clamav<const char *> t_virname, 
    tainted_clamav<void *> t_ctx) 
{
    int fd = t_fd.UNSAFE_unverified();
    auto virname = t_virname.UNSAFE_unverified();
    
    void * ctx = s.lookup_app_ptr(t_ctx);

    clamd_virus_found_cb(fd, virname, ctx);
}

void * getfptr_t_clamd_virus_found_cb() {
    return (void *)&t_clamd_virus_found_cb;
}

static void t_hash_callback(
      rlbox_sandbox_clamav& s,
      tainted_clamav<int> t_fd,
      tainted_clamav<unsigned long long> t_size,
      tainted_clamav<const unsigned char *> t_md5,
      tainted_clamav<const char *> t_virname,
      tainted_clamav<void *> t_ctx)
{
    void * ctx = s.lookup_app_ptr(t_ctx);
    struct cb_context *c = static_cast<struct cb_context*>(ctx);
    UNUSEDPARAM(t_fd);
    UNUSEDPARAM(t_virname);

    if (!c)
        return;
    c->virsize = t_size.UNSAFE_unverified();
    strncpy(c->virhash, (const char *)t_md5.UNSAFE_unverified(), 32);
    c->virhash[32] = '\0';
}

void * getfptr_t_hash_callback() {
    return (void *)&t_hash_callback;
}