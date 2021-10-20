#include <iostream>
#include "clamav_rlbox.h"
#include "rlbox_clamscan_callbacks.h"


extern "C" {
#include "manager.h"
}

static tainted_clamav<cl_error_t> t_pre(
      rlbox_sandbox_clamav& s, 
      tainted_clamav<int> t_fd,
      tainted_clamav<const char*> t_type,
      tainted_clamav<void *> t_context) {

  struct metachain *c;
  struct clamscan_cb_data *d;

  UNUSEDPARAM(t_fd);
  UNUSEDPARAM(t_type);

  void * context = s.lookup_app_ptr(t_context);
  if (!(context))
      return CL_CLEAN;
  d = (struct clamscan_cb_data *)context;
  c = d->chain;
  if (c == NULL)
      return CL_CLEAN;

  c->level++;

  return CL_CLEAN;
}

void * getfptr_t_pre() {
    return (void *)&t_pre;
}

static tainted_clamav<cl_error_t> t_meta(
      rlbox_sandbox_clamav& s, 
      tainted_clamav<const char *> t_container_type,
      tainted_clamav<unsigned long> t_fsize_container,   
      tainted_clamav<const char *> t_filename, 
      tainted_clamav<unsigned long> t_fsize_real,        
      tainted_clamav<int> t_is_encrypted,                
      tainted_clamav<unsigned int> t_filepos_container,  
      tainted_clamav<void *> t_context)
{
    auto container_type = t_container_type.UNSAFE_unverified();
    unsigned long fsize_container = t_fsize_container.UNSAFE_unverified();
    auto filename = t_filename.UNSAFE_unverified();
    unsigned long fsize_real = t_fsize_real.UNSAFE_unverified();
    int is_encrypted = t_is_encrypted.UNSAFE_unverified();
    unsigned int filepos_container = t_filepos_container.UNSAFE_unverified();

    void * context = s.lookup_app_ptr(t_context);
    
    return meta(container_type, fsize_container, filename, fsize_real, is_encrypted, filepos_container, context);
}

void * getfptr_t_meta() {
    return (void *)&t_meta;
}

static tainted_clamav<cl_error_t> t_post(
      rlbox_sandbox_clamav& s, 
      tainted_clamav<int> t_fd, 
      tainted_clamav<int> t_result, 
      tainted_clamav<const char *> t_virname, 
      tainted_clamav<void *> t_context)
{
    int fd = t_fd.UNSAFE_unverified();
    int result = t_result.UNSAFE_unverified();
    auto virname = t_virname.UNSAFE_unverified();
    void * context = s.lookup_app_ptr(t_context);
    return post(fd, result, virname, context);
}

void * getfptr_t_post() {
    return (void *)&t_post;
}

static void t_clamscan_virus_found_cb(
      rlbox_sandbox_clamav& s, 
      tainted_clamav<int> t_fd, 
      tainted_clamav<const char *> t_virname, 
      tainted_clamav<void *> t_context)
{
    int fd = t_fd.UNSAFE_unverified();
    auto virname = t_virname.UNSAFE_unverified();
    void * context = s.lookup_app_ptr(t_context);
    clamscan_virus_found_cb(fd, virname, context);
}

void * getfptr_t_clamscan_virus_found_cb() {
    return (void *)&t_clamscan_virus_found_cb;
}
