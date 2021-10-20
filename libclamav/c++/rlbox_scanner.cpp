#include <map>
#include <cstring>
#include <iostream>
#include "clamav_rlbox.h"
#include "rlbox_scanner.h"
#include "mpool.h"
#include <execinfo.h>

#ifdef _WIN32
#include "service.h"
#endif


rlbox_sandbox_clamav sandbox;


void create_sandbox() {
  sandbox.create_sandbox();
}

void destroy_sandbox() {
  sandbox.destroy_sandbox();
}

std::map<const struct cl_engine *, tainted_clamav<struct cl_engine *>> t_engines;
struct cl_engine * mapcounter = reinterpret_cast<struct cl_engine *>(NULL+1);
static void * genenginekey() {
  // TODO: This doesn't handle case when there are more than INT_MAX engine pointers. 
  //    Usually just 1 engine but may be worth revisiting. Will infinite loop.
  while(t_engines.count(const_cast<const struct cl_engine *>(mapcounter)) && mapcounter != NULL) {
    mapcounter = mapcounter + 1;
  }
  return mapcounter;
}

// Defined in readdb.h
cl_error_t invoke_cl_load(const char *path, struct cl_engine *engine, unsigned int *signo, unsigned int dboptions) {
  tainted_clamav<char *> t_path = nullptr;
  tainted_clamav<unsigned int *> t_signo = nullptr;

  if(path) {
    size_t path_len = strlen(path) + 1;
    t_path = sandbox.malloc_in_sandbox<char>(path_len);
    strncpy(t_path.unverified_safe_pointer_because(path_len, "Writing to sandbox"), path, path_len);
  }

  if(signo) {
    t_signo = sandbox.malloc_in_sandbox<unsigned int>();
    *t_signo = *signo;
  }

  cl_error_t result = sandbox.invoke_sandbox_function(cl_load, t_path, t_engines[engine], t_signo, dboptions).copy_and_verify([](cl_error_t err) {
    return err >= 0 && err <= CL_ELAST_ERROR ? err : CL_ELAST_ERROR;
  });

  if(t_signo) {
    *signo = *t_signo.UNSAFE_unverified();
  }

  if(t_path) sandbox.free_in_sandbox(t_path);
  if(t_signo) sandbox.free_in_sandbox(t_signo);
  return result;
}

int invoke_mpool_getstats(const struct cl_engine *engine, size_t *used, size_t *total) {
  auto t_used = sandbox.malloc_in_sandbox<size_t>();
  auto t_total = sandbox.malloc_in_sandbox<size_t>();
  int result = sandbox.invoke_sandbox_function(mpool_getstats, t_engines[engine], t_used, t_total).UNSAFE_unverified();
  *used = *t_used.UNSAFE_unverified();
  *total = *t_total.UNSAFE_unverified();
  sandbox.free_in_sandbox(t_used);
  sandbox.free_in_sandbox(t_total);
  return result;
}

cl_error_t invoke_cl_engine_addref(const struct cl_engine * engine) {
  return sandbox.invoke_sandbox_function(cl_engine_addref, t_engines[engine]).copy_and_verify([](cl_error_t err) {
    return err >= 0 && err <= CL_ELAST_ERROR ? err : CL_ELAST_ERROR;
  });
}

cl_error_t invoke_cl_engine_compile(const struct cl_engine *engine) {
  return sandbox.invoke_sandbox_function(cl_engine_compile, t_engines[engine]).copy_and_verify([](cl_error_t err) {
    return err >= 0 && err <= CL_ELAST_ERROR ? err : CL_ELAST_ERROR;
  });
}

cl_error_t invoke_cl_engine_free(const struct cl_engine * engine) {
  cl_error_t result = sandbox.invoke_sandbox_function(cl_engine_free, t_engines[engine]).copy_and_verify([](cl_error_t err) {
    return err >= 0 && err <= CL_ELAST_ERROR ? err : CL_ELAST_ERROR;
  });
  // TODO: Our list of engines may fill up since we're not erasing them from the map. 
  return result;
}


// Defined in others.h
struct cl_engine * invoke_cl_engine_new(void) {
  struct cl_engine * newptr = static_cast<struct cl_engine *>(genenginekey());
  t_engines[newptr] = sandbox.invoke_sandbox_function(cl_engine_new);
  return newptr;
}

cl_error_t invoke_cl_engine_set_num(const struct cl_engine * engine, enum cl_engine_field field, long long num) {
  return sandbox.invoke_sandbox_function(cl_engine_set_num, t_engines[engine], field, num).copy_and_verify([](cl_error_t err) {
    return err >= 0 && err <= CL_ELAST_ERROR ? err : CL_ELAST_ERROR;
  });
}

long long invoke_cl_engine_get_num(const struct cl_engine *engine, enum cl_engine_field field, int *err) {
  tainted_clamav<int *> t_err = nullptr;

  if(err) {
    t_err = sandbox.malloc_in_sandbox<int>();
    *t_err = *err;
  }

  // TODO: Verify return value and err value
  long long result = sandbox.invoke_sandbox_function(cl_engine_get_num, t_engines[engine], field, t_err).UNSAFE_unverified();

  if(t_err) {
    *err = *t_err.UNSAFE_unverified();
  }

  sandbox.free_in_sandbox(t_err);
  return result;
}

cl_error_t invoke_cl_engine_set_str(const struct cl_engine *engine, enum cl_engine_field field, const char *str) {
  tainted_clamav<char *> t_str = nullptr;

  if(str) {
    size_t str_len = strlen(str) + 1;
    t_str = sandbox.malloc_in_sandbox<char>(str_len);
    std::strncpy(t_str.unverified_safe_pointer_because(strlen(str), "writing to region"), str, str_len);
  }

  // TODO: Fix risky strlen
  cl_error_t result = sandbox.invoke_sandbox_function(cl_engine_set_str, t_engines[engine], field, t_str).copy_and_verify([](cl_error_t err) {
    return err >= 0 && err <= CL_ELAST_ERROR ? err : CL_ELAST_ERROR;
  });

  sandbox.free_in_sandbox(t_str);
  return result;
}


const char *invoke_cl_engine_get_str(const struct cl_engine *engine, enum cl_engine_field field, int *err)
{
  
  tainted_clamav<int *> t_err = nullptr;

  if(err) {
    t_err = sandbox.malloc_in_sandbox<int>();
    *t_err = *err;
  }

  const char * result = sandbox.invoke_sandbox_function(cl_engine_get_str, t_engines[engine], field, t_err).UNSAFE_unverified();

  if(t_err) {
    *err = *t_err.UNSAFE_unverified();
  }

  sandbox.free_in_sandbox(t_err);
  return result;
}


std::map<const struct cl_settings *, tainted_clamav<struct cl_settings *>> t_engine_settings;
struct cl_settings * settingsmapcounter = reinterpret_cast<struct cl_settings *>(NULL+1);
static void * gensettingskey() {
  // TODO: This doesn't handle case when there are more than INT_MAX engine pointers in a single thread
  while(t_engine_settings.count(const_cast<const struct cl_settings *>(settingsmapcounter)) && settingsmapcounter != NULL) {
    settingsmapcounter = settingsmapcounter + 1;
  }
  return settingsmapcounter;
}

cl_error_t invoke_cl_engine_settings_apply(const struct cl_engine *engine, const struct cl_settings *settings) {
  return sandbox.invoke_sandbox_function(cl_engine_settings_apply, t_engines[engine], t_engine_settings[settings]).copy_and_verify([](cl_error_t err) {
    return err >= 0 && err <= CL_ELAST_ERROR ? err : CL_ELAST_ERROR;
  });
}

struct cl_settings *invoke_cl_engine_settings_copy(const struct cl_engine *engine) {
  struct cl_settings * newptr = static_cast<struct cl_settings *>(gensettingskey());
  t_engine_settings[newptr] = sandbox.invoke_sandbox_function(cl_engine_settings_copy, t_engines[engine]);
  return newptr;
}

cl_error_t invoke_cl_engine_settings_free(const struct cl_settings *settings) {
  cl_error_t result = sandbox.invoke_sandbox_function(cl_engine_settings_free, t_engine_settings[settings]).copy_and_verify([](cl_error_t err) {
    return err >= 0 && err <= CL_ELAST_ERROR ? err : CL_ELAST_ERROR;
  });
  t_engine_settings.erase(settings);
  return result;
}

sandbox_callback_clamav<clcb_pre_cache> pre_cache_cb;
sandbox_callback_clamav<clcb_pre_scan> pre_scan_cb;
sandbox_callback_clamav<clcb_post_scan> post_scan_cb;
sandbox_callback_clamav<clcb_virus_found> virus_found_cb;
sandbox_callback_clamav<clcb_sigload> sigload_cb;
sandbox_callback_clamav<clcb_hash> hash_cb;
sandbox_callback_clamav<clcb_meta> meta_cb;
sandbox_callback_clamav<clcb_file_props> file_props_cb;


//void invoke_cl_engine_set_clcb_pre_cache(const struct cl_engine *engine, clcb_pre_cache callback)
void invoke_cl_engine_set_clcb_pre_cache(const struct cl_engine *engine, void * callback)
{
  pre_cache_cb = sandbox.register_callback((tainted_clamav<cl_error_t>(*)(
            rlbox_sandbox_clamav&, 
            tainted_clamav<int>, 
            tainted_clamav<const char*>, 
            tainted_clamav<void *>))callback);
  sandbox.invoke_sandbox_function(cl_engine_set_clcb_pre_cache, t_engines[engine], pre_cache_cb);
}

//void invoke_cl_engine_set_clcb_pre_scan(const struct cl_engine *engine, clcb_pre_scan callback)
void invoke_cl_engine_set_clcb_pre_scan(const struct cl_engine *engine, void * callback)
{
  pre_scan_cb = sandbox.register_callback((tainted_clamav<cl_error_t>(*)(
            rlbox_sandbox_clamav&, 
            tainted_clamav<int>,
            tainted_clamav<const char *>,
            tainted_clamav<void *>))callback);
  // This function is actually not used anywhere
  sandbox.invoke_sandbox_function(cl_engine_set_clcb_pre_scan, t_engines[engine], pre_scan_cb);
}

//void invoke_cl_engine_set_clcb_post_scan(const struct cl_engine *engine, clcb_post_scan callback)
void invoke_cl_engine_set_clcb_post_scan(const struct cl_engine *engine, void * callback)
{
  post_scan_cb = sandbox.register_callback((tainted_clamav<cl_error_t>(*)(
            rlbox_sandbox_clamav&, 
            tainted_clamav<int>,
            tainted_clamav<int>,
            tainted_clamav<const char*>,
            tainted_clamav<void *>))callback);
  sandbox.invoke_sandbox_function(cl_engine_set_clcb_post_scan, t_engines[engine], post_scan_cb);
}

//void invoke_cl_engine_set_clcb_virus_found(const struct cl_engine *engine, clcb_virus_found callback)
void invoke_cl_engine_set_clcb_virus_found(const struct cl_engine *engine, void * callback)
{
  virus_found_cb = sandbox.register_callback((void (*)(
            rlbox_sandbox_clamav&, 
            tainted_clamav<int>,
            tainted_clamav<const char*>,
            tainted_clamav<void *>))callback);

  sandbox.invoke_sandbox_function(cl_engine_set_clcb_virus_found, t_engines[engine], virus_found_cb);
}


//void invoke_cl_engine_set_clcb_sigload(const struct cl_engine *engine, clcb_sigload callback, void *context)
void invoke_cl_engine_set_clcb_sigload(const struct cl_engine *engine, void * callback, void *context)
{
  sigload_cb = sandbox.register_callback((tainted_clamav<int>(*)(
            rlbox_sandbox_clamav&, 
            tainted_clamav<const char *>,
            tainted_clamav<const char*>,
            tainted_clamav<unsigned int>,
            tainted_clamav<void *>))callback);
  app_pointer_clamav<void *> app_context = sandbox.get_app_pointer((void *)context);
  auto t_context = app_context.to_tainted();

  sandbox.invoke_sandbox_function(cl_engine_set_clcb_sigload, t_engines[engine], sigload_cb, t_context);
}

//void invoke_cl_engine_set_clcb_hash(const struct cl_engine *engine, clcb_hash callback)
void invoke_cl_engine_set_clcb_hash(const struct cl_engine *engine, void * callback)
{
  hash_cb = sandbox.register_callback((void (*)(
            rlbox_sandbox_clamav&, 
            tainted_clamav<int>,
            tainted_clamav<unsigned long long>,
            tainted_clamav<const unsigned char*>,
            tainted_clamav<const char *>,
            tainted_clamav<void *>))callback);
  sandbox.invoke_sandbox_function(cl_engine_set_clcb_hash, t_engines[engine], hash_cb);
}

//void invoke_cl_engine_set_clcb_meta(const struct cl_engine *engine, clcb_meta callback)
void invoke_cl_engine_set_clcb_meta(const struct cl_engine *engine, void * callback)
{
  meta_cb = sandbox.register_callback((tainted_clamav<cl_error_t>(*)(
            rlbox_sandbox_clamav&, 
            tainted_clamav<const char *>,
            tainted_clamav<unsigned long>,
            tainted_clamav<const char *>,
            tainted_clamav<unsigned long>,
            tainted_clamav<int>,
            tainted_clamav<unsigned int>,
            tainted_clamav<void *>))callback);
  sandbox.invoke_sandbox_function(cl_engine_set_clcb_meta, t_engines[engine], meta_cb);
}

// This function is never called.
//void invoke_cl_engine_set_clcb_file_props(const struct cl_engine *engine, clcb_file_props callback)
void invoke_cl_engine_set_clcb_file_props(const struct cl_engine *engine, void * callback)
{
  file_props_cb = sandbox.register_callback((tainted_clamav<int>(*)(
            rlbox_sandbox_clamav&, 
            tainted_clamav<const char *>,
            tainted_clamav<int>,
            tainted_clamav<void *>))callback);
  sandbox.invoke_sandbox_function(cl_engine_set_clcb_file_props, t_engines[engine], file_props_cb);
}

cl_error_t invoke_cl_scanfile_callback(const char *filename, const char **virname, unsigned long int *scanned, const struct cl_engine *engine, struct cl_scan_options *scanoptions, void *context)
{
  tainted_clamav<char *> t_filename = nullptr;
  tainted_clamav<const char **> t_virname = nullptr;
  tainted_clamav<char *> t_virname_contents = nullptr;
  tainted_clamav<unsigned long int *> t_scanned = nullptr;
  tainted_clamav<struct cl_scan_options *> t_scanoptions = nullptr;
  
  if(filename) {
    size_t filename_len = strlen(filename) + 1;
    t_filename = sandbox.malloc_in_sandbox<char>(filename_len);
    rlbox::memcpy(sandbox, t_filename, filename, filename_len);
  }

  if(virname) {
    t_virname = sandbox.malloc_in_sandbox<const char *>();
    if(!*virname) { *t_virname = nullptr; }
    else {
      size_t virname_contents_len = strlen(*virname) + 1; 
      t_virname_contents = sandbox.malloc_in_sandbox<char>(virname_contents_len);
      rlbox::memcpy(sandbox, t_virname_contents, *virname, virname_contents_len);
      *t_virname = t_virname_contents;
    }
  }

  if(scanned) {
    t_scanned = sandbox.malloc_in_sandbox<unsigned long int>();
    *t_scanned = *scanned;
  }
  
  if(scanoptions) {
    t_scanoptions = sandbox.malloc_in_sandbox<struct cl_scan_options>();
    rlbox::memcpy(sandbox, t_scanoptions, scanoptions, sizeof(struct cl_scan_options));
  }

  auto t_engine = t_engines[engine];

  // Since context is an opaque type, we use app_ptr and don't do any copying to sandbox.
  app_pointer_clamav<void *> app_context = sandbox.get_app_pointer((void *)context);
  auto t_context = app_context.to_tainted();

  cl_error_t err = sandbox.invoke_sandbox_function(cl_scanfile_callback, t_filename, t_virname, t_scanned, t_engine, t_scanoptions, t_context).copy_and_verify([](cl_error_t err) {
    return err >= 0 && err <= CL_ELAST_ERROR ? err : CL_ELAST_ERROR;
  });
  if(t_virname) { 
    if(*t_virname.UNSAFE_unverified()) {
      size_t virname_contents_len = strlen(*t_virname.UNSAFE_unverified()) + 1;
      // NOTE: Due to this malloc, *virname will need to be manually free'd eventually.
      char * virname_contents = (char *)malloc(virname_contents_len); 
      strncpy(virname_contents, *t_virname.UNSAFE_unverified(), virname_contents_len);
      *virname = virname_contents;
    }
  }
  if(t_scanned) *scanned = *t_scanned.UNSAFE_unverified();

  if(t_scanoptions) {
    *scanoptions = t_scanoptions.copy_and_verify([](std::unique_ptr<tainted_clamav<cl_scan_options>> t_scanoptions) {
      cl_scan_options result{};
      result.general = t_scanoptions->general.UNSAFE_unverified();
      result.parse = t_scanoptions->parse.UNSAFE_unverified();
      result.heuristic = t_scanoptions->heuristic.UNSAFE_unverified();
      result.mail = t_scanoptions->mail.UNSAFE_unverified();
      result.dev = t_scanoptions->dev.UNSAFE_unverified();

      return result;
    });
  }
  if(t_filename) sandbox.free_in_sandbox(t_filename);
  if(t_virname) sandbox.free_in_sandbox(t_virname);
  if(t_virname_contents) sandbox.free_in_sandbox(t_virname_contents);
  if(t_scanned) sandbox.free_in_sandbox(t_scanned);
  if(t_scanoptions) sandbox.free_in_sandbox(t_scanoptions);
  return err;
}

cl_error_t invoke_cl_scandesc_callback(int desc, const char *filename, const char **virname, unsigned long int *scanned, const struct cl_engine *engine, struct cl_scan_options *scanoptions, void * context)
{
  tainted_clamav<char *> t_filename = nullptr;
  tainted_clamav<const char **> t_virname = nullptr;
  tainted_clamav<char *> t_virname_contents = nullptr;
  tainted_clamav<unsigned long int *> t_scanned = nullptr;
  tainted_clamav<struct cl_scan_options *> t_scanoptions = nullptr;

  if(filename) {
    size_t filename_len = strlen(filename) + 1;
    t_filename = sandbox.malloc_in_sandbox<char>(filename_len);
    rlbox::memcpy(sandbox, t_filename, filename, filename_len);
  }

  if(virname) {
    t_virname = sandbox.malloc_in_sandbox<const char *>();

    if(!*virname) { *t_virname = nullptr; }
    else {
      size_t virname_contents_len = strlen(*virname) + 1; 
      t_virname_contents = sandbox.malloc_in_sandbox<char>(virname_contents_len);
      rlbox::memcpy(sandbox, t_virname_contents, *virname, virname_contents_len);
      *t_virname = t_virname_contents;
    }
  }

  if(scanned) {
    t_scanned = sandbox.malloc_in_sandbox<unsigned long int>();
    *t_scanned = *scanned;
  }
  
  if(scanoptions) {
    t_scanoptions = sandbox.malloc_in_sandbox<struct cl_scan_options>();
    rlbox::memcpy(sandbox, t_scanoptions, scanoptions, sizeof(struct cl_scan_options));
  }

  auto t_engine = t_engines[engine];

  // Since context is an opaque type, we use app_ptr and don't do any copying to sandbox.
  app_pointer_clamav<void *> app_context = sandbox.get_app_pointer((void *)context);
  auto t_context = app_context.to_tainted();

  cl_error_t err = sandbox.invoke_sandbox_function(cl_scandesc_callback, desc, t_filename, t_virname, t_scanned, t_engine, t_scanoptions, t_context).copy_and_verify([](cl_error_t err) {
    return err >= 0 && err <= CL_ELAST_ERROR ? err : CL_ELAST_ERROR;
  });
  
  if(t_virname) { 
    if(*t_virname.UNSAFE_unverified()) {
      size_t virname_contents_len = strlen(*t_virname.UNSAFE_unverified()) + 1;
      // NOTE: Due to this malloc, *virname will need to be manually free'd eventually.
      char * virname_contents = (char *)malloc(virname_contents_len); 
      strncpy(virname_contents, *t_virname.UNSAFE_unverified(), virname_contents_len);
      *virname = virname_contents;
    }
  }
  if(t_scanned) *scanned = *t_scanned.UNSAFE_unverified();

  // Need to copy and verify t_scanoptions and t_context
  *scanoptions = t_scanoptions.copy_and_verify([](std::unique_ptr<tainted_clamav<cl_scan_options>> t_scanoptions) {
    cl_scan_options result{};
    result.general = t_scanoptions->general.UNSAFE_unverified();
    result.parse = t_scanoptions->parse.UNSAFE_unverified();
    result.heuristic = t_scanoptions->heuristic.UNSAFE_unverified();
    result.mail = t_scanoptions->mail.UNSAFE_unverified();
    result.dev = t_scanoptions->dev.UNSAFE_unverified();

    return result;
  });

  if(t_filename) sandbox.free_in_sandbox(t_filename);
  if(t_virname) sandbox.free_in_sandbox(t_virname);
  if(t_virname_contents) sandbox.free_in_sandbox(t_virname_contents);
  if(t_scanned) sandbox.free_in_sandbox(t_scanned);
  if(t_scanoptions) sandbox.free_in_sandbox(t_scanoptions);

  return err;
}