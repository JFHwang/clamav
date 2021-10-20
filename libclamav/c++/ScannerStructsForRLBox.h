#ifndef ScannerStructsForRLBox_h__
#define ScannerStructsForRLBox_h__

#if defined(__clang__)
#  pragma clang diagnostic push
#  pragma clang diagnostic ignored "-Wgnu-zero-variadic-macro-arguments"
#elif defined(__GNUC__) || defined(__GNUG__)
// Can't turn off the variadic macro warning emitted from -pedantic
#  pragma GCC system_header
#elif defined(_MSC_VER)
// Doesn't seem to emit the warning
#else
// Don't know the compiler... just let it go through
#endif

#define sandbox_fields_reflection_scanner_class_cl_scan_options(f, g, ...)  \
  f(int  , general   , FIELD_NORMAL, ##__VA_ARGS__) g()  \
  f(int  , parse     , FIELD_NORMAL, ##__VA_ARGS__) g()  \
  f(int  , heuristic , FIELD_NORMAL, ##__VA_ARGS__) g()  \
  f(int  , mail      , FIELD_NORMAL, ##__VA_ARGS__) g()  \
  f(int  , dev       , FIELD_NORMAL, ##__VA_ARGS__) g()

#define sandbox_fields_reflection_scanner_allClasses(f, ...) \
  f(cl_scan_options       , scanner, ##__VA_ARGS__) 



#if defined(__clang__)
#  pragma clang diagnostic pop
#elif defined(__GNUC__) || defined(__GNUG__)
#elif defined(_MSC_VER)
#else
#endif

#endif
