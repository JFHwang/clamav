#ifndef CLAMAV_RLBOX
#define CLAMAV_RLBOX

#include "clamav_rlbox_types.h"

#define RLBOX_SINGLE_THREADED_INVOCATIONS

/*
// WASM SANDBOX
#include "rlbox_lucet_sandbox.hpp"
*/

// NOOP SANDBOX
#define RLBOX_USE_STATIC_CALLS() rlbox_noop_sandbox_lookup_symbol
#include "rlbox_noop_sandbox.hpp"


#include "rlbox.hpp"

#include "clamav.h"
#include "ScannerStructsForRLBox.h"
rlbox_load_structs_from_library(scanner);

#endif
