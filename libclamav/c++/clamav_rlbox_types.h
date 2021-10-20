/* -*- Mode: C++; tab-width: 20; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef CLAMAV_RLBOX_TYPES
#define CLAMAV_RLBOX_TYPES

#include "rlbox_types.hpp"

/*
// WASM SANDBOX
namespace rlbox {
class rlbox_lucet_sandbox;
}
using rlbox_ogg_sandbox_type = rlbox::rlbox_lucet_sandbox;
*/

// NOOP SANDBOX
using rlbox_clamav_sandbox_type = rlbox::rlbox_noop_sandbox;


using rlbox_sandbox_clamav = rlbox::rlbox_sandbox<rlbox_clamav_sandbox_type>;
template <typename T>
using sandbox_callback_clamav = rlbox::sandbox_callback<T, rlbox_clamav_sandbox_type>;
template <typename T>
using app_pointer_clamav = rlbox::app_pointer<T, rlbox_clamav_sandbox_type>;
template <typename T>
using tainted_clamav = rlbox::tainted<T, rlbox_clamav_sandbox_type>;
template <typename T>
using tainted_opaque_clamav = rlbox::tainted_opaque<T, rlbox_clamav_sandbox_type>;
template <typename T>
using tainted_volatile_clamav = rlbox::tainted_volatile<T, rlbox_clamav_sandbox_type>;
using rlbox::tainted_boolean_hint;

#endif



