#pragma once

// C-compatible ABI. No C++ virtual dispatch — Rust FFI calls flat C symbols.
// Internal implementation may use any C++ it likes behind the opaque void* handle.

#ifdef __cplusplus
extern "C" {
#endif

// Every trainer DLL MUST export all six symbols below with exact signatures.
void*       trainer_create    ();                  // allocate + construct trainer
void        trainer_destroy   (void* handle);      // destruct + free (call after shutdown)
int         trainer_initialize(void* handle);      // 1 = ok, 0 = fail (game not running etc.)
void        trainer_shutdown  (void* handle);      // stop hotkey loop, release game handle
const char* trainer_get_name  (void* handle);      // static string, no alloc
const char* trainer_get_version(void* handle);     // static string, no alloc

#ifdef __cplusplus
}
#endif
