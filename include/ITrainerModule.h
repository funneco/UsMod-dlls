#pragma once

// C-compatible ABI. No C++ virtual dispatch — Rust FFI calls flat C symbols.
// Internal implementation may use any C++ it likes behind the opaque void* handle.

#ifdef __cplusplus
extern "C" {
#endif

// Feature descriptor — all strings are static (no alloc, valid for trainer lifetime).
typedef struct {
    const char* id;          // stable machine id, e.g. "lock_health"
    const char* name;        // display name shown in UI
    const char* description; // short description shown in UI
    int         is_toggle;   // 1 = on/off toggle, 0 = one-shot action
    int         default_vk;  // default Windows VK code (0 = no default)
} TrainerFeatureInfo;

// ── Core lifecycle — every trainer must export these six ────────────────────
void*       trainer_create    ();
void        trainer_destroy   (void* handle);
int         trainer_initialize(void* handle);       // 1 = ok, 0 = fail
void        trainer_shutdown  (void* handle);
const char* trainer_get_name  (void* handle);       // static string, no alloc
const char* trainer_get_version(void* handle);      // static string, no alloc

// ── Feature API — every trainer must export these seven ─────────────────────
int                       trainer_get_feature_count  (void* handle);
const TrainerFeatureInfo* trainer_get_feature_info   (void* handle, int index);
int                       trainer_get_feature_enabled(void* handle, const char* id); // toggle: 0/1; one-shot: 0
void                      trainer_set_feature_enabled(void* handle, const char* id, int enabled);
void                      trainer_activate_feature   (void* handle, const char* id); // trigger one-shot
void                      trainer_set_keybind        (void* handle, const char* id, int vk_code); // 0 = disabled
int                       trainer_get_keybind        (void* handle, const char* id);

#ifdef __cplusplus
}
#endif
