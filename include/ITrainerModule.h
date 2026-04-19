#pragma once

// C-compatible ABI. No C++ virtual dispatch — Rust FFI calls flat C symbols.
// Internal implementation may use any C++ it likes behind the opaque void* handle.

#ifdef _WIN32
#  define TRAINER_EXPORT __declspec(dllexport)
#else
#  define TRAINER_EXPORT __attribute__((visibility("default")))
#endif

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
TRAINER_EXPORT void*       trainer_create    ();
TRAINER_EXPORT void        trainer_destroy   (void* handle);
TRAINER_EXPORT int         trainer_initialize(void* handle);       // 1 = ok, 0 = fail
TRAINER_EXPORT void        trainer_shutdown  (void* handle);
TRAINER_EXPORT const char* trainer_get_name  (void* handle);       // static string, no alloc
TRAINER_EXPORT const char* trainer_get_version(void* handle);      // static string, no alloc

// ── Feature API — every trainer must export these seven ─────────────────────
TRAINER_EXPORT int                       trainer_get_feature_count  (void* handle);
TRAINER_EXPORT const TrainerFeatureInfo* trainer_get_feature_info   (void* handle, int index);
TRAINER_EXPORT int                       trainer_get_feature_enabled(void* handle, const char* id); // toggle: 0/1; one-shot: 0
TRAINER_EXPORT void                      trainer_set_feature_enabled(void* handle, const char* id, int enabled);
TRAINER_EXPORT void                      trainer_activate_feature   (void* handle, const char* id); // trigger one-shot
TRAINER_EXPORT void                      trainer_set_keybind        (void* handle, const char* id, int vk_code); // 0 = disabled
TRAINER_EXPORT int                       trainer_get_keybind        (void* handle, const char* id);

#ifdef __cplusplus
}
#endif
