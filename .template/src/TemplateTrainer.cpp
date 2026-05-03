#include <windows.h>
#include <tlhelp32.h>
#include <vector>
#include <list>
#include <thread>
#include <atomic>
#include <cstdint>
#include <cstring>

// ============================================================
// TODO: Rename this file and class to match your game.
//       Search/replace "Template" -> "MyGame" throughout.
// ============================================================

struct TrainerFeatureInfo {
    const char* id;
    const char* name;
    const char* description;
    int is_toggle;  // 1 = toggle, 0 = one-shot
    int hotkey;
};

// --- Utilities (no changes needed) ---

static DWORD FindPid(const wchar_t* exe) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32W pe{ sizeof(pe) };
    DWORD pid = 0;
    if (Process32FirstW(snap, &pe))
        do { if (_wcsicmp(pe.szExeFile, exe) == 0) { pid = pe.th32ProcessID; break; } } while (Process32NextW(snap, &pe));
    CloseHandle(snap);
    return pid;
}

static uintptr_t GetModuleBase(DWORD pid, const wchar_t* modName) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    MODULEENTRY32W me{ sizeof(me) };
    uintptr_t base = 0;
    if (Module32FirstW(snap, &me))
        do { if (_wcsicmp(me.szModule, modName) == 0) { base = (uintptr_t)me.modBaseAddr; break; } } while (Module32NextW(snap, &me));
    CloseHandle(snap);
    return base;
}

static bool MemWrite(HANDLE hProc, uintptr_t addr, const void* data, size_t size) {
    DWORD old;
    if (!VirtualProtectEx(hProc, (LPVOID)addr, size, PAGE_EXECUTE_READWRITE, &old)) return false;
    SIZE_T r;
    bool ok = WriteProcessMemory(hProc, (LPVOID)addr, data, size, &r);
    VirtualProtectEx(hProc, (LPVOID)addr, size, old, &old);
    return ok;
}

// pat: use 0x00 as wildcard byte
static uintptr_t AobScan(HANDLE hProc, uintptr_t base, size_t sz, const uint8_t* pat, size_t len) {
    std::vector<uint8_t> buf(sz);
    SIZE_T r = 0;
    if (!ReadProcessMemory(hProc, (LPCVOID)base, buf.data(), sz, &r)) return 0;
    for (size_t i = 0; i + len <= r; ++i) {
        bool match = true;
        for (size_t j = 0; j < len; j++) {
            if (pat[j] != 0x00 && buf[i + j] != pat[j]) { match = false; break; }
        }
        if (match) return base + i;
    }
    return 0;
}

// --- Feature ---

struct Feature {
    TrainerFeatureInfo info;
    std::atomic<bool> enabled{ false };
    std::atomic<int> vk_code{ 0 };
    Feature(const char* i, const char* n, const char* d, int tog, int vk)
        : info{ i, n, d, tog, vk }, vk_code(vk) {}
};

// --- Trainer class ---

class TemplateTrainer {
public:
    HANDLE m_hProc = nullptr;
    std::atomic<bool> m_running{ false };
    std::thread m_thread;
    std::list<Feature> m_features;

    // --- TODO: Declare per-feature state ---
    //
    // Pattern A — simple memory patch:
    //   uintptr_t addrFeatureA = 0;
    //   uint8_t   origFeatureA[N] = { 0 };
    //
    // Pattern B — AOB + code cave hook:
    //   uintptr_t addrFeatureB = 0;
    //   uint8_t   origFeatureB[14] = { 0 };  // 14 bytes for abs jmp
    //   uintptr_t caveFeatureB = 0;

    TemplateTrainer() {
        // TODO: Register your features here.
        //   Args: id, display name, description, is_toggle (1/0), default VK hotkey
        //
        // Toggle example:
        //   m_features.emplace_back("feature_a", "Feature A", "What it does", 1, VK_F1);
        //
        // One-shot example:
        //   m_features.emplace_back("feature_b", "Feature B", "What it does", 0, VK_F2);
    }

    bool Initialize() {
        // TODO: Replace with your game's exe name
        DWORD pid = FindPid(L"Game.exe");
        if (!pid) return false;

        m_hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
        if (!m_hProc) return false;

        // TODO: Replace with the module that contains your target code.
        //   Unity/IL2CPP games typically use "GameAssembly.dll".
        //   Unreal Engine games use "Game-Win64-Shipping.exe" (base module).
        uintptr_t moduleBase = GetModuleBase(pid, L"GameAssembly.dll");
        if (!moduleBase) return false;

        // --- Pattern A: Simple memory patch ---
        // Find target address, save original bytes.
        //
        //   addrFeatureA = moduleBase + 0xDEADBEEF;  // TODO: your static offset
        //   ReadProcessMemory(m_hProc, (LPCVOID)addrFeatureA, origFeatureA, sizeof(origFeatureA), nullptr);

        // --- Pattern B: AOB scan + code cave hook ---
        // Locate instruction by unique byte pattern, allocate cave, write trampoline.
        //
        //   uint8_t pat[] = { 0xF3, 0x0F, 0x11, 0x00, 0x00 };  // TODO: your pattern, 0x00 = wildcard
        //   addrFeatureB = AobScan(m_hProc, moduleBase, 0x3000000, pat, sizeof(pat));
        //   if (addrFeatureB) {
        //       ReadProcessMemory(m_hProc, (LPCVOID)addrFeatureB, origFeatureB, 14, nullptr);
        //       caveFeatureB = (uintptr_t)VirtualAllocEx(m_hProc, nullptr, 1024,
        //                           MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        //
        //       // Build cave code:
        //       //   [modified instruction(s)]
        //       //   [jmp back to addrFeatureB + hook_size]
        //       //
        //       // Write cave, then patch addrFeatureB with abs jmp to cave when enabled.
        //   }

        m_running = true;
        m_thread = std::thread(&TemplateTrainer::Loop, this);
        return true;
    }

    void Loop() {
        // Per-feature previous-state trackers for edge detection
        // bool pA = false, pB = false;

        while (m_running) {
            // Hotkey polling
            for (auto& f : m_features) {
                int vk = f.vk_code.load();
                if (vk && (GetAsyncKeyState(vk) & 1)) f.enabled = !f.enabled;
            }

            auto it = m_features.begin();

            // --- TODO: Apply / revert each feature on state change ---
            //
            // Pattern A — memory patch:
            //   if (it->enabled != pA) {
            //       if (it->enabled) {
            //           uint8_t patch[] = { 0x90, 0x90, ... };  // TODO: your patch bytes
            //           MemWrite(m_hProc, addrFeatureA, patch, sizeof(patch));
            //       } else {
            //           MemWrite(m_hProc, addrFeatureA, origFeatureA, sizeof(origFeatureA));
            //       }
            //       pA = it->enabled;
            //   }
            //   ++it;
            //
            // Pattern B — code cave hook (14-byte absolute jmp):
            //   if (it->enabled != pB && addrFeatureB) {
            //       if (it->enabled) {
            //           uint8_t hook[14] = { 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00 };
            //           memcpy(&hook[6], &caveFeatureB, 8);
            //           MemWrite(m_hProc, addrFeatureB, hook, 14);
            //       } else {
            //           MemWrite(m_hProc, addrFeatureB, origFeatureB, 14);
            //       }
            //       pB = it->enabled;
            //   }
            //   ++it;

            Sleep(10);
        }
    }

    void Shutdown() {
        m_running = false;
        if (m_thread.joinable()) m_thread.join();
    }

    int GetFeatureCount() { return (int)m_features.size(); }

    const TrainerFeatureInfo* GetFeatureInfo(int idx) {
        auto it = m_features.begin();
        std::advance(it, idx);
        return &it->info;
    }

    int GetFeatureEnabled(const char* id) {
        for (auto& f : m_features)
            if (strcmp(f.info.id, id) == 0) return f.enabled ? 1 : 0;
        return 0;
    }

    void SetFeatureEnabled(const char* id, int en) {
        for (auto& f : m_features)
            if (strcmp(f.info.id, id) == 0) f.enabled = (en != 0);
    }

    void ActivateFeature(const char* id) {
        // TODO: for one-shot features, implement the action here
    }

    void SetKeybind(const char* id, int vk) {
        for (auto& f : m_features)
            if (strcmp(f.info.id, id) == 0) f.vk_code = vk;
    }

    int GetKeybind(const char* id) {
        for (auto& f : m_features)
            if (strcmp(f.info.id, id) == 0) return f.vk_code.load();
        return 0;
    }

    // TODO: Update name/version strings
    const char* GetName()    { return "Template Trainer"; }
    const char* GetVersion() { return "1.0.0"; }
};

// --- Exported C API (do not rename these — host expects exact symbols) ---

extern "C" {
    __declspec(dllexport) void*       trainer_create()                                    { return new TemplateTrainer(); }
    __declspec(dllexport) void        trainer_destroy(void* h)                            { delete static_cast<TemplateTrainer*>(h); }
    __declspec(dllexport) int         trainer_initialize(void* h)                         { return static_cast<TemplateTrainer*>(h)->Initialize() ? 1 : 0; }
    __declspec(dllexport) void        trainer_shutdown(void* h)                           { static_cast<TemplateTrainer*>(h)->Shutdown(); }
    __declspec(dllexport) const char* trainer_get_name(void* h)                           { return static_cast<TemplateTrainer*>(h)->GetName(); }
    __declspec(dllexport) const char* trainer_get_version(void* h)                        { return static_cast<TemplateTrainer*>(h)->GetVersion(); }
    __declspec(dllexport) int         trainer_get_feature_count(void* h)                  { return static_cast<TemplateTrainer*>(h)->GetFeatureCount(); }
    __declspec(dllexport) const TrainerFeatureInfo* trainer_get_feature_info(void* h, int idx) { return static_cast<TemplateTrainer*>(h)->GetFeatureInfo(idx); }
    __declspec(dllexport) int         trainer_get_feature_enabled(void* h, const char* id){ return static_cast<TemplateTrainer*>(h)->GetFeatureEnabled(id); }
    __declspec(dllexport) void        trainer_set_feature_enabled(void* h, const char* id, int en) { static_cast<TemplateTrainer*>(h)->SetFeatureEnabled(id, en); }
    __declspec(dllexport) void        trainer_activate_feature(void* h, const char* id)   { static_cast<TemplateTrainer*>(h)->ActivateFeature(id); }
    __declspec(dllexport) void        trainer_set_keybind(void* h, const char* id, int vk){ static_cast<TemplateTrainer*>(h)->SetKeybind(id, vk); }
    __declspec(dllexport) int         trainer_get_keybind(void* h, const char* id)        { return static_cast<TemplateTrainer*>(h)->GetKeybind(id); }
    __declspec(dllexport) const char* trainer_get_last_error()                            { return ""; }
}
