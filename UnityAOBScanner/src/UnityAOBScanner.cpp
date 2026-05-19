#include <windows.h>
#include <tlhelp32.h>
#include <vector>
#include <list>
#include <thread>
#include <atomic>
#include <cstdint>
#include <cstring>

// ============================================================
//  Unity AOB Scanner Trainer
//  Based on WeMod TrainerLib patterns
//  Target module: GameAssembly.dll
// ============================================================

struct TrainerFeatureInfo {
    const char* id;
    const char* name;
    const char* description;
    int is_toggle;
    int default_vk;
};

// ─────────────────────────────────────────────────────────────
//  Unity Runtime Detection
//  Based on WeMod TrainerLib patterns (mono.dll, il2cpp, GameAssembly)
// ─────────────────────────────────────────────────────────────

enum class UnityRuntime { Unknown, Mono, IL2CPP };

struct UnityRuntimeInfo {
    UnityRuntime type = UnityRuntime::Unknown;
    uintptr_t monoBase = 0;
    uintptr_t gameAssemblyBase = 0;
    uintptr_t unityPlayerBase = 0;
    bool hasMonoAttach = false;
    bool hasIl2CppInit = false;
};

// ─────────────────────────────────────────────────────────────
//  Unity AOB Scanner Utilities (WeMod-style)
// ─────────────────────────────────────────────────────────────

namespace UnityAOB {
    // Process utilities
    static DWORD FindPid(const wchar_t* exe) {
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap == INVALID_HANDLE_VALUE) return 0;
        PROCESSENTRY32W pe{ sizeof(pe) };
        DWORD pid = 0;
        if (Process32FirstW(snap, &pe))
            do {
                if (_wcsicmp(pe.szExeFile, exe) == 0) { pid = pe.th32ProcessID; break; }
            } while (Process32NextW(snap, &pe));
        CloseHandle(snap);
        return pid;
    }

    static uintptr_t GetModuleBase(DWORD pid, const wchar_t* modName) {
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
        if (snap == INVALID_HANDLE_VALUE) return 0;
        MODULEENTRY32W me{ sizeof(me) };
        uintptr_t base = 0;
        if (Module32FirstW(snap, &me))
            do {
                if (_wcsicmp(me.szModule, modName) == 0) { base = (uintptr_t)me.modBaseAddr; break; }
            } while (Module32NextW(snap, &me));
        CloseHandle(snap);
        return base;
    }

    // Get all modules for a process (Unity detection)
    static std::vector<std::pair<std::wstring, uintptr_t>> GetProcessModules(DWORD pid) {
        std::vector<std::pair<std::wstring, uintptr_t>> modules;
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
        if (snap == INVALID_HANDLE_VALUE) return modules;
        MODULEENTRY32W me{ sizeof(me) };
        if (Module32FirstW(snap, &me)) {
            do {
                modules.emplace_back(me.szModule, (uintptr_t)me.modBaseAddr);
            } while (Module32NextW(snap, &me));
        }
        CloseHandle(snap);
        return modules;
    }

    // Detect Unity runtime type (Mono vs IL2CPP)
    static UnityRuntimeInfo DetectUnityRuntime(DWORD pid) {
        UnityRuntimeInfo info;
        auto modules = GetProcessModules(pid);
        
        for (const auto& [modName, base] : modules) {
            std::wstring lower = modName;
            for (auto& c : lower) c = towlower(c);
            
            if (lower.find(L"mono.dll") != std::wstring::npos) {
                info.monoBase = base;
                info.hasMonoAttach = true;
                info.type = UnityRuntime::Mono;
            }
            if (lower.find(L"gameassembly.dll") != std::wstring::npos) {
                info.gameAssemblyBase = base;
                if (info.type == UnityRuntime::Unknown) info.type = UnityRuntime::IL2CPP;
            }
            if (lower.find(L"unityplayer.dll") != std::wstring::npos) {
                info.unityPlayerBase = base;
            }
        }
        
        if (info.gameAssemblyBase && !info.hasMonoAttach) {
            info.type = UnityRuntime::IL2CPP;
        }
        
        return info;
    }

    // Memory utilities
    static bool MemWrite(HANDLE hProc, uintptr_t addr, const void* data, size_t size) {
        DWORD old;
        if (!VirtualProtectEx(hProc, (LPVOID)addr, size, PAGE_EXECUTE_READWRITE, &old)) return false;
        SIZE_T r;
        bool ok = WriteProcessMemory(hProc, (LPVOID)addr, data, size, &r);
        VirtualProtectEx(hProc, (LPVOID)addr, size, old, &old);
        return ok;
    }

    static bool MemRead(HANDLE hProc, uintptr_t addr, void* buf, size_t size) {
        SIZE_T r;
        return ReadProcessMemory(hProc, (LPCVOID)addr, buf, size, &r) && r == size;
    }

    // AOB Scan with wildcard support (0x00 = wildcard)
    static uintptr_t AobScan(HANDLE hProc, uintptr_t base, size_t sz,
                              const uint8_t* pat, size_t len) {
        std::vector<uint8_t> buf(sz);
        SIZE_T r = 0;
        if (!ReadProcessMemory(hProc, (LPCVOID)base, buf.data(), sz, &r)) return 0;
        for (size_t i = 0; i + len <= r; ++i) {
            bool match = true;
            for (size_t j = 0; j < len; j++)
                if (pat[j] != 0x00 && buf[i + j] != pat[j]) { match = false; break; }
            if (match) return base + i;
        }
        return 0;
    }

    // AOB scan across multiple modules (Unity-specific)
    static uintptr_t AobScanModule(HANDLE hProc, DWORD pid, const wchar_t* moduleName,
                                   const uint8_t* pat, size_t len, size_t scanSize = 0x3000000) {
        uintptr_t modBase = GetModuleBase(pid, moduleName);
        if (!modBase) return 0;
        return AobScan(hProc, modBase, scanSize, pat, len);
    }

    // Build a 14-byte absolute indirect JMP: FF 25 00000000 <8-byte addr>
    static void BuildAbsJmp(uint8_t out[14], uintptr_t target) {
        out[0] = 0xFF; out[1] = 0x25;
        out[2] = out[3] = out[4] = out[5] = 0x00;
        memcpy(&out[6], &target, 8);
    }

    // Allocate code cave in target process
    static uintptr_t AllocCave(HANDLE hProc, size_t size = 256) {
        return (uintptr_t)VirtualAllocEx(hProc, nullptr, size,
                                         MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    }

    // Free code cave
    static void FreeCave(HANDLE hProc, uintptr_t cave) {
        if (cave) VirtualFreeEx(hProc, (LPVOID)cave, 0, MEM_RELEASE);
    }
}

// ─────────────────────────────────────────────────────────────
//  Hook Helper Functions
// ─────────────────────────────────────────────────────────────

static void ApplyNop2(bool enable, HANDLE hProc, uintptr_t addr, const uint8_t orig[2]) {
    if (!addr) return;
    if (enable) { uint8_t n[2] = { 0x90, 0x90 }; UnityAOB::MemWrite(hProc, addr, n, 2); }
    else UnityAOB::MemWrite(hProc, addr, orig, 2);
}

static void ApplyNop3(bool enable, HANDLE hProc, uintptr_t addr, const uint8_t orig[3]) {
    if (!addr) return;
    if (enable) { uint8_t n[3] = { 0x90, 0x90, 0x90 }; UnityAOB::MemWrite(hProc, addr, n, 3); }
    else UnityAOB::MemWrite(hProc, addr, orig, 3);
}

static void ApplyHook5(bool enable, HANDLE hProc, uintptr_t addr, uintptr_t cave, const uint8_t orig[5]) {
    if (!addr || !cave) return;
    if (enable) {
        int32_t rel = (int32_t)(cave - addr - 5);
        uint8_t hook[5] = { 0xE9 }; memcpy(&hook[1], &rel, 4);
        UnityAOB::MemWrite(hProc, addr, hook, 5);
    } else UnityAOB::MemWrite(hProc, addr, orig, 5);
}

// ─────────────────────────────────────────────────────────────
//  Feature
// ─────────────────────────────────────────────────────────────

struct Feature {
    TrainerFeatureInfo info;
    std::atomic<bool> enabled{ false };
    std::atomic<int> vk_code{ 0 };
    Feature(const char* i, const char* n, const char* d, int tog, int vk)
        : info{ i, n, d, tog, vk }, vk_code(vk) {}
};

// ─────────────────────────────────────────────────────────────
//  UnityAOBScannerTrainer
//  Based on WeMod TrainerLib patterns for Unity game detection
// ─────────────────────────────────────────────────────────────

class UnityAOBScannerTrainer {
public:
    HANDLE m_hProc = nullptr;
    std::atomic<bool> m_running{ false };
    std::thread m_thread;
    std::list<Feature> m_features;

    // Module info
    DWORD m_pid = 0;
    uintptr_t m_moduleBase = 0;
    UnityRuntimeInfo m_runtimeInfo;  // WeMod-style runtime detection

    // Hook storage - generic array for Unity game hooks
    struct UnityHook {
        uintptr_t addr = 0;
        uint8_t orig[14] = {};
        uintptr_t cave = 0;
        uint8_t* flagMem = nullptr;
        int hookSize = 0;
    };
    std::vector<UnityHook> m_hooks;

    // Unity common AOB patterns (WeMod-style)
    // These patterns are common across Unity games for money/cash manipulation
    struct UnityAOBPattern {
        const char* name;
        uint8_t pattern[16];
        size_t len;
        uintptr_t addr = 0;
        uint8_t orig[14] = {};
        uintptr_t cave = 0;
    };
    std::vector<UnityAOBPattern> m_patterns;

    UnityAOBScannerTrainer() {
        // Default Unity hooks - can be extended per game
        m_features.emplace_back("unity_hook_1", "Unity Hook 1", "Generic Unity game hook", 1, VK_F1);
        m_features.emplace_back("unity_hook_2", "Unity Hook 2", "Generic Unity game hook", 1, VK_F2);
        
        // Common Unity AOB patterns for money manipulation (based on prompt.txt patterns)
        // Pattern: F3 0F 58 49 30 0F 57 (Cash_AOB - addss xmm1,[rcx+30])
        UnityAOBPattern cashPattern = {"Cash_AOB", {0xF3,0x0F,0x58,0x49,0x30,0x0F,0x57}, 7};
        m_patterns.push_back(cashPattern);
        
        // Pattern: F3 0F 10 81 ?? ?? 00 00 45 33 C9 45 33 C0 33 D2 (Balans_AOB - movss xmm0,[rcx+offset])
        UnityAOBPattern bankPattern = {"Bank_AOB", {0xF3,0x0F,0x10,0x81,0x00,0x00,0x00,0x00,0x45,0x33,0xC9,0x45,0x33,0xC0,0x33,0xD2}, 16};
        m_patterns.push_back(bankPattern);
        
        // Pattern: 01 BB ?? ?? 00 00 BA 07 00 00 00 (EXP_AOB - add ebx,edi/imul)
        UnityAOBPattern expPattern = {"EXP_AOB", {0x01,0xBB,0x00,0x00,0x00,0x00,0xBA,0x07,0x00,0x00,0x00}, 11};
        m_patterns.push_back(expPattern);
    }

    bool Initialize() {
        // Detect Unity game process - WeMod style
        // Look for processes with GameAssembly.dll (IL2CPP) or mono.dll (Mono)
        m_pid = FindUnityProcess();
        if (!m_pid) return false;
        
        m_hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, m_pid);
        if (!m_hProc) return false;

        // Detect runtime type (Mono vs IL2CPP) - WeMod pattern
        m_runtimeInfo = UnityAOB::DetectUnityRuntime(m_pid);
        
        if (m_runtimeInfo.type == UnityRuntime::IL2CPP) {
            m_moduleBase = UnityAOB::GetModuleBase(m_pid, L"GameAssembly.dll");
        } else if (m_runtimeInfo.type == UnityRuntime::Mono) {
            m_moduleBase = UnityAOB::GetModuleBase(m_pid, L"mono.dll");
        }
        
        if (!m_moduleBase) return false;

        // Scan for Unity AOB patterns (WeMod-style)
        constexpr size_t SCAN_SIZE = 0x5000000;
        for (auto& pat : m_patterns) {
            pat.addr = UnityAOB::AobScan(m_hProc, m_moduleBase, SCAN_SIZE, pat.pattern, pat.len);
            if (pat.addr) {
                // Read original bytes
                UnityAOB::MemRead(m_hProc, pat.addr, pat.orig, 14);
                // Allocate cave for hook
                pat.cave = UnityAOB::AllocCave(m_hProc, 256);
            }
        }

        m_running = true;
        m_thread = std::thread(&UnityAOBScannerTrainer::Loop, this);
        return true;
    }

private:
    DWORD FindUnityProcess() {
        // WeMod pattern: Look for GameAssembly.dll or mono.dll modules
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap == INVALID_HANDLE_VALUE) return 0;
        
        PROCESSENTRY32W pe{ sizeof(pe) };
        DWORD pid = 0;
        
        if (Process32FirstW(snap, &pe)) {
            do {
                // Skip system processes
                if (pe.th32ProcessID <= 4) continue;
                
                HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pe.th32ProcessID);
                if (hProc) {
                    // Check for GameAssembly.dll (IL2CPP Unity)
                    if (UnityAOB::GetModuleBase(pe.th32ProcessID, L"GameAssembly.dll")) {
                        pid = pe.th32ProcessID;
                        CloseHandle(hProc);
                        break;
                    }
                    // Check for mono.dll (Mono Unity)
                    if (UnityAOB::GetModuleBase(pe.th32ProcessID, L"mono.dll")) {
                        pid = pe.th32ProcessID;
                        CloseHandle(hProc);
                        break;
                    }
                    // Check for UnityPlayer.dll
                    if (UnityAOB::GetModuleBase(pe.th32ProcessID, L"UnityPlayer.dll")) {
                        pid = pe.th32ProcessID;
                        CloseHandle(hProc);
                        break;
                    }
                    CloseHandle(hProc);
                }
            } while (Process32NextW(snap, &pe));
        }
        CloseHandle(snap);
        return pid;
    }

    void Loop() {
        while (m_running) {
            for (auto& f : m_features) {
                int vk = f.vk_code.load();
                if (vk && (GetAsyncKeyState(vk) & 1)) f.enabled = !f.enabled;
            }
            Sleep(10);
        }
    }

    void Shutdown() {
        m_running = false;
        if (m_thread.joinable()) m_thread.join();
        
        // Free allocated caves for patterns
        for (auto& pat : m_patterns) {
            if (pat.cave) UnityAOB::FreeCave(m_hProc, pat.cave);
        }
        
        if (m_hProc) { CloseHandle(m_hProc); m_hProc = nullptr; }
    }

    int GetFeatureCount() { return (int)m_features.size(); }
    const TrainerFeatureInfo* GetFeatureInfo(int idx) {
        auto it = m_features.begin(); std::advance(it, idx); return &it->info;
    }
    int GetFeatureEnabled(const char* id) {
        for (auto& f : m_features) if (strcmp(f.info.id, id) == 0) return f.enabled ? 1 : 0; return 0;
    }
    void SetFeatureEnabled(const char* id, int en) {
        for (auto& f : m_features) if (strcmp(f.info.id, id) == 0) f.enabled = (en != 0);
    }
    void ActivateFeature(const char* id) {}
    void SetKeybind(const char* id, int vk) {
        for (auto& f : m_features) if (strcmp(f.info.id, id) == 0) f.vk_code = vk;
    }
    int GetKeybind(const char* id) {
        for (auto& f : m_features) if (strcmp(f.info.id, id) == 0) return f.vk_code.load(); return 0;
    }
    const char* GetName() { return "Unity AOB Scanner"; }
    const char* GetVersion() { return "1.0.0"; }
};

// ─────────────────────────────────────────────────────────────
//  Exported C API
// ─────────────────────────────────────────────────────────────
extern "C" {
    __declspec(dllexport) void* trainer_create() { return new UnityAOBScannerTrainer(); }
    __declspec(dllexport) void  trainer_destroy(void* h) { delete static_cast<UnityAOBScannerTrainer*>(h); }
    __declspec(dllexport) int   trainer_initialize(void* h) { return static_cast<UnityAOBScannerTrainer*>(h)->Initialize() ? 1 : 0; }
    __declspec(dllexport) void  trainer_shutdown(void* h) { static_cast<UnityAOBScannerTrainer*>(h)->Shutdown(); }
    __declspec(dllexport) const char* trainer_get_name(void* h) { return static_cast<UnityAOBScannerTrainer*>(h)->GetName(); }
    __declspec(dllexport) const char* trainer_get_version(void* h) { return static_cast<UnityAOBScannerTrainer*>(h)->GetVersion(); }
    __declspec(dllexport) int trainer_get_feature_count(void* h) { return static_cast<UnityAOBScannerTrainer*>(h)->GetFeatureCount(); }
    __declspec(dllexport) const TrainerFeatureInfo* trainer_get_feature_info(void* h, int idx) { return static_cast<UnityAOBScannerTrainer*>(h)->GetFeatureInfo(idx); }
    __declspec(dllexport) int trainer_get_feature_enabled(void* h, const char* id) { return static_cast<UnityAOBScannerTrainer*>(h)->GetFeatureEnabled(id); }
    __declspec(dllexport) void trainer_set_feature_enabled(void* h, const char* id, int en) { static_cast<UnityAOBScannerTrainer*>(h)->SetFeatureEnabled(id, en); }
    __declspec(dllexport) void trainer_activate_feature(void* h, const char* id) { static_cast<UnityAOBScannerTrainer*>(h)->ActivateFeature(id); }
    __declspec(dllexport) void trainer_set_keybind(void* h, const char* id, int vk) { static_cast<UnityAOBScannerTrainer*>(h)->SetKeybind(id, vk); }
    __declspec(dllexport) int trainer_get_keybind(void* h, const char* id) { return static_cast<UnityAOBScannerTrainer*>(h)->GetKeybind(id); }
    __declspec(dllexport) const char* trainer_get_last_error() { return ""; }
}