// PowerWash Simulator Trainer
// Target: PowerWashSimulator.exe, IL2CPP module: GameAssembly.dll
//
// Pattern: GetEffectivenessAgainst
// 48 83 EC 28 81 FA 00 01 00 00 -> Function Start
// Shellcode: mov eax, 10000; cvtsi2ss xmm0, eax; ret

#include "ITrainerModule.h"
#include <windows.h>
#include <tlhelp32.h>
#include <vector>
#include <list>
#include <thread>
#include <atomic>
#include <cstdint>
#include <cstring>

static char g_lastError[256] = "";
static void SetLastErr(const char* msg) { strncpy(g_lastError, msg, sizeof(g_lastError) - 1); }

// ── Utilities ─────────────────────────────────────────────────────────────────

static DWORD FindPid(const wchar_t* exe) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32W pe{ sizeof(pe) };
    DWORD pid = 0;
    if (Process32FirstW(snap, &pe))
        do { if (_wcsicmp(pe.szExeFile, exe) == 0) { pid = pe.th32ProcessID; break; } }
        while (Process32NextW(snap, &pe));
    CloseHandle(snap);
    return pid;
}

static bool GetModuleInfo(DWORD pid, const wchar_t* mod, uintptr_t& base, size_t& sz) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
    if (snap == INVALID_HANDLE_VALUE) return false;
    MODULEENTRY32W me{ sizeof(me) };
    bool found = false;
    if (Module32FirstW(snap, &me))
        do {
            if (_wcsicmp(me.szModule, mod) == 0) {
                base = reinterpret_cast<uintptr_t>(me.modBaseAddr);
                sz = me.modBaseSize;
                found = true;
                break;
            }
        } while (Module32NextW(snap, &me));
    CloseHandle(snap);
    return found;
}

static bool MemWriteRaw(HANDLE hProc, uintptr_t addr, const void* data, size_t size) {
    DWORD old;
    VirtualProtectEx(hProc, (LPVOID)addr, size, PAGE_EXECUTE_READWRITE, &old);
    SIZE_T r;
    bool ok = WriteProcessMemory(hProc, (LPVOID)addr, data, size, &r);
    VirtualProtectEx(hProc, (LPVOID)addr, size, old, &old);
    return ok && r == size;
}

static uintptr_t AobFirst(HANDLE hProc, uintptr_t base, size_t sz, const uint8_t* pat, size_t len) {
    std::vector<uint8_t> buf(sz);
    SIZE_T r = 0;
    if (!ReadProcessMemory(hProc, (LPCVOID)base, buf.data(), sz, &r) || r == 0) return 0;
    for (size_t i = 0; i + len <= r; ++i)
        if (memcmp(buf.data() + i, pat, len) == 0) return base + i;
    return 0;
}

// ── Structures ────────────────────────────────────────────────────────────────

struct PatchSite {
    uintptr_t addr = 0;
    uint8_t   orig[10] = {};
    size_t    len = 10;
    bool      active = false;
};

struct Feature {
    TrainerFeatureInfo info;
    std::atomic<bool>  enabled{ false };
    std::atomic<int>   vk_code{ 0 };
    Feature(const char* id_, const char* n, const char* d, int tog, int vk)
        : info{ id_, n, d, tog, vk }, vk_code(vk) {}
};

// ── Trainer Class ─────────────────────────────────────────────────────────────

class PWSTrainer {
public:
    PWSTrainer() : m_running(false), m_hProc(nullptr) {
        m_features.emplace_back("instant_clean", "Instant Clean", "One-tap any dirt surface", 1, VK_F1);
        m_fInstantClean = &m_features.back();
    }

    ~PWSTrainer() { Shutdown(); }

    bool Initialize() {
    DWORD pid = FindPid(L"PowerWashSimulator.exe");
    if (!pid) {
        SetLastErr("Process not found - Start the game first.");
        return false;
    }

    m_hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!m_hProc) {
        SetLastErr("OpenProcess failed - Run as Admin.");
        return false;
    }

    uintptr_t base = 0; size_t sz = 0;
    if (!GetModuleInfo(pid, L"GameAssembly.dll", base, sz)) {
        SetLastErr("GameAssembly.dll not found. Wait for the level to load.");
        return false;
    }

    // New, more resilient pattern
    static const uint8_t PAT_CLEAN[] = { 0x48, 0x83, 0xEC, 0x28, 0x81, 0xFA };
    m_siteClean.addr = AobFirst(m_hProc, base, sz, PAT_CLEAN, sizeof(PAT_CLEAN));

    if (!m_siteClean.addr) {
        // Fallback: search for the second half of the nozzle logic if start is obscured
        static const uint8_t FALLBACK_PAT[] = { 0x81, 0xFA, 0x00, 0x01, 0x00, 0x00 };
        m_siteClean.addr = AobFirst(m_hProc, base, sz, FALLBACK_PAT, sizeof(FALLBACK_PAT));
        
        if (m_siteClean.addr) {
            m_siteClean.addr -= 4; // Move back to the start of the function (sub rsp, 28)
        }
    }

    if (!m_siteClean.addr) {
        SetLastErr("AOB Scan failed. Game version may be incompatible.");
        return false;
    }

    // Capture what was there to avoid crashing on toggle-off
    ReadProcessMemory(m_hProc, (LPCVOID)m_siteClean.addr, m_siteClean.orig, 10, nullptr);

    m_running = true;
    m_thread = std::thread(&PWSTrainer::Loop, this);
    return true;
}

    void Shutdown() {
        m_running = false;
        if (m_thread.joinable()) m_thread.join();
        if (m_hProc) {
            if (m_siteClean.active) RestoreSite(m_siteClean);
            CloseHandle(m_hProc);
            m_hProc = nullptr;
        }
    }

    const char* GetName()    const { return "PowerWash Simulator Trainer"; }
    const char* GetVersion() const { return "1.0.0"; }
    int GetFeatureCount()    const { return (int)m_features.size(); }

    const TrainerFeatureInfo* GetFeatureInfo(int idx) const {
        auto it = m_features.begin();
        std::advance(it, idx);
        return &it->info;
    }

    int GetFeatureEnabled(const char* id) const {
        for (const auto& f : m_features)
            if (strcmp(f.info.id, id) == 0) return f.enabled.load() ? 1 : 0;
        return 0;
    }

    void SetFeatureEnabled(const char* id, int enabled) {
        for (auto& f : m_features)
            if (strcmp(f.info.id, id) == 0) f.enabled = (enabled != 0);
    }

    void ActivateFeature(const char* id) {}

    void SetKeybind(const char* id, int vk) {
        for (auto& f : m_features)
            if (strcmp(f.info.id, id) == 0) f.vk_code = vk;
    }

    int GetKeybind(const char* id) const {
        for (const auto& f : m_features)
            if (strcmp(f.info.id, id) == 0) return f.vk_code.load();
        return 0;
    }

private:
    std::atomic<bool> m_running;
    HANDLE m_hProc;
    std::thread m_thread;
    std::list<Feature> m_features;
    Feature* m_fInstantClean = nullptr;
    PatchSite m_siteClean;

    void ApplyCleanPatch() {
        if (m_siteClean.active) return;
        // mov eax, 10000; cvtsi2ss xmm0, eax; ret (10 bytes total)
        uint8_t patch[] = { 0xB8, 0x10, 0x27, 0x00, 0x00, 0xF3, 0x0F, 0x2A, 0xC0, 0xC3 };
        MemWriteRaw(m_hProc, m_siteClean.addr, patch, 10);
        m_siteClean.active = true;
    }

    void RestoreSite(PatchSite& s) {
        if (!s.active) return;
        MemWriteRaw(m_hProc, s.addr, s.orig, s.len);
        s.active = false;
    }

    void Loop() {
        bool prevClean = false;
        while (m_running) {
            for (auto& f : m_features) {
                int vk = f.vk_code.load();
                if (vk && (GetAsyncKeyState(vk) & 1))
                    f.enabled = !f.enabled.load();
            }

            bool currentClean = m_fInstantClean->enabled.load();
            if (currentClean != prevClean) {
                if (currentClean) ApplyCleanPatch();
                else RestoreSite(m_siteClean);
                prevClean = currentClean;
            }
            Sleep(10);
        }
    }
};

// ── C ABI exports ─────────────────────────────────────────────────────────────

extern "C" {
    void* trainer_create() { return new PWSTrainer(); }
    void  trainer_destroy(void* h) { delete static_cast<PWSTrainer*>(h); }
    int   trainer_initialize(void* h) { return static_cast<PWSTrainer*>(h)->Initialize() ? 1 : 0; }
    void  trainer_shutdown(void* h) { static_cast<PWSTrainer*>(h)->Shutdown(); }
    const char* trainer_get_name(void* h) { return static_cast<PWSTrainer*>(h)->GetName(); }
    const char* trainer_get_version(void* h) { return static_cast<PWSTrainer*>(h)->GetVersion(); }
    int trainer_get_feature_count(void* h) { return static_cast<PWSTrainer*>(h)->GetFeatureCount(); }
    const TrainerFeatureInfo* trainer_get_feature_info(void* h, int idx) { return static_cast<PWSTrainer*>(h)->GetFeatureInfo(idx); }
    int trainer_get_feature_enabled(void* h, const char* id) { return static_cast<PWSTrainer*>(h)->GetFeatureEnabled(id); }
    void trainer_set_feature_enabled(void* h, const char* id, int en) { static_cast<PWSTrainer*>(h)->SetFeatureEnabled(id, en); }
    void trainer_activate_feature(void* h, const char* id) { static_cast<PWSTrainer*>(h)->ActivateFeature(id); }
    void trainer_set_keybind(void* h, const char* id, int vk) { static_cast<PWSTrainer*>(h)->SetKeybind(id, vk); }
    int trainer_get_keybind(void* h, const char* id) { return static_cast<PWSTrainer*>(h)->GetKeybind(id); }
    const char* trainer_get_last_error() { return g_lastError; }
}