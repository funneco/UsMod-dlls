#include "ITrainerModule.h"
#include <windows.h>
#include <tlhelp32.h>
#include <vector>
#include <list>
#include <thread>
#include <atomic>
#include <cstdint>

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

static uintptr_t GetModuleBase(DWORD pid, const wchar_t* modName) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    MODULEENTRY32W me{ sizeof(me) };
    uintptr_t base = 0;
    if (Module32FirstW(snap, &me))
        do {
            if (_wcsicmp(me.szModule, modName) == 0) {
                base = reinterpret_cast<uintptr_t>(me.modBaseAddr);
                break;
            }
        } while (Module32NextW(snap, &me));
    CloseHandle(snap);
    return base;
}

static bool MemWriteRaw(HANDLE hProc, uintptr_t addr, const void* data, size_t size) {
    DWORD old;
    if (!VirtualProtectEx(hProc, (LPVOID)addr, size, PAGE_EXECUTE_READWRITE, &old)) return false;
    SIZE_T r;
    bool ok = WriteProcessMemory(hProc, (LPVOID)addr, data, size, &r);
    VirtualProtectEx(hProc, (LPVOID)addr, size, old, &old);
    FlushInstructionCache(hProc, (LPVOID)addr, size);
    return ok && r == size;
}

struct PatchSite {
    uintptr_t addr = 0;
    uint8_t   orig[12] = {};
    size_t    len = 12;
    bool      active = false;
};

struct Feature {
    TrainerFeatureInfo info;
    std::atomic<bool>  enabled{ false };
    std::atomic<int>   vk_code{ 0 };
    Feature(const char* id_, const char* n, const char* d, int tog, int vk)
        : info{ id_, n, d, tog, vk }, vk_code(vk) {}
};

class PWSTrainer {
public:
    PWSTrainer() : m_running(false), m_hProc(nullptr) {
        m_features.emplace_back("instant_clean", "Instant Clean", "Set effectiveness to 10k", 1, VK_F1);
        m_fInstantClean = &m_features.back();
    }

    ~PWSTrainer() { Shutdown(); }

    bool Initialize() {
        DWORD pid = FindPid(L"PowerWashSimulator.exe");
        if (!pid) { SetLastErr("Process not found."); return false; }

        m_hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
        if (!m_hProc) { SetLastErr("Admin access denied."); return false; }

        uintptr_t gaBase = GetModuleBase(pid, L"GameAssembly.dll");
        if (!gaBase) { SetLastErr("Could not find GameAssembly.dll"); return false; }

        // Using your specific Steam offset: DF4790
        m_siteClean.addr = gaBase + 0xDF4790;
        
        if (!ReadProcessMemory(m_hProc, (LPCVOID)m_siteClean.addr, m_siteClean.orig, m_siteClean.len, nullptr)) {
            SetLastErr("Failed to read memory at offset. Game might be protected.");
            return false;
        }

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
        }
    }

    // Standard Interface
    const char* GetName()    const { return "PWS Steam Trainer"; }
    const char* GetVersion() const { return "1.6.0"; }
    int GetFeatureCount()    const { return (int)m_features.size(); }
    const TrainerFeatureInfo* GetFeatureInfo(int idx) const {
        auto it = m_features.begin(); std::advance(it, idx); return &it->info;
    }
    int GetFeatureEnabled(const char* id) const {
        for (const auto& f : m_features) if (strcmp(f.info.id, id) == 0) return f.enabled.load();
        return 0;
    }
    void SetFeatureEnabled(const char* id, int en) {
        for (auto& f : m_features) if (strcmp(f.info.id, id) == 0) f.enabled = (en != 0);
    }
    void ActivateFeature(const char*) {}
    void SetKeybind(const char* id, int vk) {
        for (auto& f : m_features) if (strcmp(f.info.id, id) == 0) f.vk_code = vk;
    }
    int GetKeybind(const char* id) const {
        for (const auto& f : m_features) if (strcmp(f.info.id, id) == 0) return f.vk_code.load();
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
        // mov eax, 10000 | cvtsi2ss xmm0, eax | ret | nop...
        uint8_t patch[] = { 0xB8, 0x10, 0x27, 0x00, 0x00, 0xF3, 0x0F, 0x2A, 0xC0, 0xC3, 0x90, 0x90 };
        if (MemWriteRaw(m_hProc, m_siteClean.addr, patch, sizeof(patch))) m_siteClean.active = true;
    }

    void RestoreSite(PatchSite& s) {
        if (!s.active) return;
        if (MemWriteRaw(m_hProc, s.addr, s.orig, s.len)) s.active = false;
    }

    void Loop() {
        bool prev = false;
        while (m_running) {
            for (auto& f : m_features) {
                int vk = f.vk_code.load();
                if (vk && (GetAsyncKeyState(vk) & 1)) f.enabled = !f.enabled.load();
            }
            bool cur = m_fInstantClean->enabled.load();
            if (cur != prev) {
                if (cur) ApplyCleanPatch(); else RestoreSite(m_siteClean);
                prev = cur;
            }
            Sleep(10);
        }
    }
};

extern "C" {
    __declspec(dllexport) void* trainer_create() { return new PWSTrainer(); }
    __declspec(dllexport) void  trainer_destroy(void* h) { delete static_cast<PWSTrainer*>(h); }
    __declspec(dllexport) int   trainer_initialize(void* h) { return static_cast<PWSTrainer*>(h)->Initialize() ? 1 : 0; }
    __declspec(dllexport) void  trainer_shutdown(void* h) { static_cast<PWSTrainer*>(h)->Shutdown(); }
    __declspec(dllexport) const char* trainer_get_name(void* h) { return static_cast<PWSTrainer*>(h)->GetName(); }
    __declspec(dllexport) const char* trainer_get_version(void* h) { return static_cast<PWSTrainer*>(h)->GetVersion(); }
    __declspec(dllexport) int   trainer_get_feature_count(void* h) { return static_cast<PWSTrainer*>(h)->GetFeatureCount(); }
    __declspec(dllexport) const TrainerFeatureInfo* trainer_get_feature_info(void* h, int idx) { return static_cast<PWSTrainer*>(h)->GetFeatureInfo(idx); }
    __declspec(dllexport) int   trainer_get_feature_enabled(void* h, const char* id) { return static_cast<PWSTrainer*>(h)->GetFeatureEnabled(id); }
    __declspec(dllexport) void  trainer_set_feature_enabled(void* h, const char* id, int en) { static_cast<PWSTrainer*>(h)->SetFeatureEnabled(id, en); }
    __declspec(dllexport) void  trainer_activate_feature(void* h, const char* id) { static_cast<PWSTrainer*>(h)->ActivateFeature(id); }
    __declspec(dllexport) void  trainer_set_keybind(void* h, const char* id, int vk) { static_cast<PWSTrainer*>(h)->SetKeybind(id, vk); }
    __declspec(dllexport) int   trainer_get_keybind(void* h, const char* id) { return static_cast<PWSTrainer*>(h)->GetKeybind(id); }
    __declspec(dllexport) const char* trainer_get_last_error() { return g_lastError; }
}