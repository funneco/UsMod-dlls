// PowerWash Simulator Trainer (Steam Version)
// Target: PowerWashSimulator.exe
// Module: GameAssembly.dll

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
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
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

static bool MemWrite(HANDLE hProc, uintptr_t addr, const void* data, size_t size) {
    DWORD old;
    if (!VirtualProtectEx(hProc, (LPVOID)addr, size, PAGE_EXECUTE_READWRITE, &old)) return false;
    SIZE_T r;
    bool ok = WriteProcessMemory(hProc, (LPVOID)addr, data, size, &r);
    VirtualProtectEx(hProc, (LPVOID)addr, size, old, &old);
    FlushInstructionCache(hProc, (LPVOID)addr, size);
    return ok && r == size;
}

static uintptr_t AobScan(HANDLE hProc, uintptr_t base, size_t sz, const uint8_t* pat, const char* mask) {
    std::vector<uint8_t> buf(sz);
    SIZE_T r = 0;
    if (!ReadProcessMemory(hProc, (LPCVOID)base, buf.data(), sz, &r) || r == 0) return 0;
    size_t len = strlen(mask);
    for (size_t i = 0; i + len <= r; ++i) {
        bool match = true;
        for (size_t j = 0; j < len; ++j) {
            if (mask[j] == 'x' && buf[i + j] != pat[j]) { match = false; break; }
        }
        if (match) return base + i;
    }
    return 0;
}

struct PatchSite {
    uintptr_t addr = 0;
    std::vector<uint8_t> orig;
    bool active = false;
};

struct Feature {
    TrainerFeatureInfo info;
    std::atomic<bool> enabled{ false };
    std::atomic<int> vk_code{ 0 };
    Feature(const char* id, const char* n, const char* d, int tog, int vk)
        : info{ id, n, d, tog, vk }, vk_code(vk) {}
};

class PWSTrainerSteam {
public:
    PWSTrainerSteam() : m_running(false), m_hProc(nullptr) {
        m_features.emplace_back("instant_clean", "Instant Clean", "Force 100% Cleaning Power", 1, VK_F1);
        m_fInstantClean = &m_features.back();
    }

    bool Initialize() {
        DWORD pid = FindPid(L"PowerWashSimulator.exe");
        if (!pid) { SetLastErr("Steam Version not running."); return false; }

        m_hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
        if (!m_hProc) { SetLastErr("Admin privileges required."); return false; }

        uintptr_t base = 0; size_t sz = 0;
        if (!GetModuleInfo(pid, L"GameAssembly.dll", base, sz)) {
            SetLastErr("GameAssembly.dll not found."); return false;
        }

        // Updated Steam Pattern for the Nozzle Effectiveness check
        // Looking for: comviss xmm0, xmm1 | jbe ... | movss ...
        static const uint8_t PAT_CLEAN[] = { 0x0F, 0x2F, 0xC1, 0x76, 0x00, 0xF3, 0x0F, 0x10 };
        static const char* MASK_CLEAN = "xxxx?xxx";
        
        m_siteClean.addr = AobScan(m_hProc, base, sz, PAT_CLEAN, MASK_CLEAN);
        if (!m_siteClean.addr) {
            SetLastErr("Steam-specific pattern not found.");
            return false;
        }

        m_siteClean.orig.resize(11); // Store the original instruction bytes
        ReadProcessMemory(m_hProc, (LPCVOID)m_siteClean.addr, m_siteClean.orig.data(), 11, nullptr);

        m_running = true;
        m_thread = std::thread(&PWSTrainerSteam::Loop, this);
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

    // --- Interface Boilerplate ---
    const char* GetName() const { return "PWS Steam Trainer"; }
    const char* GetVersion() const { return "1.3.0"; }
    int GetFeatureCount() const { return (int)m_features.size(); }
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
    Feature* m_fInstantClean;
    PatchSite m_siteClean;

    void ApplyCleanPatch() {
        if (m_siteClean.active) return;
        // mov eax, 10000; cvtsi2ss xmm0, eax; ret instruction variant for mid-function
        // This forces xmm0 to 10k right before the game uses it for the dirt calculation.
        uint8_t patch[] = { 0xB8, 0x10, 0x27, 0x00, 0x00, 0xF3, 0x0F, 0x2A, 0xC0, 0x90, 0x90 };
        if (MemWrite(m_hProc, m_siteClean.addr, patch, 11)) m_siteClean.active = true;
    }

    void RestoreSite(PatchSite& s) {
        if (!s.active) return;
        if (MemWrite(m_hProc, s.addr, s.orig.data(), s.orig.size())) s.active = false;
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
            Sleep(20);
        }
    }
};

extern "C" {
    __declspec(dllexport) void* trainer_create() { return new PWSTrainerSteam(); }
    __declspec(dllexport) void  trainer_destroy(void* h) { delete static_cast<PWSTrainerSteam*>(h); }
    __declspec(dllexport) int   trainer_initialize(void* h) { return static_cast<PWSTrainerSteam*>(h)->Initialize() ? 1 : 0; }
    __declspec(dllexport) void  trainer_shutdown(void* h) { static_cast<PWSTrainerSteam*>(h)->Shutdown(); }
    __declspec(dllexport) const char* trainer_get_name(void* h) { return static_cast<PWSTrainerSteam*>(h)->GetName(); }
    __declspec(dllexport) const char* trainer_get_version(void* h) { return static_cast<PWSTrainerSteam*>(h)->GetVersion(); }
    __declspec(dllexport) int   trainer_get_feature_count(void* h) { return static_cast<PWSTrainerSteam*>(h)->GetFeatureCount(); }
    __declspec(dllexport) const TrainerFeatureInfo* trainer_get_feature_info(void* h, int idx) { return static_cast<PWSTrainerSteam*>(h)->GetFeatureInfo(idx); }
    __declspec(dllexport) int   trainer_get_feature_enabled(void* h, const char* id) { return static_cast<PWSTrainerSteam*>(h)->GetFeatureEnabled(id); }
    __declspec(dllexport) void  trainer_set_feature_enabled(void* h, const char* id, int en) { static_cast<PWSTrainerSteam*>(h)->SetFeatureEnabled(id, en); }
    __declspec(dllexport) void  trainer_activate_feature(void* h, const char* id) { static_cast<PWSTrainerSteam*>(h)->ActivateFeature(id); }
    __declspec(dllexport) void  trainer_set_keybind(void* h, const char* id, int vk) { static_cast<PWSTrainerSteam*>(h)->SetKeybind(id, vk); }
    __declspec(dllexport) int   trainer_get_keybind(void* h, const char* id) { return static_cast<PWSTrainerSteam*>(h)->GetKeybind(id); }
    __declspec(dllexport) const char* trainer_get_last_error() { return g_lastError; }
}