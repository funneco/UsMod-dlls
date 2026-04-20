// We Love Katamari REROLL+ Royal Reverie Trainer
// Steam App 1730700, build 20552039
// Target: WLKRR.exe, IL2CPP module: GameAssembly.dll
//
// Patterns sourced from WLKRR-Freeze.CT and WLKRR-EndLevel.CT
//   Freeze time:    FF 41 40 48 83 C4 28  — inc [rcx+40], NOP 3 bytes
//   Freeze cntdown: 89 4A 3C 48 83 C4 28 C3 E8 — 1st match, NOP 3 bytes
//   End level:      89 4A 3C 48 83 C4 28 C3 E8 — 2nd match, cave writes 0

#include "ITrainerModule.h"
#include <windows.h>
#include <tlhelp32.h>
#include <vector>
#include <list>
#include <thread>
#include <atomic>
#include <cstdint>
#include <cstring>
#include <algorithm>

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
                base  = reinterpret_cast<uintptr_t>(me.modBaseAddr);
                sz    = me.modBaseSize;
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

// Scan entire module buffer for all occurrences of pat.
static std::vector<uintptr_t> AobAll(HANDLE hProc, uintptr_t base, size_t sz,
                                     const uint8_t* pat, size_t len) {
    std::vector<uint8_t> buf(sz);
    SIZE_T r;
    std::vector<uintptr_t> hits;
    if (!ReadProcessMemory(hProc, (LPCVOID)base, buf.data(), sz, &r)) return hits;
    for (size_t i = 0; i + len <= r; ++i)
        if (memcmp(buf.data() + i, pat, len) == 0)
            hits.push_back(base + i);
    return hits;
}

static uintptr_t AobFirst(HANDLE hProc, uintptr_t base, size_t sz,
                           const uint8_t* pat, size_t len) {
    auto hits = AobAll(hProc, base, sz, pat, len);
    return hits.empty() ? 0 : hits[0];
}

static uintptr_t AllocNear(HANDLE hProc, uintptr_t hint, size_t size) {
    SYSTEM_INFO si; GetSystemInfo(&si);
    const uintptr_t gran = si.dwAllocationGranularity;
    const uintptr_t lo = (hint > 0x7FF00000ULL) ? hint - 0x7FF00000ULL
                                                 : (uintptr_t)si.lpMinimumApplicationAddress;
    const uintptr_t hi = hint + 0x7FF00000ULL;
    for (uintptr_t a = (hint & ~(gran-1)); a > lo; a -= gran) {
        MEMORY_BASIC_INFORMATION mbi;
        if (!VirtualQueryEx(hProc, (LPCVOID)a, &mbi, sizeof(mbi))) continue;
        if (mbi.State == MEM_FREE) {
            void* p = VirtualAllocEx(hProc, (LPVOID)a, size,
                                     MEM_RESERVE|MEM_COMMIT, PAGE_EXECUTE_READWRITE);
            if (p) return (uintptr_t)p;
        }
    }
    for (uintptr_t a = (hint+gran)&~(gran-1); a < hi; a += gran) {
        MEMORY_BASIC_INFORMATION mbi;
        if (!VirtualQueryEx(hProc, (LPCVOID)a, &mbi, sizeof(mbi))) continue;
        if (mbi.State == MEM_FREE) {
            void* p = VirtualAllocEx(hProc, (LPVOID)a, size,
                                     MEM_RESERVE|MEM_COMMIT, PAGE_EXECUTE_READWRITE);
            if (p) return (uintptr_t)p;
        }
    }
    return 0;
}

// ── Patch site ────────────────────────────────────────────────────────────────

struct PatchSite {
    uintptr_t addr      = 0;
    uint8_t   orig[16]  = {};
    size_t    len       = 0;
    uintptr_t cave      = 0;   // non-zero = code cave installed here
    bool      active    = false;
};

// ── Feature ───────────────────────────────────────────────────────────────────

struct Feature {
    TrainerFeatureInfo info;
    std::atomic<bool>  enabled{false};
    std::atomic<int>   vk_code{0};
    Feature(const char* id_, const char* n, const char* d, int tog, int vk)
        : info{id_, n, d, tog, vk}, vk_code(vk) {}
};

// ── Trainer ───────────────────────────────────────────────────────────────────

class WLKRRTrainer {
public:
    WLKRRTrainer() : m_running(false), m_hProc(nullptr) {
        m_features.emplace_back("end_level",   "End Level",   "Set countdown to 0 — ends level on next tick", 1, VK_F1);
        m_features.emplace_back("freeze_time", "Freeze Time", "Freeze timer display and countdown",           1, VK_F2);

        auto it = m_features.begin();
        m_fEndLevel   = &(*it++);
        m_fFreezeTime = &(*it++);
    }

    ~WLKRRTrainer() { Shutdown(); }

    bool Initialize() {
        DWORD pid = FindPid(L"WLKRR.exe");
        if (!pid) {
            SetLastErr("process not found — is We Love Katamari REROLL running?");
            return false;
        }
        m_hProc = OpenProcess(
            PROCESS_VM_READ | PROCESS_VM_WRITE |
            PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION,
            FALSE, pid);
        if (!m_hProc) {
            char buf[128];
            wsprintfA(buf, "OpenProcess failed (error %lu) — run as administrator", GetLastError());
            SetLastErr(buf);
            return false;
        }
        if (!ScanPatterns(pid)) {
            CloseHandle(m_hProc); m_hProc = nullptr;
            return false;
        }
        m_running = true;
        m_thread  = std::thread(&WLKRRTrainer::Loop, this);
        return true;
    }

    void Shutdown() {
        m_running = false;
        if (m_thread.joinable()) m_thread.join();
        if (m_hProc) {
            if (m_siteEndLevel.active)  RestoreSite(m_siteEndLevel);
            if (m_siteTimeInc.active)   RestoreSite(m_siteTimeInc);
            if (m_siteCountdown.active) RestoreSite(m_siteCountdown);
            if (m_siteEndLevel.cave)
                VirtualFreeEx(m_hProc, (LPVOID)m_siteEndLevel.cave, 0, MEM_RELEASE);
            CloseHandle(m_hProc);
            m_hProc = nullptr;
        }
    }

    const char* GetName()    const { return "We Love Katamari REROLL+ Royal Reverie Trainer"; }
    const char* GetVersion() const { return "1.0.0"; }

    int GetFeatureCount() const { return static_cast<int>(m_features.size()); }

    const TrainerFeatureInfo* GetFeatureInfo(int idx) const {
        auto it = m_features.begin();
        for (int i = 0; i < idx && it != m_features.end(); ++i) ++it;
        return it != m_features.end() ? &it->info : nullptr;
    }

    int GetFeatureEnabled(const char* id) const {
        for (const auto& f : m_features)
            if (strcmp(f.info.id, id) == 0) return f.enabled.load() ? 1 : 0;
        return 0;
    }

    void SetFeatureEnabled(const char* id, int enabled) {
        for (auto& f : m_features)
            if (strcmp(f.info.id, id) == 0 && f.info.is_toggle) {
                f.enabled = (enabled != 0);
                return;
            }
    }

    void ActivateFeature(const char* /*id*/) {}  // all features are toggles

    void SetKeybind(const char* id, int vk) {
        for (auto& f : m_features)
            if (strcmp(f.info.id, id) == 0) { f.vk_code = vk; return; }
    }

    int GetKeybind(const char* id) const {
        for (const auto& f : m_features)
            if (strcmp(f.info.id, id) == 0) return f.vk_code.load();
        return 0;
    }

private:
    std::atomic<bool>  m_running;
    HANDLE             m_hProc;
    std::thread        m_thread;
    std::list<Feature> m_features;

    Feature* m_fEndLevel   = nullptr;
    Feature* m_fFreezeTime = nullptr;

    PatchSite m_siteEndLevel;   // code cave — 2nd countdown match, writes 0
    PatchSite m_siteTimeInc;    // NOP — time increment (FF 41 40)
    PatchSite m_siteCountdown;  // NOP — 1st countdown match (89 4A 3C)

    // ── Scan ──────────────────────────────────────────────────────────────────

    bool ScanPatterns(DWORD pid) {
        uintptr_t gaBase = 0; size_t gaSize = 0;
        if (!GetModuleInfo(pid, L"GameAssembly.dll", gaBase, gaSize)) {
            SetLastErr("GameAssembly.dll not found — game may still be loading");
            return false;
        }

        // Countdown pattern — must appear at least twice:
        //   hits[0] = freeze site  (~GameAssembly.dll+62E218)
        //   hits[1] = end-level site (~GameAssembly.dll+638958)
        static const uint8_t PAT_CD[] = {
            0x89,0x4A,0x3C, 0x48,0x83,0xC4,0x28, 0xC3, 0xE8
        };
        auto cdHits = AobAll(m_hProc, gaBase, gaSize, PAT_CD, sizeof(PAT_CD));
        if (cdHits.size() < 2) {
            char buf[128];
            wsprintfA(buf, "countdown pattern: need >=2 matches, found %zu — wrong build?",
                      cdHits.size());
            SetLastErr(buf);
            return false;
        }

        // Time increment — first match
        static const uint8_t PAT_TI[] = {
            0xFF,0x41,0x40, 0x48,0x83,0xC4,0x28
        };
        uintptr_t tiAddr = AobFirst(m_hProc, gaBase, gaSize, PAT_TI, sizeof(PAT_TI));
        if (!tiAddr) {
            SetLastErr("time increment pattern not found — wrong build?");
            return false;
        }

        // ── siteCountdown (NOP 3 bytes at hits[0]) ────────────────────────────
        m_siteCountdown.addr = cdHits[0];
        m_siteCountdown.len  = 3;
        ReadProcessMemory(m_hProc, (LPCVOID)cdHits[0], m_siteCountdown.orig, 3, nullptr);

        // ── siteTimeInc (NOP 3 bytes) ─────────────────────────────────────────
        m_siteTimeInc.addr = tiAddr;
        m_siteTimeInc.len  = 3;
        ReadProcessMemory(m_hProc, (LPCVOID)tiAddr, m_siteTimeInc.orig, 3, nullptr);

        // ── siteEndLevel (code cave, 7 bytes at hits[1]) ─────────────────────
        // Original 7 bytes: 89 4A 3C (mov [rdx+3C],ecx) + 48 83 C4 28 (add rsp,28)
        // Cave: C7 42 3C 00 00 00 00 (mov [rdx+3C],0) + 48 83 C4 28 + E9 rel32 (jmp back)
        uintptr_t elAddr = cdHits[1];
        uintptr_t cave   = AllocNear(m_hProc, elAddr, 32);
        if (!cave) {
            SetLastErr("failed to allocate code cave for end_level");
            return false;
        }

        m_siteEndLevel.addr = elAddr;
        m_siteEndLevel.len  = 7;
        m_siteEndLevel.cave = cave;
        ReadProcessMemory(m_hProc, (LPCVOID)elAddr, m_siteEndLevel.orig, 7, nullptr);

        // Build cave:
        //   [0..6]  C7 42 3C 00 00 00 00  — mov dword [rdx+3C], 0
        //   [7..10] 48 83 C4 28           — add rsp, 28
        //   [11..15] E9 xx xx xx xx       — jmp elAddr+7
        uint8_t caveBytes[16] = {};
        caveBytes[0]=0xC7; caveBytes[1]=0x42; caveBytes[2]=0x3C;
        caveBytes[3]=0x00; caveBytes[4]=0x00; caveBytes[5]=0x00; caveBytes[6]=0x00;
        caveBytes[7]=0x48; caveBytes[8]=0x83; caveBytes[9]=0xC4; caveBytes[10]=0x28;
        caveBytes[11]=0xE9;
        int32_t rel = static_cast<int32_t>((elAddr + 7) - (cave + 11) - 5);
        memcpy(&caveBytes[12], &rel, 4);
        WriteProcessMemory(m_hProc, (LPVOID)cave, caveBytes, sizeof(caveBytes), nullptr);

        return true;
    }

    // ── Patch helpers ─────────────────────────────────────────────────────────

    void ApplyNop(PatchSite& s) {
        if (s.active || !s.addr) return;
        uint8_t nops[16] = {};
        memset(nops, 0x90, s.len);
        MemWriteRaw(m_hProc, s.addr, nops, s.len);
        s.active = true;
    }

    void ApplyCaveJmp(PatchSite& s) {
        if (s.active || !s.addr || !s.cave) return;
        // 5-byte rel32 JMP + 2 NOPs (total 7 bytes)
        uint8_t patch[7] = { 0xE9,0,0,0,0, 0x90,0x90 };
        int32_t rel = static_cast<int32_t>(s.cave - s.addr - 5);
        memcpy(&patch[1], &rel, 4);
        MemWriteRaw(m_hProc, s.addr, patch, s.len);
        s.active = true;
    }

    void RestoreSite(PatchSite& s) {
        if (!s.active || !s.addr) return;
        MemWriteRaw(m_hProc, s.addr, s.orig, s.len);
        s.active = false;
    }

    // ── Main loop ─────────────────────────────────────────────────────────────

    void Loop() {
        bool prevEndLevel   = false;
        bool prevFreezeTime = false;

        while (m_running) {
            // Hotkey dispatch
            for (auto& f : m_features) {
                int vk = f.vk_code.load();
                if (vk && (GetAsyncKeyState(vk) & 1))
                    f.enabled = !f.enabled.load();
            }

            bool endLevel   = m_fEndLevel->enabled.load();
            bool freezeTime = m_fFreezeTime->enabled.load();

            if (endLevel != prevEndLevel) {
                if (endLevel) ApplyCaveJmp(m_siteEndLevel);
                else          RestoreSite(m_siteEndLevel);
                prevEndLevel = endLevel;
            }

            if (freezeTime != prevFreezeTime) {
                if (freezeTime) {
                    ApplyNop(m_siteTimeInc);
                    ApplyNop(m_siteCountdown);
                } else {
                    RestoreSite(m_siteTimeInc);
                    RestoreSite(m_siteCountdown);
                }
                prevFreezeTime = freezeTime;
            }

            Sleep(10);
        }

        if (m_siteEndLevel.active)  RestoreSite(m_siteEndLevel);
        if (m_siteTimeInc.active)   RestoreSite(m_siteTimeInc);
        if (m_siteCountdown.active) RestoreSite(m_siteCountdown);
    }
};

// ── C ABI exports ─────────────────────────────────────────────────────────────

extern "C" {

void* trainer_create()            { return new WLKRRTrainer(); }
void  trainer_destroy(void* h)    { delete static_cast<WLKRRTrainer*>(h); }
int   trainer_initialize(void* h) { return static_cast<WLKRRTrainer*>(h)->Initialize() ? 1 : 0; }
void  trainer_shutdown(void* h)   { static_cast<WLKRRTrainer*>(h)->Shutdown(); }

const char* trainer_get_name(void* h)    { return static_cast<WLKRRTrainer*>(h)->GetName(); }
const char* trainer_get_version(void* h) { return static_cast<WLKRRTrainer*>(h)->GetVersion(); }

int trainer_get_feature_count(void* h)
    { return static_cast<WLKRRTrainer*>(h)->GetFeatureCount(); }
const TrainerFeatureInfo* trainer_get_feature_info(void* h, int idx)
    { return static_cast<WLKRRTrainer*>(h)->GetFeatureInfo(idx); }
int trainer_get_feature_enabled(void* h, const char* id)
    { return static_cast<WLKRRTrainer*>(h)->GetFeatureEnabled(id); }
void trainer_set_feature_enabled(void* h, const char* id, int en)
    { static_cast<WLKRRTrainer*>(h)->SetFeatureEnabled(id, en); }
void trainer_activate_feature(void* h, const char* id)
    { static_cast<WLKRRTrainer*>(h)->ActivateFeature(id); }
void trainer_set_keybind(void* h, const char* id, int vk)
    { static_cast<WLKRRTrainer*>(h)->SetKeybind(id, vk); }
int trainer_get_keybind(void* h, const char* id)
    { return static_cast<WLKRRTrainer*>(h)->GetKeybind(id); }

const char* trainer_get_last_error() { return g_lastError; }

} // extern "C"
