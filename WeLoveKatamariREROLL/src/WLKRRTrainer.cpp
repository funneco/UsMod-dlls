#include <windows.h>
#include <tlhelp32.h>
#include <vector>
#include <list>
#include <thread>
#include <atomic>
#include <cstdint>
#include <cstring>

struct TrainerFeatureInfo {
    const char* id;
    const char* name;
    const char* description;
    int is_toggle;
    int hotkey;
};

// --- Utilities ---
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

// AOB scan — 0x00 is wildcard (matches PowerWash framework convention)
static uintptr_t AobScan(HANDLE hProc, uintptr_t base, size_t sz,
                          const uint8_t* pat, size_t len) {
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

// AobScan with nth-occurrence selection (0-based)
static uintptr_t AobScanNth(HANDLE hProc, uintptr_t base, size_t sz,
                              const uint8_t* pat, size_t len, int nth) {
    std::vector<uint8_t> buf(sz);
    SIZE_T r = 0;
    if (!ReadProcessMemory(hProc, (LPCVOID)base, buf.data(), sz, &r)) return 0;
    int found = 0;
    for (size_t i = 0; i + len <= r; ++i) {
        bool match = true;
        for (size_t j = 0; j < len; j++) {
            if (pat[j] != 0x00 && buf[i + j] != pat[j]) { match = false; break; }
        }
        if (match) {
            if (found == nth) return base + i;
            ++found;
        }
    }
    return 0;
}

struct Feature {
    TrainerFeatureInfo  info;
    std::atomic<bool>   enabled{ false };
    std::atomic<int>    vk_code{ 0 };
    Feature(const char* i, const char* n, const char* d, int tog, int vk)
        : info{ i, n, d, tog, vk }, vk_code(vk) {}
};

class WLKTrainer {
public:
    HANDLE              m_hProc  = nullptr;
    std::atomic<bool>   m_running{ false };
    std::thread         m_thread;
    std::list<Feature>  m_features;

    // ── Freeze Time ───────────────────────────────────────────────────────
    // Patch 1 "Time":     FF 41 40 → 90 90 90   (inc [rcx+40] → NOP)
    // Patch 2 "Countdown":89 4A 3C → 90 90 90   (mov [rdx+3C],ecx → NOP, occ.0)
    uintptr_t addrTime     = 0;
    uint8_t   origTime[3]  = {};
    uintptr_t addrCountdown     = 0;
    uint8_t   origCountdown[3]  = {};

    // ── End Level ─────────────────────────────────────────────────────────
    // 14-byte absolute jmp hook at context pattern +6
    //   Pattern: 8B 42 3C 8D 48 FF 89 4A 3C 48 83 C4
    //   Hook at: +6  (89 4A 3C 48 83 C4 28  = 7 stolen bytes)
    //   Cave:    mov dword ptr [rdx+3C],0 / add rsp,28 / ret
    uintptr_t addrEndLevel       = 0;
    uint8_t   origEndLevel[14]   = {};
    uintptr_t caveEndLevel       = 0;

    WLKTrainer() {
        m_features.emplace_back("freeze_time", "Freeze Time",
            "Prevents the round timer from ticking down.", 1, VK_F1);
        m_features.emplace_back("end_level",   "End Level",
            "Forces countdown to zero, completing the level on next tick.", 1, VK_F2);
    }

    bool Initialize() {
        // Wait up to 30 s for the game process
        DWORD pid = 0;
        for (int i = 0; i < 300 && !pid; ++i) { pid = FindPid(L"WLKRR.exe"); Sleep(100); }
        if (!pid) return false;

        m_hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
        if (!m_hProc) return false;

        // Wait up to 30 s for GameAssembly.dll
        uintptr_t gaBase = 0;
        for (int i = 0; i < 300 && !gaBase; ++i) { gaBase = GetModuleBase(pid, L"GameAssembly.dll"); Sleep(100); }
        if (!gaBase) return false;

        // IL2CPP JIT warm-up
        Sleep(2000);

        const size_t scanSize = 0x3000000; // 48 MB — covers the IL2CPP .text section

        // ── Patch 1: Time ─────────────────────────────────────────────────
        // Pattern: FF 41 40 48 83 C4 28   (unique, first occurrence)
        // We only NOP the first 3 bytes: FF 41 40 = inc dword ptr [rcx+40]
        {
            uint8_t pat[] = { 0xFF,0x41,0x40, 0x48,0x83,0xC4,0x28 };
            uintptr_t hit = AobScan(m_hProc, gaBase, scanSize, pat, sizeof(pat));
            if (hit) {
                addrTime = hit;
                ReadProcessMemory(m_hProc, (LPCVOID)addrTime, origTime, 3, nullptr);
            }
        }

        // ── Patch 2: Countdown ────────────────────────────────────────────
        // Pattern: 89 4A 3C 48 83 C4 28 C3 E8   occurrence 0 (~62E218)
        // occurrence 1 (~638958) is the End Level hook site.
        // We only NOP the first 3 bytes: 89 4A 3C = mov [rdx+3C],ecx
        {
            uint8_t pat[] = { 0x89,0x4A,0x3C, 0x48,0x83,0xC4,0x28, 0xC3,0xE8 };
            uintptr_t hit = AobScanNth(m_hProc, gaBase, scanSize, pat, sizeof(pat), 0);
            if (hit) {
                addrCountdown = hit;
                ReadProcessMemory(m_hProc, (LPCVOID)addrCountdown, origCountdown, 3, nullptr);
            }
        }

        // ── End Level cave + hook ─────────────────────────────────────────
        // Context pattern (12 bytes) uniquely identifies the injection site:
        //   8B 42 3C  = mov eax,[rdx+3C]
        //   8D 48 FF  = lea ecx,[rax-1]
        //   89 4A 3C  = mov [rdx+3C],ecx   ← hook at context+6
        //   48 83 C4  = add rsp (partial)
        // Stolen: 7 bytes (89 4A 3C  +  48 83 C4 28)
        // Cave:   mov dword ptr [rdx+3C],0 / add rsp,28 / ret  (complete tail)
        {
            uint8_t ctx[] = { 0x8B,0x42,0x3C, 0x8D,0x48,0xFF,
                               0x89,0x4A,0x3C, 0x48,0x83,0xC4 };
            uintptr_t hit = AobScan(m_hProc, gaBase, scanSize, ctx, sizeof(ctx));
            if (hit) {
                addrEndLevel = hit + 6; // offset to actual injection point

                // Save 14 bytes (7 stolen + 7 slack for safe restore)
                ReadProcessMemory(m_hProc, (LPCVOID)addrEndLevel, origEndLevel, 14, nullptr);

                // Allocate cave
                caveEndLevel = (uintptr_t)VirtualAllocEx(
                    m_hProc, nullptr, 64,
                    MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

                if (caveEndLevel) {
                    // Cave shellcode (12 bytes payload + 14-byte return trampoline slot):
                    //   C7 42 3C 00 00 00 00  = mov dword ptr [rdx+3C], 0
                    //   48 83 C4 28           = add rsp, 28          (stolen epilogue)
                    //   C3                    = ret                   (function tail)
                    // No return jmp needed — cave IS the complete function tail.
                    uint8_t cave[] = {
                        0xC7,0x42,0x3C,0x00,0x00,0x00,0x00,  // mov dword ptr [rdx+3C], 0
                        0x48,0x83,0xC4,0x28,                  // add rsp, 28
                        0xC3                                   // ret
                    };
                    WriteProcessMemory(m_hProc, (LPVOID)caveEndLevel, cave, sizeof(cave), nullptr);
                }
            }
        }

        m_running = true;
        m_thread = std::thread(&WLKTrainer::Loop, this);
        return true;
    }

    void Loop() {
        bool prevFreezeTime = false;
        bool prevEndLevel   = false;

        while (m_running) {
            // Hotkey edge detection (same pattern as PowerWash trainer)
            for (auto& f : m_features) {
                int vk = f.vk_code.load();
                if (vk && (GetAsyncKeyState(vk) & 1)) f.enabled = !f.enabled.load();
            }

            auto it = m_features.begin();

            // ── Feature: Freeze Time ──────────────────────────────────────
            bool wantFreezeTime = it->enabled.load();
            if (wantFreezeTime != prevFreezeTime) {
                const uint8_t nop3[3] = { 0x90,0x90,0x90 };
                if (wantFreezeTime) {
                    // Apply both patches — skip whichever address we failed to find
                    if (addrTime)      MemWrite(m_hProc, addrTime,      nop3,         3);
                    if (addrCountdown) MemWrite(m_hProc, addrCountdown,  nop3,         3);
                } else {
                    if (addrTime)      MemWrite(m_hProc, addrTime,      origTime,     3);
                    if (addrCountdown) MemWrite(m_hProc, addrCountdown,  origCountdown,3);
                }
                prevFreezeTime = wantFreezeTime;
            }

            ++it;

            // ── Feature: End Level ────────────────────────────────────────
            // 14-byte absolute jmp hook (FF 25 00000000 <8-byte addr>)
            // Bytes 7-13 of origEndLevel serve as the NOP pad / restore buffer.
            bool wantEndLevel = it->enabled.load();
            if (wantEndLevel != prevEndLevel && addrEndLevel && caveEndLevel) {
                if (wantEndLevel) {
                    // Write 14-byte absolute jmp: FF 25 00 00 00 00 [caveEndLevel]
                    uint8_t hook[14] = { 0xFF,0x25,0x00,0x00,0x00,0x00 };
                    memcpy(&hook[6], &caveEndLevel, 8);
                    MemWrite(m_hProc, addrEndLevel, hook, 14);
                } else {
                    MemWrite(m_hProc, addrEndLevel, origEndLevel, 14);
                }
                prevEndLevel = wantEndLevel;
            }

            Sleep(10);
        }
    }

    void Shutdown() {
        m_running = false;
        if (m_thread.joinable()) m_thread.join();
        // Restore patches on exit
        if (addrTime      && origTime[0])      MemWrite(m_hProc, addrTime,      origTime,      3);
        if (addrCountdown && origCountdown[0]) MemWrite(m_hProc, addrCountdown,  origCountdown, 3);
        if (addrEndLevel  && caveEndLevel)     MemWrite(m_hProc, addrEndLevel,   origEndLevel,  14);
        if (caveEndLevel)  { VirtualFreeEx(m_hProc, (LPVOID)caveEndLevel, 0, MEM_RELEASE); caveEndLevel = 0; }
        if (m_hProc)       { CloseHandle(m_hProc); m_hProc = nullptr; }
    }

    int                      GetFeatureCount()   { return (int)m_features.size(); }
    const TrainerFeatureInfo* GetFeatureInfo(int idx) {
        auto it = m_features.begin(); std::advance(it, idx); return &it->info;
    }
    int  GetFeatureEnabled(const char* id) {
        for (auto& f : m_features) if (strcmp(f.info.id, id) == 0) return f.enabled.load() ? 1 : 0;
        return 0;
    }
    void SetFeatureEnabled(const char* id, int en) {
        for (auto& f : m_features) if (strcmp(f.info.id, id) == 0) f.enabled = (en != 0);
    }
    void ActivateFeature(const char* /*id*/) {}
    void SetKeybind(const char* id, int vk) {
        for (auto& f : m_features) if (strcmp(f.info.id, id) == 0) f.vk_code = vk;
    }
    int  GetKeybind(const char* id) {
        for (auto& f : m_features) if (strcmp(f.info.id, id) == 0) return f.vk_code.load();
        return 0;
    }
    const char* GetName()    { return "We Love Katamari REROLL Trainer"; }
    const char* GetVersion() { return "1.0.0"; }
};

extern "C" {
    __declspec(dllexport) void*       trainer_create()              { return new WLKTrainer(); }
    __declspec(dllexport) void        trainer_destroy(void* h)      { static_cast<WLKTrainer*>(h)->Shutdown(); delete static_cast<WLKTrainer*>(h); }
    __declspec(dllexport) int         trainer_initialize(void* h)   { return static_cast<WLKTrainer*>(h)->Initialize() ? 1 : 0; }
    __declspec(dllexport) void        trainer_shutdown(void* h)     { static_cast<WLKTrainer*>(h)->Shutdown(); }
    __declspec(dllexport) const char* trainer_get_name(void* h)     { return static_cast<WLKTrainer*>(h)->GetName(); }
    __declspec(dllexport) const char* trainer_get_version(void* h)  { return static_cast<WLKTrainer*>(h)->GetVersion(); }
    __declspec(dllexport) const char* trainer_get_last_error()      { return ""; }
    __declspec(dllexport) int         trainer_get_feature_count(void* h)                       { return static_cast<WLKTrainer*>(h)->GetFeatureCount(); }
    __declspec(dllexport) const TrainerFeatureInfo* trainer_get_feature_info(void* h, int i)   { return static_cast<WLKTrainer*>(h)->GetFeatureInfo(i); }
    __declspec(dllexport) int         trainer_get_feature_enabled(void* h, const char* id)     { return static_cast<WLKTrainer*>(h)->GetFeatureEnabled(id); }
    __declspec(dllexport) void        trainer_set_feature_enabled(void* h, const char* id, int en) { static_cast<WLKTrainer*>(h)->SetFeatureEnabled(id, en); }
    __declspec(dllexport) void        trainer_activate_feature(void* h, const char* id)        { static_cast<WLKTrainer*>(h)->ActivateFeature(id); }
    __declspec(dllexport) void        trainer_set_keybind(void* h, const char* id, int vk)     { static_cast<WLKTrainer*>(h)->SetKeybind(id, vk); }
    __declspec(dllexport) int         trainer_get_keybind(void* h, const char* id)             { return static_cast<WLKTrainer*>(h)->GetKeybind(id); }
}