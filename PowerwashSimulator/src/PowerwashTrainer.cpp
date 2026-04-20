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
            if (_wcsicmp(me.szModule, modName) == 0) { base = reinterpret_cast<uintptr_t>(me.modBaseAddr); break; }
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

static uintptr_t AobScan(HANDLE hProc, uintptr_t base, size_t sz, const uint8_t* pat, size_t len) {
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
    uint8_t   orig[15] = {};
    size_t    len = 5;
    uintptr_t cave = 0;
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
        m_features.emplace_back("instant_clean", "Instant Clean", "Set effectiveness to 10k", 1, VK_F1);
        m_features.emplace_back("show_dirt", "Permanent Show Dirt", "Keeps dirt highlighted constantly", 1, VK_F3);
        
        auto it = m_features.begin();
        m_fInstantClean = &(*it++);
        m_fShowDirt = &(*it++);
    }

    bool Initialize() {
        DWORD pid = FindPid(L"PowerWashSimulator.exe");
        if (!pid) { SetLastErr("Process not found."); return false; }
        m_hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
        if (!m_hProc) { SetLastErr("Admin required."); return false; }

        uintptr_t gaBase = GetModuleBase(pid, L"GameAssembly.dll");
        size_t gaSize = 0x2000000; // Approx 32MB scan range for Steam

        // 1. Instant Clean (Static Offset)
        m_siteClean.addr = gaBase + 0xDF4790;
        m_siteClean.len = 10;
        ReadProcessMemory(m_hProc, (LPCVOID)m_siteClean.addr, m_siteClean.orig, 10, nullptr);

        // 2. Show Dirt (AOB Scan)
        static const uint8_t PAT_DIRT[] = { 0xF3, 0x0F, 0x11, 0x43, 0x38, 0xF3, 0x0F, 0x10 };
        m_siteDirt.addr = AobScan(m_hProc, gaBase, gaSize, PAT_DIRT, 8);
        
        if (m_siteDirt.addr) {
            m_siteDirt.len = 5; // Size of the JMP we will place
            ReadProcessMemory(m_hProc, (LPCVOID)m_siteDirt.addr, m_siteDirt.orig, 5, nullptr);
            
            // Allocate Cave for Show Dirt
            m_siteDirt.cave = (uintptr_t)VirtualAllocEx(m_hProc, nullptr, 128, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (m_siteDirt.cave) {
                float glow = 1.0f;
                uint8_t caveCode[32] = {
                    0xF3, 0x0F, 0x10, 0x05, 0x0A, 0x00, 0x00, 0x00, // movss xmm0, [glow_val]
                    0xF3, 0x0F, 0x11, 0x43, 0x38,                   // movss [rbx+38], xmm0
                    0xE9, 0x00, 0x00, 0x00, 0x00                    // jmp return
                };
                // Calculate back jump
                int32_t relBack = (int32_t)(m_siteDirt.addr + 5 - (m_siteDirt.cave + 18));
                memcpy(&caveCode[14], &relBack, 4);
                // Append the float value 1.0f at cave + 18
                memcpy(&caveCode[18], &glow, 4);
                WriteProcessMemory(m_hProc, (LPVOID)m_siteDirt.cave, caveCode, 22, nullptr);
            }
        }

        m_running = true;
        m_thread = std::thread(&PWSTrainer::Loop, this);
        return true;
    }

    void ApplyDirtPatch() {
        if (m_siteDirt.active || !m_siteDirt.cave) return;
        uint8_t jmpPatch[5] = { 0xE9, 0, 0, 0, 0 };
        int32_t relAddr = (int32_t)(m_siteDirt.cave - m_siteDirt.addr - 5);
        memcpy(&jmpPatch[1], &relAddr, 4);
        MemWriteRaw(m_hProc, m_siteDirt.addr, jmpPatch, 5);
        m_siteDirt.active = true;
    }

    void RestoreSite(PatchSite& s) {
        if (!s.active) return;
        MemWriteRaw(m_hProc, s.addr, s.orig, s.len);
        s.active = false;
    }

    // [Loop handles hotkeys and toggle logic similarly to your previous version]
    // ... rest of the interface methods ...

private:
    std::atomic<bool> m_running;
    HANDLE m_hProc;
    std::thread m_thread;
    std::list<Feature> m_features;
    Feature* m_fInstantClean;
    Feature* m_fShowDirt;
    PatchSite m_siteClean;
    PatchSite m_siteDirt;

    void Loop() {
        bool p1 = false, p2 = false;
        while (m_running) {
            for (auto& f : m_features) {
                if (GetAsyncKeyState(f.vk_code.load()) & 1) f.enabled = !f.enabled.load();
            }
            if (m_fInstantClean->enabled.load() != p1) {
                if (m_fInstantClean->enabled.load()) {
                    uint8_t p[] = { 0xB8, 0x10, 0x27, 0x00, 0x00, 0xF3, 0x0F, 0x2A, 0xC0, 0xC3 };
                    MemWriteRaw(m_hProc, m_siteClean.addr, p, 10);
                    m_siteClean.active = true;
                } else RestoreSite(m_siteClean);
                p1 = m_fInstantClean->enabled.load();
            }
            if (m_fShowDirt->enabled.load() != p2) {
                if (m_fShowDirt->enabled.load()) ApplyDirtPatch();
                else RestoreSite(m_siteDirt);
                p2 = m_fShowDirt->enabled.load();
            }
            Sleep(10);
        }
    }
};

// [C ABI Exports as before]