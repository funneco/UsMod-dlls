// Stardew Valley Trainer — Steam App 413150, build 16826371 (v1.6.x)
// Strategy: hook Game1::Update to get farmer ptr each frame via get_player call;
//           patch .NET JIT stubs for fishing and movement.
//
// Patterns sourced from Stardew Valley_x64.CT by sub1to.
//
// ── Field offsets ────────────────────────────────────────────────────────────
// These are for .NET 6 x64 managed heap layout (build 16826371).
// To verify in CE: enable table → right-click stat entry →
//   "Find out what accesses this address" → subtract farmer_base_ptr.
// ─────────────────────────────────────────────────────────────────────────────

#include "ITrainerModule.h"
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <vector>
#include <list>
#include <thread>
#include <atomic>
#include <cstdint>
#include <cstring>

// ── .NET Farmer field offsets ─────────────────────────────────────────────────
static constexpr ptrdiff_t OFF_HEALTH           = 0x178;
static constexpr ptrdiff_t OFF_MAX_HEALTH       = 0x17C;
static constexpr ptrdiff_t OFF_NET_STAMINA_PTR  = 0x198;
static constexpr ptrdiff_t OFF_NETFLOAT_VALUE   = 0x10;
static constexpr ptrdiff_t OFF_MAX_STAMINA_PTR  = 0x1A0;
static constexpr ptrdiff_t OFF_NETINT_VALUE     = 0x10;
static constexpr ptrdiff_t OFF_NET_SPEED_PTR    = 0x1B0;
static constexpr ptrdiff_t OFF_TEAM_ROOT_PTR    = 0x148;
static constexpr ptrdiff_t OFF_NETREF_VALUE     = 0x18;
static constexpr ptrdiff_t OFF_TEAM_MONEY_PTR   = 0x150;

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

static uintptr_t GetMainModuleBase(HANDLE hProc, const wchar_t* mod) {
    HMODULE mods[1024]; DWORD needed;
    if (!EnumProcessModulesEx(hProc, mods, sizeof(mods), &needed, LIST_MODULES_64BIT)) return 0;
    wchar_t name[MAX_PATH];
    for (DWORD i = 0; i < needed / sizeof(HMODULE); ++i) {
        GetModuleBaseNameW(hProc, mods[i], name, MAX_PATH);
        if (_wcsicmp(name, mod) == 0) return reinterpret_cast<uintptr_t>(mods[i]);
    }
    return 0;
}

static size_t GetModuleSize(HANDLE hProc, uintptr_t base) {
    IMAGE_DOS_HEADER dos; SIZE_T r;
    if (!ReadProcessMemory(hProc, reinterpret_cast<LPCVOID>(base), &dos, sizeof(dos), &r)) return 0;
    IMAGE_NT_HEADERS64 nt;
    if (!ReadProcessMemory(hProc, reinterpret_cast<LPCVOID>(base + dos.e_lfanew), &nt, sizeof(nt), &r)) return 0;
    return nt.OptionalHeader.SizeOfImage;
}

static uintptr_t AobFirst(HANDLE hProc, uintptr_t base, size_t size,
                           const uint8_t* pat, const uint8_t* mask, size_t len) {
    constexpr size_t CHUNK = 0x100000;
    std::vector<uint8_t> buf(CHUNK);
    for (size_t offset = 0; offset < size; offset += CHUNK) {
        size_t readSize = (offset + CHUNK > size) ? (size - offset) : CHUNK;
        SIZE_T r;
        if (!ReadProcessMemory(hProc, reinterpret_cast<LPCVOID>(base + offset),
                               buf.data(), readSize, &r)) continue;
        for (size_t i = 0; i + len <= r; ++i) {
            bool ok = true;
            for (size_t j = 0; j < len; ++j)
                if (mask[j] != 0xCC && buf[i + j] != pat[j]) { ok = false; break; }
            if (ok) return base + offset + i;
        }
    }
    return 0;
}

static uintptr_t AllocNear(HANDLE hProc, uintptr_t hint, size_t size) {
    SYSTEM_INFO si; GetSystemInfo(&si);
    const uintptr_t gran = si.dwAllocationGranularity;
    const uintptr_t lo = (hint > 0x7FF00000ULL) ? hint - 0x7FF00000ULL : (uintptr_t)si.lpMinimumApplicationAddress;
    const uintptr_t hi = hint + 0x7FF00000ULL;

    for (uintptr_t addr = (hint & ~(gran - 1)); addr > lo; addr -= gran) {
        MEMORY_BASIC_INFORMATION mbi;
        if (!VirtualQueryEx(hProc, (LPCVOID)addr, &mbi, sizeof(mbi))) continue;
        if (mbi.State == MEM_FREE) {
            void* p = VirtualAllocEx(hProc, (LPVOID)addr, size,
                                     MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
            if (p) return (uintptr_t)p;
        }
    }
    for (uintptr_t addr = (hint + gran) & ~(gran - 1); addr < hi; addr += gran) {
        MEMORY_BASIC_INFORMATION mbi;
        if (!VirtualQueryEx(hProc, (LPCVOID)addr, &mbi, sizeof(mbi))) continue;
        if (mbi.State == MEM_FREE) {
            void* p = VirtualAllocEx(hProc, (LPVOID)addr, size,
                                     MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
            if (p) return (uintptr_t)p;
        }
    }
    return 0;
}

static void RemoteWrite(HANDLE hProc, uintptr_t addr, const void* data, size_t size) {
    DWORD old;
    VirtualProtectEx(hProc, (LPVOID)addr, size, PAGE_EXECUTE_READWRITE, &old);
    WriteProcessMemory(hProc, (LPVOID)addr, data, size, nullptr);
    VirtualProtectEx(hProc, (LPVOID)addr, size, old, &old);
}

static void WriteRel32Jmp(HANDLE hProc, uintptr_t from, uintptr_t to, size_t patchLen = 5) {
    std::vector<uint8_t> patch(patchLen, 0x90);
    patch[0] = 0xE9;
    int32_t rel = (int32_t)(to - from - 5);
    memcpy(&patch[1], &rel, 4);
    RemoteWrite(hProc, from, patch.data(), patchLen);
}

template<typename T>
static bool RemoteRead(HANDLE hProc, uintptr_t addr, T& out) {
    SIZE_T r;
    return ReadProcessMemory(hProc, (LPCVOID)addr, &out, sizeof(T), &r) && r == sizeof(T);
}

template<typename T>
static bool RemoteWrite(HANDLE hProc, uintptr_t addr, const T& val) {
    SIZE_T r;
    DWORD old;
    VirtualProtectEx(hProc, (LPVOID)addr, sizeof(T), PAGE_EXECUTE_READWRITE, &old);
    bool ok = WriteProcessMemory(hProc, (LPVOID)addr, &val, sizeof(T), &r);
    VirtualProtectEx(hProc, (LPVOID)addr, sizeof(T), old, &old);
    return ok && r == sizeof(T);
}

// ── Hook state ────────────────────────────────────────────────────────────────

struct HookSite {
    uintptr_t origAddr  = 0;
    uintptr_t caveAddr  = 0;
    uint8_t   origBytes[16] = {};
    size_t    origLen   = 0;
    bool      installed = false;
};

// ── Feature ───────────────────────────────────────────────────────────────────

struct Feature {
    TrainerFeatureInfo info;
    std::atomic<bool>  enabled{false};
    std::atomic<int>   vk_code{0};
    Feature(const char* id_, const char* n, const char* d, int tog, int vk)
        : info{id_, n, d, tog, vk}, vk_code(vk) {}
};

// ── Trainer class ─────────────────────────────────────────────────────────────

class StardewTrainer {
public:
    StardewTrainer()
        : m_running(false), m_hProc(nullptr), m_farmerPtr(0) {
        m_features.emplace_back("lock_health",   "Lock Health",       "Keep health at maximum",         1, VK_F1);
        m_features.emplace_back("lock_stamina",  "Lock Stamina",      "Keep stamina at maximum",        1, VK_F2);
        m_features.emplace_back("add_money",     "Add $10,000",       "Add $10,000 to wallet",          0, VK_F3);
        m_features.emplace_back("instant_bite",  "Instant Bite",      "Fish bite immediately",          1, VK_F4);
        m_features.emplace_back("instant_catch", "Instant Catch",     "Fishing bar always full",        1, VK_F5);
        m_features.emplace_back("max_quality",   "Max Fish Quality",  "Iridium quality + treasure",     1, VK_F6);
        m_features.emplace_back("speed_hack",    "Speed Hack",        "Add +10 movement speed bonus",   1, VK_F7);

        // Cache stable pointers into list nodes
        auto it = m_features.begin();
        m_fLockHealth   = &(*it++);
        m_fLockStamina  = &(*it++);
        m_fAddMoney     = &(*it++);
        m_fInstantBite  = &(*it++);
        m_fInstantCatch = &(*it++);
        m_fMaxQuality   = &(*it++);
        m_fSpeedHack    = &(*it++);
    }

    ~StardewTrainer() { Shutdown(); }

    bool Initialize() {
        DWORD pid = FindPid(L"Stardew Valley.exe");
        if (!pid) {
            OutputDebugStringA("[StardewTrainer] Process not found\n");
            return false;
        }

        m_hProc = OpenProcess(
            PROCESS_VM_READ | PROCESS_VM_WRITE |
            PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION,
            FALSE, pid);
        if (!m_hProc) {
            char buf[64];
            wsprintfA(buf, "[StardewTrainer] OpenProcess failed, error: %lu\n", GetLastError());
            OutputDebugStringA(buf);
            return false;
        }

        uintptr_t base = GetMainModuleBase(m_hProc, L"Stardew Valley.exe");
        if (!base) {
            OutputDebugStringA("[StardewTrainer] GetMainModuleBase failed\n");
            Cleanup(); return false;
        }
        size_t modSize = GetModuleSize(m_hProc, base);
        if (!modSize) {
            OutputDebugStringA("[StardewTrainer] GetModuleSize failed\n");
            Cleanup(); return false;
        }

        if (!InstallHooks(base, modSize)) {
            OutputDebugStringA("[StardewTrainer] InstallHooks failed (AOB mismatch?)\n");
            Cleanup(); return false;
        }

        m_running = true;
        m_thread  = std::thread(&StardewTrainer::Loop, this);
        return true;
    }

    void Shutdown() {
        m_running = false;
        if (m_thread.joinable()) m_thread.join();
        RemoveHooks();
        Cleanup();
    }

    const char* GetName()    const { return "Stardew Valley Trainer"; }
    const char* GetVersion() const { return "1.0.0"; }

    int GetFeatureCount() const { return (int)m_features.size(); }

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

    void ActivateFeature(const char* id) {
        if (strcmp(id, "add_money") == 0) {
            uintptr_t farmer = m_farmerPtr;
            if (farmer) AddMoney(farmer, 10000);
        }
    }

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
    std::atomic<bool>   m_running;
    HANDLE              m_hProc;
    volatile uintptr_t  m_farmerPtr;
    std::thread         m_thread;
    std::list<Feature>  m_features;

    Feature* m_fLockHealth   = nullptr;
    Feature* m_fLockStamina  = nullptr;
    Feature* m_fAddMoney     = nullptr;
    Feature* m_fInstantBite  = nullptr;
    Feature* m_fInstantCatch = nullptr;
    Feature* m_fMaxQuality   = nullptr;
    Feature* m_fSpeedHack    = nullptr;

    HookSite   m_hkUpdate;
    HookSite   m_hkBite;
    HookSite   m_hkCatch;
    HookSite   m_hkQuality;
    uintptr_t  m_speedCaveAddr  = 0;
    uintptr_t  m_speedOrigAddr  = 0;
    uint8_t    m_speedOrigBytes[8] = {};
    bool       m_speedInstalled = false;

    void Cleanup() {
        if (m_hProc) { CloseHandle(m_hProc); m_hProc = nullptr; }
    }

    // ── Hook install ──────────────────────────────────────────────────────────

    bool InstallHooks(uintptr_t base, size_t modSize) {
        // ── 1. Game1::Update ─────────────────────────────────────────────────
        {
            static const uint8_t PAT[] = { 0x57,0x56,0x55,0x53,0x48,0x81,0xEC,0x28,0x01,0x00,0x00 };
            static const uint8_t MSK[] = { 1,1,1,1,1,1,1,1,1,1,1 };
            uintptr_t addr = AobFirst(m_hProc, base, modSize, PAT, MSK, sizeof(PAT));
            if (!addr) return false;

            m_hkUpdate.origAddr = addr;
            m_hkUpdate.origLen  = 11;
            ReadProcessMemory(m_hProc, (LPCVOID)addr, m_hkUpdate.origBytes, 11, nullptr);

            uintptr_t cave = AllocNear(m_hProc, addr, 64);
            if (!cave) return false;
            m_hkUpdate.caveAddr = cave;

            std::vector<uint8_t> caveBytes(16, 0x90);
            memcpy(caveBytes.data(), PAT, 11);
            caveBytes[11] = 0xE9;
            int32_t rel = (int32_t)((addr + 11) - (cave + 11) - 5);
            memcpy(&caveBytes[12], &rel, 4);
            RemoteWrite(m_hProc, cave, caveBytes.data(), 16);
            WriteRel32Jmp(m_hProc, addr, cave, 11);
            m_hkUpdate.installed = true;
        }

        // ── 2. Farmer::getMovementSpeed — captures farmer ptr (rcx = this) ───
        {
            static const uint8_t PAT[] = { 0x56,0x48,0x83,0xEC,0x60,0xC5,0xF8,0x77 };
            static const uint8_t MSK[] = { 1,1,1,1,1,1,1,1 };
            uintptr_t addr = AobFirst(m_hProc, base, modSize, PAT, MSK, sizeof(PAT));
            if (!addr) return false;

            uintptr_t cave = AllocNear(m_hProc, addr, 128);
            if (!cave) return false;

            uint8_t caveBytes[128] = {};
            caveBytes[0x00] = 0x50;
            caveBytes[0x01] = 0x48; caveBytes[0x02] = 0x8D; caveBytes[0x03] = 0x05;
            int32_t leaOff = (int32_t)(0x40 - 0x08);
            memcpy(&caveBytes[0x04], &leaOff, 4);
            caveBytes[0x08] = 0x48; caveBytes[0x09] = 0x89; caveBytes[0x0A] = 0x08;
            caveBytes[0x0B] = 0x58;
            memcpy(&caveBytes[0x0C], PAT, 8);
            caveBytes[0x14] = 0xE9;
            int32_t rel = (int32_t)((addr + 8) - (cave + 0x14) - 5);
            memcpy(&caveBytes[0x15], &rel, 4);

            RemoteWrite(m_hProc, cave, caveBytes, sizeof(caveBytes));
            m_speedCaveAddr  = cave;
            m_speedOrigAddr  = addr;
            memcpy(m_speedOrigBytes, PAT, 8);
            m_speedInstalled = true;
            WriteRel32Jmp(m_hProc, addr, cave, 8);
        }

        // ── 3. calculateTimeUntilFishingBite — instant bite ───────────────────
        {
            static const uint8_t PAT[] = { 0x41,0x57,0x41,0x56,0x57,0x56,0x55,0x53,0x48,0x83,0xEC,0x38,0xC5,0xF8,0x77 };
            static const uint8_t MSK[] = { 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1 };
            uintptr_t addr = AobFirst(m_hProc, base, modSize, PAT, MSK, sizeof(PAT));
            if (addr) {
                m_hkBite.origAddr = addr;
                m_hkBite.origLen  = 5;
                ReadProcessMemory(m_hProc, (LPCVOID)addr, m_hkBite.origBytes, 5, nullptr);

                uintptr_t cave = AllocNear(m_hProc, addr, 64);
                if (cave) {
                    m_hkBite.caveAddr = cave;
                    uint8_t caveBytes[32] = {};
                    caveBytes[0] = 0x66; caveBytes[1] = 0x0F; caveBytes[2] = 0xEF; caveBytes[3] = 0xC0;
                    caveBytes[4] = 0xC3;
                    memcpy(&caveBytes[8], m_hkBite.origBytes, 5);
                    caveBytes[13] = 0xE9;
                    int32_t rel = (int32_t)((addr + 5) - (cave + 13) - 5);
                    memcpy(&caveBytes[14], &rel, 4);
                    RemoteWrite(m_hProc, cave, caveBytes, sizeof(caveBytes));
                    m_hkBite.installed = true;
                }
            }
        }

        // ── 4. BobberBar::update+19B9 — instant catch ────────────────────────
        {
            static const uint8_t PAT[] = { 0xC5,0xFA,0x10,0x86,0xC8,0x00,0x00,0x00 };
            static const uint8_t MSK[] = { 1,1,1,1,1,1,1,1 };
            uintptr_t addr = AobFirst(m_hProc, base, modSize, PAT, MSK, sizeof(PAT));
            if (addr) {
                m_hkCatch.origAddr = addr;
                m_hkCatch.origLen  = 8;
                ReadProcessMemory(m_hProc, (LPCVOID)addr, m_hkCatch.origBytes, 8, nullptr);

                uintptr_t cave = AllocNear(m_hProc, addr, 64);
                if (cave) {
                    m_hkCatch.caveAddr = cave;
                    uint8_t caveBytes[32] = {};
                    caveBytes[0] = 0xC7; caveBytes[1] = 0x86;
                    caveBytes[2] = 0xC8; caveBytes[3] = 0x00; caveBytes[4] = 0x00; caveBytes[5] = 0x00;
                    caveBytes[6] = 0x00; caveBytes[7] = 0x00; caveBytes[8] = 0x80; caveBytes[9] = 0x3F;
                    memcpy(&caveBytes[10], PAT, 8);
                    caveBytes[18] = 0xE9;
                    int32_t rel = (int32_t)((addr + 8) - (cave + 18) - 5);
                    memcpy(&caveBytes[19], &rel, 4);
                    RemoteWrite(m_hProc, cave, caveBytes, sizeof(caveBytes));
                    m_hkCatch.installed = true;
                }
            }
        }

        // ── 5. doPullFishFromWater+FE — force Iridium quality + treasure ──────
        {
            static const uint8_t PAT[] = { 0x44,0x88,0xAE,0xCC,0xCC,0xCC,0xCC,0x44,0x89,0xB6 };
            static const uint8_t MSK[] = { 1,1,1,0,0,0,0,1,1,1 };
            uintptr_t addr = AobFirst(m_hProc, base, modSize, PAT, MSK, sizeof(PAT));
            if (addr) {
                m_hkQuality.origAddr = addr;
                m_hkQuality.origLen  = 7;
                ReadProcessMemory(m_hProc, (LPCVOID)addr, m_hkQuality.origBytes, 7, nullptr);

                uintptr_t cave = AllocNear(m_hProc, addr, 64);
                if (cave) {
                    m_hkQuality.caveAddr = cave;
                    uint8_t caveBytes[32] = {};
                    size_t off = 0;
                    caveBytes[off++] = 0x41; caveBytes[off++] = 0xB5; caveBytes[off++] = 0x01;
                    caveBytes[off++] = 0x41; caveBytes[off++] = 0xBF;
                    caveBytes[off++] = 0x04; caveBytes[off++] = 0x00; caveBytes[off++] = 0x00; caveBytes[off++] = 0x00;
                    memcpy(&caveBytes[off], m_hkQuality.origBytes, 7); off += 7;
                    caveBytes[off++] = 0xE9;
                    int32_t rel = (int32_t)((addr + 7) - (cave + off) - 4);
                    memcpy(&caveBytes[off], &rel, 4);
                    RemoteWrite(m_hProc, cave, caveBytes, sizeof(caveBytes));
                    m_hkQuality.installed = true;
                }
            }
        }

        return true;
    }

    void RemoveHooks() {
        auto restore = [&](HookSite& h) {
            if (h.installed && h.origAddr && m_hProc) {
                RemoteWrite(m_hProc, h.origAddr, h.origBytes, h.origLen);
                if (h.caveAddr) VirtualFreeEx(m_hProc, (LPVOID)h.caveAddr, 0, MEM_RELEASE);
            }
            h = {};
        };
        restore(m_hkUpdate);
        restore(m_hkBite);
        restore(m_hkCatch);
        restore(m_hkQuality);

        if (m_speedInstalled && m_speedOrigAddr && m_hProc) {
            RemoteWrite(m_hProc, m_speedOrigAddr, m_speedOrigBytes, 8);
            if (m_speedCaveAddr) VirtualFreeEx(m_hProc, (LPVOID)m_speedCaveAddr, 0, MEM_RELEASE);
        }
        m_speedInstalled = false;
        m_speedOrigAddr  = 0;
        m_speedCaveAddr  = 0;
    }

    // ── Hook enable/disable ───────────────────────────────────────────────────

    void EnableHook(HookSite& h) {
        if (!h.installed || !m_hProc) return;
        WriteRel32Jmp(m_hProc, h.origAddr, h.caveAddr, h.origLen);
    }

    void DisableHook(HookSite& h) {
        if (!h.installed || !m_hProc) return;
        RemoteWrite(m_hProc, h.origAddr, h.origBytes, h.origLen);
    }

    // ── Stat helpers ──────────────────────────────────────────────────────────

    uintptr_t ReadFarmerPtr() {
        if (!m_speedCaveAddr) return 0;
        uintptr_t ptr = 0;
        RemoteRead(m_hProc, m_speedCaveAddr + 0x40, ptr);
        return ptr;
    }

    void LockHealth(uintptr_t farmer) {
        int32_t maxHp = 0;
        if (!RemoteRead(m_hProc, farmer + OFF_MAX_HEALTH, maxHp) || maxHp <= 0) return;
        RemoteWrite(m_hProc, farmer + OFF_HEALTH, maxHp);
    }

    void LockStamina(uintptr_t farmer) {
        uintptr_t netStaminaPtr = 0;
        if (!RemoteRead(m_hProc, farmer + OFF_NET_STAMINA_PTR, netStaminaPtr) || !netStaminaPtr) return;
        uintptr_t maxStaminaPtr = 0;
        if (!RemoteRead(m_hProc, farmer + OFF_MAX_STAMINA_PTR, maxStaminaPtr) || !maxStaminaPtr) return;
        int32_t maxStam = 0;
        if (!RemoteRead(m_hProc, maxStaminaPtr + OFF_NETINT_VALUE, maxStam) || maxStam <= 0) return;
        float maxStamF = static_cast<float>(maxStam);
        RemoteWrite(m_hProc, netStaminaPtr + OFF_NETFLOAT_VALUE, maxStamF);
    }

    void AddMoney(uintptr_t farmer, int32_t amount) {
        uintptr_t teamRootPtr = 0;
        if (!RemoteRead(m_hProc, farmer + OFF_TEAM_ROOT_PTR, teamRootPtr) || !teamRootPtr) return;
        uintptr_t teamPtr = 0;
        if (!RemoteRead(m_hProc, teamRootPtr + OFF_NETREF_VALUE, teamPtr) || !teamPtr) return;
        uintptr_t moneyNetPtr = 0;
        if (!RemoteRead(m_hProc, teamPtr + OFF_TEAM_MONEY_PTR, moneyNetPtr) || !moneyNetPtr) return;
        int32_t current = 0;
        RemoteRead(m_hProc, moneyNetPtr + OFF_NETINT_VALUE, current);
        RemoteWrite(m_hProc, moneyNetPtr + OFF_NETINT_VALUE, current + amount);
    }

    void SetSpeedBonus(uintptr_t farmer, int32_t bonus) {
        uintptr_t netSpeedPtr = 0;
        if (!RemoteRead(m_hProc, farmer + OFF_NET_SPEED_PTR, netSpeedPtr) || !netSpeedPtr) return;
        RemoteWrite(m_hProc, netSpeedPtr + OFF_NETINT_VALUE, bonus);
    }

    // ── Main loop ─────────────────────────────────────────────────────────────

    void Loop() {
        bool prevBite    = false;
        bool prevCatch   = false;
        bool prevQuality = false;
        bool prevSpeed   = false;

        while (m_running) {
            // Refresh farmer pointer
            uintptr_t farmer = ReadFarmerPtr();
            if (farmer) m_farmerPtr = farmer;
            farmer = m_farmerPtr;

            // Hotkey dispatch
            for (auto& f : m_features) {
                int vk = f.vk_code.load();
                if (vk && (GetAsyncKeyState(vk) & 1)) {
                    if (f.info.is_toggle)
                        f.enabled = !f.enabled.load();
                    else
                        ActivateFeature(f.info.id);
                }
            }

            // Apply hook patches on toggle state change
            bool bite = m_fInstantBite->enabled.load();
            if (bite != prevBite) {
                if (bite) EnableHook(m_hkBite); else DisableHook(m_hkBite);
                prevBite = bite;
            }
            bool cat = m_fInstantCatch->enabled.load();
            if (cat != prevCatch) {
                if (cat) EnableHook(m_hkCatch); else DisableHook(m_hkCatch);
                prevCatch = cat;
            }
            bool qual = m_fMaxQuality->enabled.load();
            if (qual != prevQuality) {
                if (qual) EnableHook(m_hkQuality); else DisableHook(m_hkQuality);
                prevQuality = qual;
            }

            // Continuous stat locks
            if (farmer) {
                if (m_fLockHealth->enabled.load())  LockHealth(farmer);
                if (m_fLockStamina->enabled.load()) LockStamina(farmer);

                bool spd = m_fSpeedHack->enabled.load();
                if (spd != prevSpeed) {
                    SetSpeedBonus(farmer, spd ? 10 : 0);
                    prevSpeed = spd;
                }
            }

            Sleep(100);
        }

        // Shutdown: restore all active patches
        if (m_fInstantBite->enabled.load())  DisableHook(m_hkBite);
        if (m_fInstantCatch->enabled.load()) DisableHook(m_hkCatch);
        if (m_fMaxQuality->enabled.load())   DisableHook(m_hkQuality);
        if (m_fSpeedHack->enabled.load() && m_farmerPtr) SetSpeedBonus(m_farmerPtr, 0);
    }
};

// ── C ABI exports ─────────────────────────────────────────────────────────────

extern "C" {

void* trainer_create()            { return new StardewTrainer(); }
void  trainer_destroy(void* h)    { delete static_cast<StardewTrainer*>(h); }
int   trainer_initialize(void* h) { return static_cast<StardewTrainer*>(h)->Initialize() ? 1 : 0; }
void  trainer_shutdown(void* h)   { static_cast<StardewTrainer*>(h)->Shutdown(); }

const char* trainer_get_name(void* h)    { return static_cast<StardewTrainer*>(h)->GetName(); }
const char* trainer_get_version(void* h) { return static_cast<StardewTrainer*>(h)->GetVersion(); }

int trainer_get_feature_count(void* h)
    { return static_cast<StardewTrainer*>(h)->GetFeatureCount(); }
const TrainerFeatureInfo* trainer_get_feature_info(void* h, int idx)
    { return static_cast<StardewTrainer*>(h)->GetFeatureInfo(idx); }
int trainer_get_feature_enabled(void* h, const char* id)
    { return static_cast<StardewTrainer*>(h)->GetFeatureEnabled(id); }
void trainer_set_feature_enabled(void* h, const char* id, int en)
    { static_cast<StardewTrainer*>(h)->SetFeatureEnabled(id, en); }
void trainer_activate_feature(void* h, const char* id)
    { static_cast<StardewTrainer*>(h)->ActivateFeature(id); }
void trainer_set_keybind(void* h, const char* id, int vk)
    { static_cast<StardewTrainer*>(h)->SetKeybind(id, vk); }
int trainer_get_keybind(void* h, const char* id)
    { return static_cast<StardewTrainer*>(h)->GetKeybind(id); }

} // extern "C"
