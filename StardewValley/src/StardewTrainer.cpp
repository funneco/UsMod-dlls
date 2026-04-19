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
#include <thread>
#include <atomic>
#include <cstdint>
#include <cstring>

// ── .NET Farmer field offsets ─────────────────────────────────────────────────
static constexpr ptrdiff_t OFF_HEALTH           = 0x178; // int health
static constexpr ptrdiff_t OFF_MAX_HEALTH       = 0x17C; // int maxHealth
static constexpr ptrdiff_t OFF_NET_STAMINA_PTR  = 0x198; // NetFloat* netStamina
static constexpr ptrdiff_t OFF_NETFLOAT_VALUE   = 0x10;  // float within NetFloat
static constexpr ptrdiff_t OFF_MAX_STAMINA_PTR  = 0x1A0; // NetInt*  MaxStamina
static constexpr ptrdiff_t OFF_NETINT_VALUE     = 0x10;  // int  within NetInt
static constexpr ptrdiff_t OFF_NET_SPEED_PTR    = 0x1B0; // NetInt* netSpeed
static constexpr ptrdiff_t OFF_TEAM_ROOT_PTR    = 0x148; // NetRef<FarmerTeam>* teamRoot
static constexpr ptrdiff_t OFF_NETREF_VALUE     = 0x18;  // T* within NetRef<T>
static constexpr ptrdiff_t OFF_TEAM_MONEY_PTR   = 0x150; // NetInt* money  (in FarmerTeam)

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

// Scan the entire module image for a byte pattern (wildcard = 0xCC in mask).
static uintptr_t AobFirst(HANDLE hProc, uintptr_t base, size_t size,
                           const uint8_t* pat, const uint8_t* mask, size_t len) {
    constexpr size_t CHUNK = 0x100000; // 1 MB chunks to avoid huge allocs
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

// Allocate executable memory near target (within ±2 GB for rel32 JMP).
static uintptr_t AllocNear(HANDLE hProc, uintptr_t near, size_t size) {
    SYSTEM_INFO si; GetSystemInfo(&si);
    const uintptr_t gran = si.dwAllocationGranularity;
    const uintptr_t lo = (near > 0x7FF00000ULL) ? near - 0x7FF00000ULL : (uintptr_t)si.lpMinimumApplicationAddress;
    const uintptr_t hi = near + 0x7FF00000ULL;

    // Search downward first
    for (uintptr_t addr = (near & ~(gran - 1)); addr > lo; addr -= gran) {
        MEMORY_BASIC_INFORMATION mbi;
        if (!VirtualQueryEx(hProc, (LPCVOID)addr, &mbi, sizeof(mbi))) continue;
        if (mbi.State == MEM_FREE) {
            void* p = VirtualAllocEx(hProc, (LPVOID)addr, size,
                                     MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
            if (p) return (uintptr_t)p;
        }
    }
    // Then upward
    for (uintptr_t addr = (near + gran) & ~(gran - 1); addr < hi; addr += gran) {
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
    std::vector<uint8_t> patch(patchLen, 0x90); // NOPs
    patch[0] = 0xE9;
    int32_t rel = (int32_t)(to - from - 5);
    memcpy(&patch[1], &rel, 4);
    RemoteWrite(hProc, from, patch.data(), patchLen);
}

// Helpers for reading typed values from target process
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

// ── Trainer class ─────────────────────────────────────────────────────────────

class StardewTrainer {
public:
    StardewTrainer()
        : m_running(false), m_hProc(nullptr), m_farmerPtr(0) {}

    ~StardewTrainer() { Shutdown(); }

    bool Initialize() {
        DWORD pid = FindPid(L"Stardew Valley.exe");
        if (!pid) return false;

        m_hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
        if (!m_hProc) return false;

        uintptr_t base = GetMainModuleBase(m_hProc, L"Stardew Valley.exe");
        if (!base) { Cleanup(); return false; }
        size_t modSize = GetModuleSize(m_hProc, base);
        if (!modSize) { Cleanup(); return false; }

        if (!InstallHooks(base, modSize)) { Cleanup(); return false; }

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

private:
    std::atomic<bool> m_running;
    HANDLE            m_hProc;
    volatile uintptr_t m_farmerPtr;
    std::thread       m_thread;

    // Feature toggles
    std::atomic<bool> m_lockHealth   {false};
    std::atomic<bool> m_lockStamina  {false};
    std::atomic<bool> m_instantBite  {false};
    std::atomic<bool> m_instantCatch {false};
    std::atomic<bool> m_maxFishQual  {false};
    std::atomic<bool> m_speedHack    {false};

    // Hook sites
    HookSite m_hkUpdate;    // Game1::Update  → farmer ptr refresh
    HookSite m_hkBite;      // calculateTimeUntilFishingBite → instant bite
    HookSite m_hkCatch;     // BobberBar::update+19B9 → instant catch
    HookSite m_hkQuality;   // doPullFishFromWater+FE → max quality

    void Cleanup() {
        if (m_hProc) { CloseHandle(m_hProc); m_hProc = nullptr; }
    }

    // ── Hook install ──────────────────────────────────────────────────────────

    bool InstallHooks(uintptr_t base, size_t modSize) {
        // ── 1. Game1::Update ─ captures farmer ptr each frame ─────────────────
        // assert: 57 56 55 53 48 81 EC 28 01 00 00  (11 bytes)
        {
            static const uint8_t PAT[] = { 0x57,0x56,0x55,0x53,0x48,0x81,0xEC,0x28,0x01,0x00,0x00 };
            static const uint8_t MSK[] = { 1,1,1,1,1,1,1,1,1,1,1 };
            uintptr_t addr = AobFirst(m_hProc, base, modSize, PAT, MSK, sizeof(PAT));
            if (!addr) return false;

            m_hkUpdate.origAddr = addr;
            m_hkUpdate.origLen  = 11;
            ReadProcessMemory(m_hProc, (LPCVOID)addr, m_hkUpdate.origBytes, 11, nullptr);

            // Cave layout:
            //   +00: push rax                                     (1)
            //   +01: mov rax, imm64 (&m_farmerPtr as seen from trainer)
            //        We use a shared memory location: cave+0x80 as farmer ptr storage
            //   We write the farmer ptr address into cave+0x80 for polling by the host.
            //   But we're EXTERNAL — we can't share memory directly with a cave in the target.
            //   Instead: cave writes farmer ptr to a known cave offset, host polls via ReadProcessMemory.
            //
            //   Since get_player() is a .NET static method (not take rcx),
            //   and the CE hook calls it explicitly, we cannot trivially replicate that here.
            //   Instead we hook via getMovementSpeed (instance method, rcx = Farmer*).
            //   The Update hook is only used here to confirm the module is live.
            //   Farmer ptr captured in the speed hook below.
            //   We still install this hook to match CE's struct resolver timing,
            //   but the cave just executes the original prologue and returns.
            //
            // Minimal cave: original 11 bytes + jmp back
            uintptr_t cave = AllocNear(m_hProc, addr, 64);
            if (!cave) return false;
            m_hkUpdate.caveAddr = cave;

            // Write cave: original bytes + jmp back to addr+11
            std::vector<uint8_t> caveBytes(16, 0x90);
            memcpy(caveBytes.data(), PAT, 11);
            // jmp addr+11
            caveBytes[11] = 0xE9;
            int32_t rel = (int32_t)((addr + 11) - (cave + 11) - 5);
            memcpy(&caveBytes[12], &rel, 4);
            RemoteWrite(m_hProc, cave, caveBytes.data(), 16);
            WriteRel32Jmp(m_hProc, addr, cave, 11);
            m_hkUpdate.installed = true;
        }

        // ── 2. Farmer::getMovementSpeed ─ captures farmer ptr (rcx = this) ───
        // assert: 56 48 83 EC 60 C5 F8 77  (8 bytes to save)
        // This is an instance method; rcx = Farmer* at entry.
        // Cave allocates a 8-byte slot at cave+0x40 to store the ptr.
        // Host polls cave+0x40 via ReadProcessMemory every loop tick.
        {
            static const uint8_t PAT[] = { 0x56,0x48,0x83,0xEC,0x60,0xC5,0xF8,0x77 };
            static const uint8_t MSK[] = { 1,1,1,1,1,1,1,1 };
            uintptr_t addr = AobFirst(m_hProc, base, modSize, PAT, MSK, sizeof(PAT));
            if (!addr) return false;

            // We reuse m_hkUpdate's concept but a new separate cave.
            // Cave layout (64 bytes):
            //   +00: push rax                    50
            //   +01: lea rax, [rip+0x37]          48 8D 05 37 00 00 00  (points to +0x40)
            //   +08: mov [rax], rcx               48 89 08
            //   +0B: pop rax                      58
            //   +0C: 56 48 83 EC 60 C5 F8 77      original 8 bytes
            //   +14: E9 ?? ?? ?? ??               jmp back to addr+8
            //   ...
            //   +40: dq 0                         farmer ptr storage
            uintptr_t cave = AllocNear(m_hProc, addr, 128);
            if (!cave) return false;

            uint8_t caveBytes[128] = {};

            // +00  push rax
            caveBytes[0x00] = 0x50;
            // +01  lea rax, [rip+0x37]  → points to cave+0x40 (rip = cave+0x08 after 7-byte instr)
            // cave+0x08 + 0x38 = cave+0x40  → offset = 0x38
            caveBytes[0x01] = 0x48; caveBytes[0x02] = 0x8D; caveBytes[0x03] = 0x05;
            int32_t leaOff = (int32_t)(0x40 - 0x08);  // 0x38
            memcpy(&caveBytes[0x04], &leaOff, 4);
            // +08  mov [rax], rcx
            caveBytes[0x08] = 0x48; caveBytes[0x09] = 0x89; caveBytes[0x0A] = 0x08;
            // +0B  pop rax
            caveBytes[0x0B] = 0x58;
            // +0C  original 8 bytes
            memcpy(&caveBytes[0x0C], PAT, 8);
            // +14  jmp addr+8
            caveBytes[0x14] = 0xE9;
            int32_t rel = (int32_t)((addr + 8) - (cave + 0x14) - 5);
            memcpy(&caveBytes[0x15], &rel, 4);
            // +40  farmer ptr (initially 0)
            // (already zeroed)

            RemoteWrite(m_hProc, cave, caveBytes, sizeof(caveBytes));

            // Save original bytes and patch site info into m_hkUpdate's spare (we use a dedicated field)
            // Store cave address so we can read farmer ptr from cave+0x40
            m_speedCaveAddr = cave;
            m_speedOrigAddr = addr;
            memcpy(m_speedOrigBytes, PAT, 8);
            m_speedInstalled = true;

            WriteRel32Jmp(m_hProc, addr, cave, 8);
        }

        // ── 3. calculateTimeUntilFishingBite ─ instant bite ───────────────────
        // Pattern from ORIGINAL CODE: 41 57 41 56 57 56 55 53 48 83 EC 38 C5 F8 77
        {
            static const uint8_t PAT[] = { 0x41,0x57,0x41,0x56,0x57,0x56,0x55,0x53,0x48,0x83,0xEC,0x38,0xC5,0xF8,0x77 };
            static const uint8_t MSK[] = { 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1 };
            uintptr_t addr = AobFirst(m_hProc, base, modSize, PAT, MSK, sizeof(PAT));
            if (addr) {
                m_hkBite.origAddr = addr;
                m_hkBite.origLen  = 5;
                ReadProcessMemory(m_hProc, (LPCVOID)addr, m_hkBite.origBytes, 5, nullptr);

                // Cave: pxor xmm0,xmm0; ret  (returns 0.0f immediately)
                // Stored in cave+0 when active, original in cave+8
                uintptr_t cave = AllocNear(m_hProc, addr, 64);
                if (cave) {
                    m_hkBite.caveAddr = cave;
                    // cave+0:  pxor xmm0,xmm0  (66 0F EF C0) + ret (C3) = 5 bytes
                    // cave+8:  original 5 bytes + jmp addr+5  (for unhook restore)
                    uint8_t caveBytes[32] = {};
                    // instant return (used when hook active)
                    caveBytes[0] = 0x66; caveBytes[1] = 0x0F; caveBytes[2] = 0xEF; caveBytes[3] = 0xC0; // pxor xmm0,xmm0
                    caveBytes[4] = 0xC3; // ret
                    // trampoline restore (cave+8): orig bytes + jmp back addr+5
                    memcpy(&caveBytes[8], m_hkBite.origBytes, 5);
                    caveBytes[13] = 0xE9;
                    int32_t rel = (int32_t)((addr + 5) - (cave + 13) - 5);
                    memcpy(&caveBytes[14], &rel, 4);
                    RemoteWrite(m_hProc, cave, caveBytes, sizeof(caveBytes));
                    m_hkBite.installed = true;
                    // Hook is NOT active yet — hotkey enables it
                }
            }
        }

        // ── 4. BobberBar::update+19B9 ─ instant catch ────────────────────────
        // assert: C5 FA 10 86 C8 00 00 00
        {
            static const uint8_t PAT[] = { 0xC5,0xFA,0x10,0x86,0xC8,0x00,0x00,0x00 };
            static const uint8_t MSK[] = { 1,1,1,1,1,1,1,1 };
            uintptr_t addr = AobFirst(m_hProc, base, modSize, PAT, MSK, sizeof(PAT));
            if (addr) {
                m_hkCatch.origAddr = addr;
                m_hkCatch.origLen  = 8;
                ReadProcessMemory(m_hProc, (LPCVOID)addr, m_hkCatch.origBytes, 8, nullptr);

                // Cave: write 1.0f to [rsi+0xC8], then load it (original), jmp back
                // C7 86 C8 00 00 00 00 00 80 3F  = mov dword ptr [rsi+C8], 3F800000h  (10 bytes)
                // C5 FA 10 86 C8 00 00 00        = vmovss xmm0,[rsi+C8]               (8 bytes, original)
                // E9 ?? ?? ?? ??                 = jmp addr+8                          (5 bytes)
                uintptr_t cave = AllocNear(m_hProc, addr, 64);
                if (cave) {
                    m_hkCatch.caveAddr = cave;
                    uint8_t caveBytes[32] = {};
                    // mov dword ptr [rsi+0xC8], 0x3F800000 (= 1.0f)
                    caveBytes[0] = 0xC7; caveBytes[1] = 0x86;
                    caveBytes[2] = 0xC8; caveBytes[3] = 0x00; caveBytes[4] = 0x00; caveBytes[5] = 0x00;
                    caveBytes[6] = 0x00; caveBytes[7] = 0x00; caveBytes[8] = 0x80; caveBytes[9] = 0x3F;
                    // vmovss xmm0,[rsi+0xC8]  (original)
                    memcpy(&caveBytes[10], PAT, 8);
                    // jmp addr+8
                    caveBytes[18] = 0xE9;
                    int32_t rel = (int32_t)((addr + 8) - (cave + 18) - 5);
                    memcpy(&caveBytes[19], &rel, 4);
                    RemoteWrite(m_hProc, cave, caveBytes, sizeof(caveBytes));
                    m_hkCatch.installed = true;
                }
            }
        }

        // ── 5. doPullFishFromWater+FE ─ force quality=Iridium, treasure=true ─
        // From CE ORIGINAL CODE:
        //   +FE:  44 88 AE 83 01 00 00  → mov [rsi+183h], r13l  (treasure flag)
        //   +105: 44 89 B6 5C 01 00 00  → mov [rsi+15Ch], r14d  (size)
        //   +10C: 44 89 BE 64 01 00 00  → mov [rsi+164h], r15d  (quality)
        // assert: 44 88 AE ?? ?? ?? ?? 44 89 B6
        {
            static const uint8_t PAT[] = { 0x44,0x88,0xAE,0xCC,0xCC,0xCC,0xCC,0x44,0x89,0xB6 };
            static const uint8_t MSK[] = { 1,1,1,0,0,0,0,1,1,1 };
            uintptr_t addr = AobFirst(m_hProc, base, modSize, PAT, MSK, sizeof(PAT));
            if (addr) {
                m_hkQuality.origAddr = addr;
                m_hkQuality.origLen  = 7;
                ReadProcessMemory(m_hProc, (LPCVOID)addr, m_hkQuality.origBytes, 7, nullptr);

                // Cave:
                //   41 B5 01               mov r13l, 1       (treasure = true)
                //   41 BF 04 00 00 00      mov r15d, 4       (quality = Iridium)
                //   <original 7 bytes>     mov [rsi+???], r13l
                //   E9 ?? ?? ?? ??         jmp addr+7
                uintptr_t cave = AllocNear(m_hProc, addr, 64);
                if (cave) {
                    m_hkQuality.caveAddr = cave;
                    uint8_t caveBytes[32] = {};
                    size_t off = 0;
                    // mov r13l, 1
                    caveBytes[off++] = 0x41; caveBytes[off++] = 0xB5; caveBytes[off++] = 0x01;
                    // mov r15d, 4
                    caveBytes[off++] = 0x41; caveBytes[off++] = 0xBF;
                    caveBytes[off++] = 0x04; caveBytes[off++] = 0x00; caveBytes[off++] = 0x00; caveBytes[off++] = 0x00;
                    // original 7 bytes
                    memcpy(&caveBytes[off], m_hkQuality.origBytes, 7); off += 7;
                    // jmp addr+7
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

    // ── Feature toggles ───────────────────────────────────────────────────────

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
        // netStamina is NetFloat*; value is a float at NetFloat + OFF_NETFLOAT_VALUE
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
        int32_t newVal = current + amount;
        RemoteWrite(m_hProc, moneyNetPtr + OFF_NETINT_VALUE, newVal);
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

            // ── Hotkeys (edge-triggered) ──────────────────────────────────────
            // F1: Lock health
            if (GetAsyncKeyState(VK_F1) & 1) m_lockHealth = !m_lockHealth;
            // F2: Lock stamina
            if (GetAsyncKeyState(VK_F2) & 1) m_lockStamina = !m_lockStamina;
            // F3: Add $10,000
            if ((GetAsyncKeyState(VK_F3) & 1) && farmer)
                AddMoney(farmer, 10000);
            // F4: Instant fish bite toggle
            if (GetAsyncKeyState(VK_F4) & 1) m_instantBite = !m_instantBite.load();
            // F5: Instant catch toggle
            if (GetAsyncKeyState(VK_F5) & 1) m_instantCatch = !m_instantCatch.load();
            // F6: Max quality toggle
            if (GetAsyncKeyState(VK_F6) & 1) m_maxFishQual = !m_maxFishQual.load();
            // F7: Speed hack toggle
            if (GetAsyncKeyState(VK_F7) & 1) m_speedHack = !m_speedHack.load();

            // ── Toggle hook patches on state change ───────────────────────────
            bool bite = m_instantBite.load();
            if (bite != prevBite) {
                if (bite) EnableHook(m_hkBite); else DisableHook(m_hkBite);
                prevBite = bite;
            }
            bool cat = m_instantCatch.load();
            if (cat != prevCatch) {
                if (cat) EnableHook(m_hkCatch); else DisableHook(m_hkCatch);
                prevCatch = cat;
            }
            bool qual = m_maxFishQual.load();
            if (qual != prevQuality) {
                if (qual) EnableHook(m_hkQuality); else DisableHook(m_hkQuality);
                prevQuality = qual;
            }

            // ── Continuous stat locks ─────────────────────────────────────────
            if (farmer) {
                if (m_lockHealth)  LockHealth(farmer);
                if (m_lockStamina) LockStamina(farmer);

                bool spd = m_speedHack.load();
                if (spd != prevSpeed) {
                    SetSpeedBonus(farmer, spd ? 10 : 0);
                    prevSpeed = spd;
                }
            }

            Sleep(100);
        }

        // On shutdown: disable all active patches
        if (m_instantBite)  DisableHook(m_hkBite);
        if (m_instantCatch) DisableHook(m_hkCatch);
        if (m_maxFishQual)  DisableHook(m_hkQuality);
        if (m_speedHack && m_farmerPtr) SetSpeedBonus(m_farmerPtr, 0);
    }

    // Extra state for speed hook (doesn't use HookSite struct due to cave ptr storage)
    uintptr_t m_speedCaveAddr  = 0;
    uintptr_t m_speedOrigAddr  = 0;
    uint8_t   m_speedOrigBytes[8] = {};
    bool      m_speedInstalled = false;
};

// ── C ABI exports ─────────────────────────────────────────────────────────────

extern "C" {

void* trainer_create() {
    return new StardewTrainer();
}
void trainer_destroy(void* h) {
    delete static_cast<StardewTrainer*>(h);
}
int trainer_initialize(void* h) {
    return static_cast<StardewTrainer*>(h)->Initialize() ? 1 : 0;
}
void trainer_shutdown(void* h) {
    static_cast<StardewTrainer*>(h)->Shutdown();
}
const char* trainer_get_name(void* h) {
    return static_cast<StardewTrainer*>(h)->GetName();
}
const char* trainer_get_version(void* h) {
    return static_cast<StardewTrainer*>(h)->GetVersion();
}

} // extern "C"
