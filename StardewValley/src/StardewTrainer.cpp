#include <windows.h>
#include <tlhelp32.h>
#include <algorithm>
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

// --- Process utilities ---

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
    return ok && r == size;
}

static bool MemRead(HANDLE hProc, uintptr_t addr, void* data, size_t size) {
    SIZE_T r;
    return ReadProcessMemory(hProc, (LPCVOID)addr, data, size, &r) && r == size;
}

// mask: 'x' = match exact byte, '?' = wildcard
static uintptr_t AobScan(HANDLE hProc, uintptr_t start, uintptr_t end,
                          const uint8_t* pattern, const char* mask) {
    size_t patLen = strlen(mask);
    std::vector<uint8_t> chunk(0x10000);
    for (uintptr_t addr = start; addr < end; addr += chunk.size() - patLen) {
        SIZE_T read = 0;
        ReadProcessMemory(hProc, (LPCVOID)addr, chunk.data(), chunk.size(), &read);
        if (!read) continue;
        for (size_t i = 0; i + patLen <= read; i++) {
            bool found = true;
            for (size_t j = 0; j < patLen; j++)
                if (mask[j] == 'x' && chunk[i + j] != pattern[j]) { found = false; break; }
            if (found) return addr + i;
        }
    }
    return 0;
}

// --- Patch types ---

// Pattern A: overwrite bytes in-place, restore on disable.
struct SimplePatch {
    uintptr_t addr = 0;
    uint8_t orig[8]  = {};
    uint8_t patch[8] = {};
    size_t  sz = 0;
    bool    active = false;
};

static bool ApplyPatch(HANDLE hProc, SimplePatch& p) {
    if (!p.addr || p.active) return false;
    if (!MemWrite(hProc, p.addr, p.patch, p.sz)) return false;
    p.active = true;
    return true;
}

static bool RevertPatch(HANDLE hProc, SimplePatch& p) {
    if (!p.active) return false;
    MemWrite(hProc, p.addr, p.orig, p.sz);
    p.active = false;
    return true;
}

// Allocate executable memory within ~1.75 GB of target for 5-byte relative JMPs.
static uintptr_t AllocNear(HANDLE hProc, uintptr_t target, size_t size) {
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    const uintptr_t range = 0x70000000ULL;
    uintptr_t lo = (target > range) ? target - range : (uintptr_t)si.lpMinimumApplicationAddress;
    uintptr_t hi = (std::min)(target + range, (uintptr_t)si.lpMaximumApplicationAddress);
    MEMORY_BASIC_INFORMATION mbi;
    // Search forward
    for (uintptr_t cur = target; cur < hi; ) {
        if (!VirtualQueryEx(hProc, (LPCVOID)cur, &mbi, sizeof(mbi))) break;
        if (mbi.State == MEM_FREE) {
            uintptr_t at = ((uintptr_t)mbi.BaseAddress + 0xFFFF) & ~(uintptr_t)0xFFFF;
            if (at + size <= hi) {
                LPVOID p = VirtualAllocEx(hProc, (LPVOID)at, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
                if (p) return (uintptr_t)p;
            }
        }
        uintptr_t next = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
        if (next <= cur) break;
        cur = next;
    }
    // Search backward
    for (uintptr_t cur = target & ~(uintptr_t)0xFFFF; cur > lo + 0x10000; cur -= 0x10000) {
        if (!VirtualQueryEx(hProc, (LPCVOID)(cur - 0x10000), &mbi, sizeof(mbi))) continue;
        if (mbi.State == MEM_FREE) {
            LPVOID p = VirtualAllocEx(hProc, (LPVOID)(cur - 0x10000), size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (p) return (uintptr_t)p;
        }
    }
    return 0;
}

// Pattern B: allocate cave near target, write shell + 14-byte abs jmp-back once.
//   Enable/Disable only write/restore the 5-byte relative JMP at addr.
struct SimpleHook {
    uintptr_t addr    = 0;
    uintptr_t cave    = 0;
    uint8_t   orig[16] = {};
    size_t    patchSz = 0;
    bool      active  = false;
};

// SetupHook: called once from ScanAll after addr is found.
//   Allocates cave, writes shell + 14-byte abs jmp-back (FF 25 00000000 <addr64>).
//   Pass retAddr=0 if shell ends with its own ret.
static bool SetupHook(HANDLE hProc, SimpleHook& h, size_t patchSz,
                      const uint8_t* shell, size_t shellSz, uintptr_t retAddr) {
    if (!h.addr || h.cave) return false;
    h.patchSz = patchSz;
    if (!MemRead(hProc, h.addr, h.orig, patchSz)) return false;

    size_t caveSize = shellSz + 14; // shell + 14-byte abs jmp-back
    h.cave = AllocNear(hProc, h.addr, caveSize);
    if (!h.cave) return false;

    std::vector<uint8_t> buf(caveSize, 0x90);
    memcpy(buf.data(), shell, shellSz);
    if (retAddr) {
        // FF 25 00000000 <8-byte addr>
        buf[shellSz + 0] = 0xFF; buf[shellSz + 1] = 0x25;
        buf[shellSz + 2] = buf[shellSz + 3] = buf[shellSz + 4] = buf[shellSz + 5] = 0x00;
        memcpy(buf.data() + shellSz + 6, &retAddr, 8);
    }
    if (!MemWrite(hProc, h.cave, buf.data(), caveSize)) {
        VirtualFreeEx(hProc, (LPVOID)h.cave, 0, MEM_RELEASE);
        h.cave = 0;
        return false;
    }
    return true;
}

static void EnableHook(HANDLE hProc, SimpleHook& h) {
    if (h.active || !h.addr || !h.cave) return;
    int64_t diff = (int64_t)h.cave - (int64_t)(h.addr + 5);
    if (diff < INT32_MIN || diff > INT32_MAX) return;
    uint8_t patch[16];
    memset(patch, 0x90, h.patchSz);
    patch[0] = 0xE9;
    int32_t rel = (int32_t)diff;
    memcpy(patch + 1, &rel, 4);
    if (MemWrite(hProc, h.addr, patch, h.patchSz))
        h.active = true;
}

static void DisableHook(HANDLE hProc, SimpleHook& h) {
    if (!h.active) return;
    MemWrite(hProc, h.addr, h.orig, h.patchSz);
    h.active = false;
}

static void TeardownHook(HANDLE hProc, SimpleHook& h) {
    DisableHook(hProc, h);
    if (h.cave) { VirtualFreeEx(hProc, (LPVOID)h.cave, 0, MEM_RELEASE); h.cave = 0; }
}

// --- Feature ---

struct Feature {
    TrainerFeatureInfo info;
    std::atomic<bool> enabled{ false };
    std::atomic<int>  vk_code{ 0 };
    Feature(const char* i, const char* n, const char* d, int tog, int vk)
        : info{ i, n, d, tog, vk }, vk_code(vk) {}
};

// --- Trainer ---

class StardewTrainer {
public:
    HANDLE             m_hProc  = nullptr;
    DWORD              m_pid    = 0;
    uintptr_t          m_base   = 0;
    uintptr_t          m_scanEnd= 0;
    std::atomic<bool>  m_running{ false };
    std::thread        m_thread;
    std::list<Feature> m_features;

    // Pattern A — in-place patches
    SimplePatch pNoclip, pItems, pTrees, pFreezeTime;

    // Pattern B — code cave hooks
    SimpleHook hookHealth, hookStamina, hookSpeed, hookWater;
    SimpleHook hookFishBite, hookFishCatch, hookFreeCraft;
    SimpleHook hookCropGrowth, hookFriendship;
    SimpleHook hookPetFriend, hookAnimalStats; // share same addr, mutually exclusive
    SimpleHook hookStackables, hookGold;

    StardewTrainer() {
        m_features.emplace_back("noclip",              "No Clip",              "Walk through walls",                 1, VK_F1);
        m_features.emplace_back("unlimited_health",    "Unlimited Health",     "Health resets to max",               1, VK_F2);
        m_features.emplace_back("unlimited_stamina",   "Unlimited Stamina",    "Stamina resets to max",              1, VK_F3);
        m_features.emplace_back("super_speed",         "Super Speed",          "Move 10x faster",                    1, VK_F4);
        m_features.emplace_back("unlimited_items",     "Unlimited Items",      "Items don't decrease",               1, VK_F5);
        m_features.emplace_back("unlimited_water",     "Unlimited Water",      "Watering can never empties",         1, VK_F6);
        m_features.emplace_back("freeze_time",         "Freeze Game Time",     "Time stops",                         1, VK_F7);
        m_features.emplace_back("instant_fish_bite",   "Instant Fish Bite",    "Fish bite immediately",              1, VK_F8);
        m_features.emplace_back("easy_fish_catch",     "Easy Fish Catch",      "Catch bar fills instantly",          1, VK_F9);
        m_features.emplace_back("one_hit_trees",       "One Hit Trees",        "Trees fall in one hit",              1, VK_F10);
        m_features.emplace_back("free_crafting",       "Free Crafting",        "Craft without resources",            1, VK_F11);
        m_features.emplace_back("instant_crop_growth", "Instant Crop Growth",  "Crops skip to last stage",           1, VK_F12);
        m_features.emplace_back("max_friendship",      "Max Friendship",       "Max friendship when talking",        1, VK_NUMPAD1);
        m_features.emplace_back("max_pet_friendship",  "Max Pet Friendship",   "Pet friendship set to 1000",         1, VK_NUMPAD2);
        m_features.emplace_back("stackables_999",      "Stackables to 999",    "Stack size reported as 999",         1, VK_NUMPAD3);
        m_features.emplace_back("max_animal_stats",    "Max Animal Stats",     "Animals always full/happy/friendly", 1, VK_NUMPAD4);
        m_features.emplace_back("set_gold",            "Set Max Gold",         "Gold set to 999,999,999",            1, VK_NUMPAD5);
    }

    bool Initialize() {
        const wchar_t* exes[] = { L"Stardew Valley.exe", L"StardewValley.exe", L"StardewModdingAPI.exe" };
        for (auto e : exes) { m_pid = FindPid(e); if (m_pid) break; }
        if (!m_pid) return false;

        m_hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, m_pid);
        if (!m_hProc) return false;

        for (auto e : exes) { m_base = GetModuleBase(m_pid, e); if (m_base) break; }
        if (!m_base) { CloseHandle(m_hProc); m_hProc = nullptr; return false; }

        m_scanEnd = m_base + 0x5000000;
        ScanAll();

        m_running.store(true);
        m_thread = std::thread(&StardewTrainer::Loop, this);
        return true;
    }

    // ------------------------------------------------------------------ scans + cave setup

    void ScanAll() {
        // No Clip: movzx ecx,[rsi+74E] -> mov ecx,1 + nop nop
        // aobscan: 0F B6 8E 4E 07 00 00
        {
            const uint8_t pat[] = { 0x0F, 0xB6, 0x8E, 0x4E, 0x07, 0x00, 0x00 };
            uintptr_t a = AobScan(m_hProc, m_base, m_scanEnd, pat, "xxxxxxx");
            if (a) {
                pNoclip.addr = a;
                pNoclip.sz   = 7;
                memcpy(pNoclip.orig,  pat, 7);
                const uint8_t p[] = { 0xB9, 0x01, 0x00, 0x00, 0x00, 0x90, 0x90 }; // mov ecx,1; nop; nop
                memcpy(pNoclip.patch, p, 7);
            }
        }

        // Unlimited Health: fild maxHealth -> fistp curHealth, then original vcvtsi2ss
        // aobscan: C5 FA 2A 81 EC 06 00 00 C5 F0 57 C9 C5 F2 2A CA
        {
            const uint8_t pat[] = { 0xC5, 0xFA, 0x2A, 0x81, 0xEC, 0x06, 0x00, 0x00,
                                    0xC5, 0xF0, 0x57, 0xC9, 0xC5, 0xF2, 0x2A, 0xCA };
            hookHealth.addr = AobScan(m_hProc, m_base, m_scanEnd, pat, "xxxxxxxxxxxxxxxx");
            if (hookHealth.addr) {
                const uint8_t shell[] = {
                    0xDB, 0x81, 0xF0, 0x06, 0x00, 0x00,              // fild dword [rcx+6F0]  (maxHealth)
                    0xDB, 0x99, 0xEC, 0x06, 0x00, 0x00,              // fistp dword [rcx+6EC] (curHealth = max)
                    0xC5, 0xFA, 0x2A, 0x81, 0xEC, 0x06, 0x00, 0x00  // vcvtsi2ss xmm0,[rcx+6EC] (original)
                };
                SetupHook(m_hProc, hookHealth, 8, shell, sizeof(shell), hookHealth.addr + 8);
            }
        }

        // Unlimited Stamina: execute original chain, then copy maxStamina -> curStamina
        // aobscan: 48 8B 09 48 8B 89 D0 04 00 00 C5 7A 10 49 4C
        {
            const uint8_t pat[] = { 0x48, 0x8B, 0x09, 0x48, 0x8B, 0x89, 0xD0, 0x04, 0x00, 0x00,
                                    0xC5, 0x7A, 0x10, 0x49, 0x4C };
            hookStamina.addr = AobScan(m_hProc, m_base, m_scanEnd, pat, "xxxxxxxxxxxxxxx");
            if (hookStamina.addr) {
                const uint8_t shell[] = {
                    0x48, 0x8B, 0x09,                              // mov rcx,[rcx]      (orig 0..2)
                    0x48, 0x8B, 0x89, 0xD0, 0x04, 0x00, 0x00,    // mov rcx,[rcx+4D0]  (orig 3..9)
                    0xD9, 0x41, 0x54,                              // fld  dword [rcx+54] (maxStamina)
                    0xD9, 0x59, 0x4C                               // fstp dword [rcx+4C] (curStamina = max)
                };
                SetupHook(m_hProc, hookStamina, 10, shell, sizeof(shell), hookStamina.addr + 10);
            }
        }

        // Super Speed: replace GetMovementSpeed entirely; shell ends with ret, no jmp-back needed
        // aobscan: 57 56 48 83 EC 68 C5 F8 77 ...
        {
            const uint8_t pat[] = {
                0x57, 0x56, 0x48, 0x83, 0xEC, 0x68, 0xC5, 0xF8, 0x77,
                0xC5, 0xF8, 0x29, 0x74, 0x24, 0x50, 0xC5, 0xF8, 0x29,
                0x7C, 0x24, 0x40, 0x48, 0x8B, 0xF1, 0x48, 0x8B, 0x8E,
                0x20, 0x05, 0x00, 0x00, 0x80, 0x79, 0x4D, 0x00 };
            hookSpeed.addr = AobScan(m_hProc, m_base, m_scanEnd, pat, "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
            if (hookSpeed.addr) {
                const uint8_t shell[] = {
                    0x48, 0x83, 0xEC, 0x08,                       // sub rsp,8
                    0xC7, 0x04, 0x24, 0x00, 0x00, 0x20, 0x41,    // mov dword [rsp],0x41200000 (10.0f)
                    0xF3, 0x0F, 0x10, 0x04, 0x24,                 // movss xmm0,[rsp]
                    0x48, 0x83, 0xC4, 0x08,                       // add rsp,8
                    0xC3                                           // ret
                };
                SetupHook(m_hProc, hookSpeed, 6, shell, sizeof(shell), 0);
            }
        }

        // Unlimited Items: lea ebp,[rax-1] -> lea ebp,[rax+0]  (single byte at pattern+2)
        // aobscan: 8D 68 FF 48 8B CF
        {
            const uint8_t pat[] = { 0x8D, 0x68, 0xFF, 0x48, 0x8B, 0xCF };
            uintptr_t a = AobScan(m_hProc, m_base, m_scanEnd, pat, "xxxxxx");
            if (a) {
                pItems.addr    = a + 2;
                pItems.sz      = 1;
                pItems.orig[0] = 0xFF;
                pItems.patch[0]= 0x00;
            }
        }

        // Unlimited Water: load watering can object, set water level to 32 (full)
        // aobscan: 4C 8B 86 08 01 00 00 45 8B 40 4C
        {
            const uint8_t pat[] = { 0x4C, 0x8B, 0x86, 0x08, 0x01, 0x00, 0x00,
                                    0x45, 0x8B, 0x40, 0x4C };
            hookWater.addr = AobScan(m_hProc, m_base, m_scanEnd, pat, "xxxxxxxxxxx");
            if (hookWater.addr) {
                const uint8_t shell[] = {
                    0x4C, 0x8B, 0x86, 0x08, 0x01, 0x00, 0x00,        // mov r8,[rsi+108] (original)
                    0x4D, 0x85, 0xC0,                                  // test r8,r8
                    0x74, 0x07,                                        // je +7 (skip set)
                    0x41, 0xC7, 0x40, 0x4C, 0x20, 0x00, 0x00, 0x00   // mov dword [r8+4C],32
                };
                SetupHook(m_hProc, hookWater, 7, shell, sizeof(shell), hookWater.addr + 7);
            }
        }

        // Freeze Time: add dword [counter],0A -> patch immediate 0A to 00
        // aobscan: 83 05 ?? ?? ?? ?? 0A 8B 0D ?? ?? ?? ?? BA 1F 85 EB 51
        {
            const uint8_t pat[] = { 0x83, 0x05, 0x00, 0x00, 0x00, 0x00, 0x0A,
                                    0x8B, 0x0D, 0x00, 0x00, 0x00, 0x00,
                                    0xBA, 0x1F, 0x85, 0xEB, 0x51 };
            uintptr_t a = AobScan(m_hProc, m_base, m_scanEnd, pat, "xx????x?????xxxxxx");
            if (a) {
                pFreezeTime.addr    = a + 6;
                pFreezeTime.sz      = 1;
                pFreezeTime.orig[0] = 0x0A;
                pFreezeTime.patch[0]= 0x00;
            }
        }

        // Instant Fish Bite: zero xmm6 accumulator before original movaps pair
        // aobscan: C5 F8 28 C6 C5 F8 28 74 24 20 48 83 C4 38 5B 5D 5E 5F 41 5C 41 5D 41 5E 41 5F C3
        {
            const uint8_t pat[] = {
                0xC5, 0xF8, 0x28, 0xC6, 0xC5, 0xF8, 0x28, 0x74, 0x24, 0x20,
                0x48, 0x83, 0xC4, 0x38, 0x5B, 0x5D, 0x5E, 0x5F,
                0x41, 0x5C, 0x41, 0x5D, 0x41, 0x5E, 0x41, 0x5F, 0xC3 };
            hookFishBite.addr = AobScan(m_hProc, m_base, m_scanEnd, pat, "xxxxxxxxxxxxxxxxxxxxxxxxxxx");
            if (hookFishBite.addr) {
                const uint8_t shell[] = {
                    0x0F, 0x57, 0xF6,                              // xorps xmm6,xmm6
                    0xC5, 0xF8, 0x28, 0xC6,                        // vmovaps xmm0,xmm6     (orig 0..3)
                    0xC5, 0xF8, 0x28, 0x74, 0x24, 0x20            // vmovaps xmm6,[rsp+20] (orig 4..9)
                };
                SetupHook(m_hProc, hookFishBite, 10, shell, sizeof(shell), hookFishBite.addr + 10);
            }
        }

        // Easy Fish Catch: write 1.0f directly to catch bar field, skip original movss
        // aobscan: F3 0F 11 81 E8 00 00 00 F3 0F 10 89
        {
            const uint8_t pat[] = { 0xF3, 0x0F, 0x11, 0x81, 0xE8, 0x00, 0x00, 0x00,
                                    0xF3, 0x0F, 0x10, 0x89 };
            hookFishCatch.addr = AobScan(m_hProc, m_base, m_scanEnd, pat, "xxxxxxxxxxxx");
            if (hookFishCatch.addr) {
                const uint8_t shell[] = {
                    0xC7, 0x81, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x3F  // mov dword [rcx+E8],0x3F800000 (1.0f)
                };
                SetupHook(m_hProc, hookFishCatch, 8, shell, sizeof(shell), hookFishCatch.addr + 8);
            }
        }

        // One Hit Trees: vmovss xmm1,[rcx+4C] -> vxorps xmm1,xmm1,xmm1 + nop
        // aobscan: C5 FA 10 49 4C C4 C1 72 5C C8 48 8B 01 48 8B 40 60
        {
            const uint8_t pat[] = { 0xC5, 0xFA, 0x10, 0x49, 0x4C,
                                    0xC4, 0xC1, 0x72, 0x5C, 0xC8,
                                    0x48, 0x8B, 0x01, 0x48, 0x8B, 0x40, 0x60 };
            uintptr_t a = AobScan(m_hProc, m_base, m_scanEnd, pat, "xxxxxxxxxxxxxxxxx");
            if (a) {
                pTrees.addr = a;
                pTrees.sz   = 5;
                const uint8_t orig[] = { 0xC5, 0xFA, 0x10, 0x49, 0x4C };
                const uint8_t p[]    = { 0xC5, 0xF0, 0x57, 0xC9, 0x90 }; // vxorps xmm1,xmm1,xmm1; nop
                memcpy(pTrees.orig,  orig, 5);
                memcpy(pTrees.patch, p,    5);
            }
        }

        // Free Crafting: zero required-ingredient count at [rax+38] before the subtract
        // aobscan: 8B 50 38 2B 50 40 8D 04 D2 44 8D 2C 81
        {
            const uint8_t pat[] = { 0x8B, 0x50, 0x38, 0x2B, 0x50, 0x40,
                                    0x8D, 0x04, 0xD2, 0x44, 0x8D, 0x2C, 0x81 };
            hookFreeCraft.addr = AobScan(m_hProc, m_base, m_scanEnd, pat, "xxxxxxxxxxxxx");
            if (hookFreeCraft.addr) {
                const uint8_t shell[] = {
                    0xC7, 0x40, 0x38, 0x00, 0x00, 0x00, 0x00,  // mov dword [rax+38],0
                    0x8B, 0x50, 0x38,                           // mov edx,[rax+38] (orig 0..2)
                    0x2B, 0x50, 0x40                            // sub edx,[rax+40] (orig 3..5)
                };
                SetupHook(m_hProc, hookFreeCraft, 6, shell, sizeof(shell), hookFreeCraft.addr + 6);
            }
        }

        // Instant Crop Growth: advance phase to (totalPhases-1) on each tick
        // aobscan: 48 8B 4E 28 8B 49 4C 48
        {
            const uint8_t pat[] = { 0x48, 0x8B, 0x4E, 0x28, 0x8B, 0x49, 0x4C, 0x48 };
            hookCropGrowth.addr = AobScan(m_hProc, m_base, m_scanEnd, pat, "xxxxxxxx");
            if (hookCropGrowth.addr) {
                const uint8_t shell[] = {
                    0x48, 0x8B, 0x4E, 0x28,  // mov rcx,[rsi+28]  (orig 0..3)
                    0x48, 0x8B, 0x46, 0x10,  // mov rax,[rsi+10]
                    0x48, 0x8B, 0x40, 0x38,  // mov rax,[rax+38]
                    0x8B, 0x40, 0x4C,        // mov eax,[rax+4C]  (total phases)
                    0xFF, 0xC8,              // dec eax           (last phase index)
                    0x3B, 0x41, 0x4C,        // cmp [rcx+4C],eax
                    0x7F, 0x03,              // jg +3
                    0x89, 0x41, 0x4C,        // mov [rcx+4C],eax
                    0x8B, 0x49, 0x4C         // mov ecx,[rcx+4C]  (orig 4..6)
                };
                SetupHook(m_hProc, hookCropGrowth, 7, shell, sizeof(shell), hookCropGrowth.addr + 7);
            }
        }

        // Max Friendship: set edx=9999999 before function entry, then original prolog pushes
        // aobscan: 41 56 57 56 55 53 48
        {
            const uint8_t pat[] = { 0x41, 0x56, 0x57, 0x56, 0x55, 0x53, 0x48 };
            hookFriendship.addr = AobScan(m_hProc, m_base, m_scanEnd, pat, "xxxxxxx");
            if (hookFriendship.addr) {
                const uint8_t shell[] = {
                    0xBA, 0x7F, 0x96, 0x98, 0x00,  // mov edx,9999999
                    0x41, 0x56,                     // push r14 (orig 0..1)
                    0x57,                           // push rdi (orig 2)
                    0x56,                           // push rsi (orig 3)
                    0x55                            // push rbp (orig 4)
                };
                SetupHook(m_hProc, hookFriendship, 5, shell, sizeof(shell), hookFriendship.addr + 5);
            }
        }

        // Max Pet Friendship + Max Animal Stats share injection point; mutually exclusive caves
        // aobscan: 55 41 57 41 56 41 55 41 54 57
        {
            const uint8_t pat[] = { 0x55, 0x41, 0x57, 0x41, 0x56, 0x41, 0x55, 0x41, 0x54, 0x57 };
            uintptr_t a = AobScan(m_hProc, m_base, m_scanEnd, pat, "xxxxxxxxxx");
            if (a) {
                hookPetFriend.addr  = a;
                hookAnimalStats.addr = a;

                // Pet friendship: set [rcx+450]+4C = 1000
                {
                    const uint8_t shell[] = {
                        0x48, 0x8B, 0x81, 0x50, 0x04, 0x00, 0x00,   // mov rax,[rcx+450]
                        0x48, 0x85, 0xC0,                             // test rax,rax
                        0x74, 0x07,                                   // je +7 (skip)
                        0xC7, 0x40, 0x4C, 0xE8, 0x03, 0x00, 0x00,   // mov dword [rax+4C],1000
                        0x55,                                          // push rbp (orig 0)
                        0x41, 0x57,                                   // push r15 (orig 1..2)
                        0x41, 0x56                                    // push r14 (orig 3..4)
                    };
                    SetupHook(m_hProc, hookPetFriend, 5, shell, sizeof(shell), a + 5);
                }

                // Animal stats: set fullness/happiness/friendliness = 9999
                {
                    const uint8_t shell[] = {
                        0x48, 0x8B, 0x81, 0x90, 0x01, 0x00, 0x00,   // mov rax,[rcx+190]
                        0x48, 0x85, 0xC0,                             // test rax,rax
                        0x74, 0x07,                                   // je +7
                        0xC7, 0x40, 0x4C, 0x0F, 0x27, 0x00, 0x00,   // mov dword [rax+4C],9999
                        0x48, 0x8B, 0x81, 0xD0, 0x01, 0x00, 0x00,   // mov rax,[rcx+1D0]
                        0x48, 0x85, 0xC0,                             // test rax,rax
                        0x74, 0x07,                                   // je +7
                        0xC7, 0x40, 0x4C, 0x0F, 0x27, 0x00, 0x00,   // mov dword [rax+4C],9999
                        0x48, 0x8B, 0x81, 0xC8, 0x01, 0x00, 0x00,   // mov rax,[rcx+1C8]
                        0x48, 0x85, 0xC0,                             // test rax,rax
                        0x74, 0x07,                                   // je +7
                        0xC7, 0x40, 0x4C, 0x0F, 0x27, 0x00, 0x00,   // mov dword [rax+4C],9999
                        0x55,                                          // push rbp (orig 0)
                        0x41, 0x57,                                   // push r15 (orig 1..2)
                        0x41, 0x56                                    // push r14 (orig 3..4)
                    };
                    SetupHook(m_hProc, hookAnimalStats, 5, shell, sizeof(shell), a + 5);
                }
            }
        }

        // Stackables to 999: overwrite stack count with 999, then original mov+test
        // aobscan: 8B 40 4C 85 C0 7E
        {
            const uint8_t pat[] = { 0x8B, 0x40, 0x4C, 0x85, 0xC0, 0x7E };
            hookStackables.addr = AobScan(m_hProc, m_base, m_scanEnd, pat, "xxxxxx");
            if (hookStackables.addr) {
                const uint8_t shell[] = {
                    0x53,                           // push rbx
                    0xBB, 0xE7, 0x03, 0x00, 0x00,  // mov ebx,999
                    0x89, 0x58, 0x4C,               // mov [rax+4C],ebx
                    0x5B,                           // pop rbx
                    0x8B, 0x40, 0x4C,               // mov eax,[rax+4C] (orig 0..2)
                    0x85, 0xC0                      // test eax,eax     (orig 3..4)
                };
                SetupHook(m_hProc, hookStackables, 5, shell, sizeof(shell), hookStackables.addr + 5);
            }
        }

        // Set Gold: hook at aob+1; set gold to 999,999,999 then execute original
        // aobscan: FF 8B 40 4C 48 83 C4 28
        {
            const uint8_t pat[] = { 0xFF, 0x8B, 0x40, 0x4C, 0x48, 0x83, 0xC4, 0x28 };
            uintptr_t a = AobScan(m_hProc, m_base, m_scanEnd, pat, "xxxxxxxx");
            if (a) {
                hookGold.addr = a + 1;
                const uint8_t shell[] = {
                    0xC7, 0x40, 0x4C, 0xFF, 0xC9, 0x9A, 0x3B,  // mov dword [rax+4C],999999999
                    0x8B, 0x40, 0x4C,                           // mov eax,[rax+4C] (original)
                    0x48, 0x83, 0xC4, 0x28                      // add rsp,28       (original)
                };
                SetupHook(m_hProc, hookGold, 7, shell, sizeof(shell), a + 8);
            }
        }
    }

    // ------------------------------------------------------------------ loop

    void Loop() {
        bool prev[17] = {};

        while (m_running.load()) {
            // Hotkey toggle
            int idx = 0;
            for (auto& f : m_features) {
                int vk = f.vk_code.load();
                if (vk && (GetAsyncKeyState(vk) & 1))
                    f.enabled.store(!f.enabled.load());
                idx++;
            }

            // Apply / revert on state change
            idx = 0;
            for (auto& f : m_features) {
                bool en = f.enabled.load();
                if (en == prev[idx]) { idx++; continue; }
                prev[idx] = en;

                const char* id = f.info.id;

                if (!strcmp(id, "noclip"))
                    en ? ApplyPatch(m_hProc, pNoclip)      : RevertPatch(m_hProc, pNoclip);
                else if (!strcmp(id, "unlimited_health"))
                    en ? EnableHook(m_hProc, hookHealth)   : DisableHook(m_hProc, hookHealth);
                else if (!strcmp(id, "unlimited_stamina"))
                    en ? EnableHook(m_hProc, hookStamina)  : DisableHook(m_hProc, hookStamina);
                else if (!strcmp(id, "super_speed"))
                    en ? EnableHook(m_hProc, hookSpeed)    : DisableHook(m_hProc, hookSpeed);
                else if (!strcmp(id, "unlimited_items"))
                    en ? ApplyPatch(m_hProc, pItems)       : RevertPatch(m_hProc, pItems);
                else if (!strcmp(id, "unlimited_water"))
                    en ? EnableHook(m_hProc, hookWater)    : DisableHook(m_hProc, hookWater);
                else if (!strcmp(id, "freeze_time"))
                    en ? ApplyPatch(m_hProc, pFreezeTime)  : RevertPatch(m_hProc, pFreezeTime);
                else if (!strcmp(id, "instant_fish_bite"))
                    en ? EnableHook(m_hProc, hookFishBite) : DisableHook(m_hProc, hookFishBite);
                else if (!strcmp(id, "easy_fish_catch"))
                    en ? EnableHook(m_hProc, hookFishCatch): DisableHook(m_hProc, hookFishCatch);
                else if (!strcmp(id, "one_hit_trees"))
                    en ? ApplyPatch(m_hProc, pTrees)       : RevertPatch(m_hProc, pTrees);
                else if (!strcmp(id, "free_crafting"))
                    en ? EnableHook(m_hProc, hookFreeCraft): DisableHook(m_hProc, hookFreeCraft);
                else if (!strcmp(id, "instant_crop_growth"))
                    en ? EnableHook(m_hProc, hookCropGrowth) : DisableHook(m_hProc, hookCropGrowth);
                else if (!strcmp(id, "max_friendship"))
                    en ? EnableHook(m_hProc, hookFriendship) : DisableHook(m_hProc, hookFriendship);
                else if (!strcmp(id, "max_pet_friendship")) {
                    if (en) { DisableHook(m_hProc, hookAnimalStats); EnableHook(m_hProc, hookPetFriend); }
                    else      DisableHook(m_hProc, hookPetFriend);
                } else if (!strcmp(id, "stackables_999"))
                    en ? EnableHook(m_hProc, hookStackables) : DisableHook(m_hProc, hookStackables);
                else if (!strcmp(id, "max_animal_stats")) {
                    if (en) { DisableHook(m_hProc, hookPetFriend); EnableHook(m_hProc, hookAnimalStats); }
                    else      DisableHook(m_hProc, hookAnimalStats);
                } else if (!strcmp(id, "set_gold"))
                    en ? EnableHook(m_hProc, hookGold)     : DisableHook(m_hProc, hookGold);

                idx++;
            }

            Sleep(50);
        }
    }

    // ------------------------------------------------------------------ shutdown

    void Shutdown() {
        m_running.store(false);
        if (m_thread.joinable()) m_thread.join();

        RevertPatch(m_hProc, pNoclip);
        RevertPatch(m_hProc, pItems);
        RevertPatch(m_hProc, pTrees);
        RevertPatch(m_hProc, pFreezeTime);

        TeardownHook(m_hProc, hookHealth);
        TeardownHook(m_hProc, hookStamina);
        TeardownHook(m_hProc, hookSpeed);
        TeardownHook(m_hProc, hookWater);
        TeardownHook(m_hProc, hookFishBite);
        TeardownHook(m_hProc, hookFishCatch);
        TeardownHook(m_hProc, hookFreeCraft);
        TeardownHook(m_hProc, hookCropGrowth);
        TeardownHook(m_hProc, hookFriendship);
        TeardownHook(m_hProc, hookPetFriend);
        TeardownHook(m_hProc, hookAnimalStats);
        TeardownHook(m_hProc, hookStackables);
        TeardownHook(m_hProc, hookGold);

        if (m_hProc) { CloseHandle(m_hProc); m_hProc = nullptr; }
    }

    // ------------------------------------------------------------------ API

    int          GetFeatureCount()  { return (int)m_features.size(); }
    const char*  GetName()          { return "Stardew Valley Trainer"; }
    const char*  GetVersion()       { return "2.1.0"; }

    const TrainerFeatureInfo* GetFeatureInfo(int idx) {
        auto it = m_features.begin(); std::advance(it, idx); return &it->info;
    }
    int GetFeatureEnabled(const char* id) {
        for (auto& f : m_features) if (!strcmp(f.info.id, id)) return f.enabled.load();
        return 0;
    }
    void SetFeatureEnabled(const char* id, int en) {
        for (auto& f : m_features) if (!strcmp(f.info.id, id)) f.enabled.store(en != 0);
    }
    void ActivateFeature(const char*) {}
    void SetKeybind(const char* id, int vk) {
        for (auto& f : m_features) if (!strcmp(f.info.id, id)) f.vk_code.store(vk);
    }
    int GetKeybind(const char* id) {
        for (auto& f : m_features) if (!strcmp(f.info.id, id)) return f.vk_code.load();
        return 0;
    }
};

// ------------------------------------------------------------------ C exports

extern "C" {
    __declspec(dllexport) void*       trainer_create()                                          { return new StardewTrainer(); }
    __declspec(dllexport) void        trainer_destroy(void* h)                                  { delete static_cast<StardewTrainer*>(h); }
    __declspec(dllexport) int         trainer_initialize(void* h)                               { return static_cast<StardewTrainer*>(h)->Initialize() ? 1 : 0; }
    __declspec(dllexport) void        trainer_shutdown(void* h)                                 { static_cast<StardewTrainer*>(h)->Shutdown(); }
    __declspec(dllexport) const char* trainer_get_name(void* h)                                 { return static_cast<StardewTrainer*>(h)->GetName(); }
    __declspec(dllexport) const char* trainer_get_version(void* h)                              { return static_cast<StardewTrainer*>(h)->GetVersion(); }
    __declspec(dllexport) int         trainer_get_feature_count(void* h)                        { return static_cast<StardewTrainer*>(h)->GetFeatureCount(); }
    __declspec(dllexport) const TrainerFeatureInfo* trainer_get_feature_info(void* h, int idx)  { return static_cast<StardewTrainer*>(h)->GetFeatureInfo(idx); }
    __declspec(dllexport) int         trainer_get_feature_enabled(void* h, const char* id)      { return static_cast<StardewTrainer*>(h)->GetFeatureEnabled(id); }
    __declspec(dllexport) void        trainer_set_feature_enabled(void* h, const char* id, int en) { static_cast<StardewTrainer*>(h)->SetFeatureEnabled(id, en); }
    __declspec(dllexport) void        trainer_activate_feature(void* h, const char* id)         { static_cast<StardewTrainer*>(h)->ActivateFeature(id); }
    __declspec(dllexport) void        trainer_set_keybind(void* h, const char* id, int vk)      { static_cast<StardewTrainer*>(h)->SetKeybind(id, vk); }
    __declspec(dllexport) int         trainer_get_keybind(void* h, const char* id)              { return static_cast<StardewTrainer*>(h)->GetKeybind(id); }
    __declspec(dllexport) const char* trainer_get_last_error()                                  { return ""; }
}
