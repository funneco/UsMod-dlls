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
            for (size_t j = 0; j < patLen; j++) {
                if (mask[j] == 'x' && chunk[i + j] != pattern[j]) { found = false; break; }
            }
            if (found) return addr + i;
        }
    }
    return 0;
}

// --- Patch infrastructure ---

// SimplePatch: overwrite a fixed block of bytes in-place, restore on disable.
struct SimplePatch {
    uintptr_t addr = 0;
    std::vector<uint8_t> original;
    std::vector<uint8_t> patched;
    bool active = false;
};

static bool ApplySimplePatch(HANDLE hProc, SimplePatch& p) {
    if (!p.addr || p.active) return false;
    if (!MemWrite(hProc, p.addr, p.patched.data(), p.patched.size())) return false;
    p.active = true;
    return true;
}

static bool RemoveSimplePatch(HANDLE hProc, SimplePatch& p) {
    if (!p.active) return false;
    if (!MemWrite(hProc, p.addr, p.original.data(), p.original.size())) return false;
    p.active = false;
    return true;
}

// Hook: allocates a nearby executable trampoline, patches src with a 5-byte relative jmp
// into the trampoline, appends a jmp-back at the end of the trampoline shellcode.
struct Hook {
    uintptr_t src = 0;
    uintptr_t trampoline = 0;
    size_t patchSize = 0;
    std::vector<uint8_t> original;
    bool active = false;
};

static void BuildJmp5(uint8_t* buf, uintptr_t src, uintptr_t dst) {
    buf[0] = 0xE9;
    int32_t rel = (int32_t)(dst - (src + 5));
    memcpy(buf + 1, &rel, 4);
}

// 14-byte absolute jmp: FF 25 00000000 <addr64>
static void BuildAbsJmp14(uint8_t* buf, uintptr_t dst) {
    buf[0] = 0xFF; buf[1] = 0x25;
    buf[2] = buf[3] = buf[4] = buf[5] = 0x00;
    memcpy(buf + 6, &dst, 8);
}

// Try to allocate executable memory within +-2GB of target for short relative jumps.
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
            uintptr_t allocAt = ((uintptr_t)mbi.BaseAddress + 0xFFFF) & ~(uintptr_t)0xFFFF;
            if (allocAt + size <= hi) {
                LPVOID p = VirtualAllocEx(hProc, (LPVOID)allocAt, size,
                                          MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
                if (p) return (uintptr_t)p;
            }
        }
        uintptr_t next = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
        if (next <= cur) break;
        cur = next;
    }
    // Search backward
    for (uintptr_t cur = (target & ~(uintptr_t)0xFFFF); cur > lo + 0x10000; cur -= 0x10000) {
        if (!VirtualQueryEx(hProc, (LPCVOID)(cur - 0x10000), &mbi, sizeof(mbi))) continue;
        if (mbi.State == MEM_FREE) {
            LPVOID p = VirtualAllocEx(hProc, (LPVOID)(cur - 0x10000), size,
                                      MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (p) return (uintptr_t)p;
        }
    }
    return 0;
}

// Install a trampoline hook at src.
//   patchSize  - bytes overwritten at src (filled with jmp5 + 0x90 nops)
//   shell      - shellcode written to trampoline before the jmp-back
//   returnAddr - where the trampoline jmps back to (usually src + patchSize;
//                pass 0 if the shell ends with its own ret)
static bool InstallHook(HANDLE hProc, Hook& hook,
                        uintptr_t src, size_t patchSize,
                        const uint8_t* shell, size_t shellSize,
                        uintptr_t returnAddr) {
    if (hook.active || !src) return false;

    hook.src = src;
    hook.patchSize = patchSize;
    hook.original.resize(patchSize);
    if (!MemRead(hProc, src, hook.original.data(), patchSize)) return false;

    size_t tramSize = shellSize + 14; // shell + abs jmp-back (14 bytes)
    hook.trampoline = AllocNear(hProc, src, tramSize);
    if (!hook.trampoline) return false;

    std::vector<uint8_t> tram(tramSize, 0x90);
    memcpy(tram.data(), shell, shellSize);
    if (returnAddr)
        BuildAbsJmp14(tram.data() + shellSize, returnAddr);
    if (!MemWrite(hProc, hook.trampoline, tram.data(), tramSize)) {
        VirtualFreeEx(hProc, (LPVOID)hook.trampoline, 0, MEM_RELEASE);
        hook.trampoline = 0;
        return false;
    }

    int64_t rel = (int64_t)hook.trampoline - (int64_t)(src + 5);
    if (rel < INT32_MIN || rel > INT32_MAX) {
        VirtualFreeEx(hProc, (LPVOID)hook.trampoline, 0, MEM_RELEASE);
        hook.trampoline = 0;
        return false;
    }

    std::vector<uint8_t> patch(patchSize, 0x90);
    BuildJmp5(patch.data(), src, hook.trampoline);
    if (!MemWrite(hProc, src, patch.data(), patchSize)) {
        VirtualFreeEx(hProc, (LPVOID)hook.trampoline, 0, MEM_RELEASE);
        hook.trampoline = 0;
        return false;
    }

    hook.active = true;
    return true;
}

static void RemoveHook(HANDLE hProc, Hook& hook) {
    if (!hook.active) return;
    MemWrite(hProc, hook.src, hook.original.data(), hook.patchSize);
    if (hook.trampoline) { VirtualFreeEx(hProc, (LPVOID)hook.trampoline, 0, MEM_RELEASE); hook.trampoline = 0; }
    hook.active = false;
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
    HANDLE             m_hProc   = nullptr;
    DWORD              m_pid     = 0;
    uintptr_t          m_base    = 0;
    uintptr_t          m_scanEnd = 0;
    std::atomic<bool>  m_running{ false };
    std::thread        m_thread;
    std::list<Feature> m_features;

    // Direct (in-place) patches
    SimplePatch pNoclip;
    SimplePatch pItems;
    SimplePatch pTrees;
    SimplePatch pFreezeTime;

    // Trampoline hooks — scanned addresses stored in hook.src after ScanAll
    uintptr_t addrHealth      = 0;
    uintptr_t addrStamina     = 0;
    uintptr_t addrSpeed       = 0;
    uintptr_t addrWater       = 0;
    uintptr_t addrFishBite    = 0;
    uintptr_t addrFishCatch   = 0;
    uintptr_t addrFreeCraft   = 0;
    uintptr_t addrCropGrowth  = 0;
    uintptr_t addrFriendship  = 0;
    uintptr_t addrPetFriend   = 0;
    uintptr_t addrStackables  = 0;

    Hook hookHealth, hookStamina, hookSpeed, hookWater;
    Hook hookFishBite, hookFishCatch, hookFreeCraft;
    Hook hookCropGrowth, hookFriendship, hookPetFriend, hookStackables;

    StardewTrainer() {
        m_features.emplace_back("noclip",            "No Clip",              "Walk through walls",           1, VK_F1);
        m_features.emplace_back("unlimited_health",  "Unlimited Health",     "Health resets to max",         1, VK_F2);
        m_features.emplace_back("unlimited_stamina", "Unlimited Stamina",    "Stamina resets to max",        1, VK_F3);
        m_features.emplace_back("super_speed",       "Super Speed",          "Move 10x faster",              1, VK_F4);
        m_features.emplace_back("unlimited_items",   "Unlimited Items",      "Items don't decrease",         1, VK_F5);
        m_features.emplace_back("unlimited_water",   "Unlimited Water",      "Watering can never empties",   1, VK_F6);
        m_features.emplace_back("freeze_time",       "Freeze Game Time",     "Time stops",                   1, VK_F7);
        m_features.emplace_back("instant_fish_bite", "Instant Fish Bite",    "Fish bite immediately",        1, VK_F8);
        m_features.emplace_back("easy_fish_catch",   "Easy Fish Catch",      "Catch bar fills instantly",    1, VK_F9);
        m_features.emplace_back("one_hit_trees",     "One Hit Trees",        "Trees fall in one hit",        1, VK_F10);
        m_features.emplace_back("free_crafting",     "Free Crafting",        "Craft without resources",      1, VK_F11);
        m_features.emplace_back("instant_crop_growth","Instant Crop Growth", "Crops skip to last stage",     1, VK_F12);
        m_features.emplace_back("max_friendship",    "Max Friendship",       "Max friendship when talking",  1, VK_NUMPAD1);
        m_features.emplace_back("max_pet_friendship","Max Pet Friendship",   "Pet friendship set to 1000",   1, VK_NUMPAD2);
        m_features.emplace_back("stackables_999",    "Stackables to 999",    "Stack size reported as 999",   1, VK_NUMPAD3);
    }

    bool Initialize() {
        const wchar_t* exes[] = { L"Stardew Valley.exe", L"StardewValley.exe", L"StardewModdingAPI.exe" };
        for (auto e : exes) { m_pid = FindPid(e); if (m_pid) break; }
        if (!m_pid) return false;

        m_hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, m_pid);
        if (!m_hProc) return false;

        for (auto e : exes) { m_base = GetModuleBase(m_pid, e); if (m_base) break; }
        if (!m_base) { CloseHandle(m_hProc); return false; }

        m_scanEnd = m_base + 0x5000000;
        ScanAll();

        m_running.store(true);
        m_thread = std::thread(&StardewTrainer::Loop, this);
        return true;
    }

    // ------------------------------------------------------------------ scans

    void ScanAll() {
        // No Clip: movzx ecx,[rsi+74E]  ->  mov ecx,1 + nop nop
        // Pattern: 0F B6 8E 4E 07 00 00
        {
            const uint8_t pat[] = { 0x0F, 0xB6, 0x8E, 0x4E, 0x07, 0x00, 0x00 };
            uintptr_t a = AobScan(m_hProc, m_base, m_scanEnd, pat, "xxxxxxx");
            if (a) {
                pNoclip.addr     = a;
                pNoclip.original = { 0x0F, 0xB6, 0x8E, 0x4E, 0x07, 0x00, 0x00 };
                pNoclip.patched  = { 0xB9, 0x01, 0x00, 0x00, 0x00, 0x90, 0x90 }; // mov ecx,1; nop; nop
            }
        }

        // Unlimited Health: vcvtsi2ss xmm0,[rcx+6EC]
        // Pattern: C5 FA 2A 81 EC 06 00 00
        {
            const uint8_t pat[] = { 0xC5, 0xFA, 0x2A, 0x81, 0xEC, 0x06, 0x00, 0x00 };
            addrHealth = AobScan(m_hProc, m_base, m_scanEnd, pat, "xxxxxxxx");
        }

        // Unlimited Stamina: mov rcx,[rcx]; mov rcx,[rcx+4D0]; vmovss xmm9,[rcx+4C]
        // Pattern: 48 8B 09 48 8B 89 D0 04 00 00 C5 7A 10 49 4C
        {
            const uint8_t pat[] = { 0x48, 0x8B, 0x09, 0x48, 0x8B, 0x89, 0xD0, 0x04, 0x00, 0x00,
                                    0xC5, 0x7A, 0x10, 0x49, 0x4C };
            addrStamina = AobScan(m_hProc, m_base, m_scanEnd, pat, "xxxxxxxxxxxxxxx");
        }

        // Super Speed: function prolog of GetMovementSpeed
        // Pattern (long, to be specific): 57 56 48 83 EC 68 C5 F8 77 C5 F8 29 74 24 50
        {
            const uint8_t pat[] = { 0x57, 0x56, 0x48, 0x83, 0xEC, 0x68, 0xC5, 0xF8, 0x77,
                                    0xC5, 0xF8, 0x29, 0x74, 0x24, 0x50 };
            addrSpeed = AobScan(m_hProc, m_base, m_scanEnd, pat, "xxxxxxxxxxxxxxx");
        }

        // Unlimited Items: lea ebp,[rax-1] -> lea ebp,[rax+0]  (one byte change at +2)
        // Pattern: 8D 68 FF 48 8B CF 8B D5 FF 53 10
        {
            const uint8_t pat[] = { 0x8D, 0x68, 0xFF, 0x48, 0x8B, 0xCF };
            uintptr_t a = AobScan(m_hProc, m_base, m_scanEnd, pat, "xxxxxx");
            if (a) {
                pItems.addr     = a + 2;   // byte at offset+2 is 0xFF (-1 displacement)
                pItems.original = { 0xFF };
                pItems.patched  = { 0x00 }; // change lea ebp,[rax-1] to lea ebp,[rax+0]
            }
        }

        // Unlimited Water: mov r8,[rsi+108]
        // Pattern: 4C 8B 86 08 01 00 00
        {
            const uint8_t pat[] = { 0x4C, 0x8B, 0x86, 0x08, 0x01, 0x00, 0x00 };
            addrWater = AobScan(m_hProc, m_base, m_scanEnd, pat, "xxxxxxx");
        }

        // Freeze Time: add dword ptr [counter],0A  ->  patch immediate to 00
        // Pattern: 83 05 ?? ?? ?? ?? 0A 8B 0D ?? ?? ?? ?? BA 1F 85 EB 51
        {
            const uint8_t pat[] = { 0x83, 0x05, 0x00, 0x00, 0x00, 0x00, 0x0A,
                                    0x8B, 0x0D, 0x00, 0x00, 0x00, 0x00,
                                    0xBA, 0x1F, 0x85, 0xEB, 0x51 };
            uintptr_t a = AobScan(m_hProc, m_base, m_scanEnd, pat, "xx????x?????xxxxxx");
            if (a) {
                pFreezeTime.addr     = a + 6; // the 0x0A immediate byte
                pFreezeTime.original = { 0x0A };
                pFreezeTime.patched  = { 0x00 };
            }
        }

        // Instant Fish Bite: vmovaps xmm0,xmm6; vmovaps xmm6,[rsp+20]
        // Pattern: C5 F8 28 C6 C5 F8 28 74 24 20
        {
            const uint8_t pat[] = { 0xC5, 0xF8, 0x28, 0xC6, 0xC5, 0xF8, 0x28, 0x74, 0x24, 0x20 };
            addrFishBite = AobScan(m_hProc, m_base, m_scanEnd, pat, "xxxxxxxxxx");
        }

        // Easy Fish Catch: movss [rcx+E8],xmm0
        // Pattern: F3 0F 11 81 E8 00 00 00
        {
            const uint8_t pat[] = { 0xF3, 0x0F, 0x11, 0x81, 0xE8, 0x00, 0x00, 0x00 };
            addrFishCatch = AobScan(m_hProc, m_base, m_scanEnd, pat, "xxxxxxxx");
        }

        // One Hit Trees: vmovss xmm1,[rcx+4C]  ->  vxorps xmm1,xmm1,xmm1 + nop
        // Pattern: C5 FA 10 49 4C C4 C1 72 5C C8
        {
            const uint8_t pat[] = { 0xC5, 0xFA, 0x10, 0x49, 0x4C, 0xC4, 0xC1, 0x72, 0x5C, 0xC8 };
            uintptr_t a = AobScan(m_hProc, m_base, m_scanEnd, pat, "xxxxxxxxxx");
            if (a) {
                pTrees.addr     = a;
                pTrees.original = { 0xC5, 0xFA, 0x10, 0x49, 0x4C };
                pTrees.patched  = { 0xC5, 0xF0, 0x57, 0xC9, 0x90 }; // vxorps xmm1,xmm1,xmm1; nop
            }
        }

        // Free Crafting: mov edx,[rax+38]; sub edx,[rax+40]
        // Pattern: 8B 50 38 2B 50 40
        {
            const uint8_t pat[] = { 0x8B, 0x50, 0x38, 0x2B, 0x50, 0x40 };
            addrFreeCraft = AobScan(m_hProc, m_base, m_scanEnd, pat, "xxxxxx");
        }

        // Instant Crop Growth: mov rcx,[rsi+28]; mov ecx,[rcx+4C]
        // Pattern: 48 8B 4E 28 8B 49 4C 48
        {
            const uint8_t pat[] = { 0x48, 0x8B, 0x4E, 0x28, 0x8B, 0x49, 0x4C, 0x48 };
            addrCropGrowth = AobScan(m_hProc, m_base, m_scanEnd, pat, "xxxxxxxx");
        }

        // Max Friendship: function prolog containing push r14/rdi/rsi/rbp/rbx
        // Pattern: 41 56 57 56 55 53 48
        {
            const uint8_t pat[] = { 0x41, 0x56, 0x57, 0x56, 0x55, 0x53, 0x48 };
            addrFriendship = AobScan(m_hProc, m_base, m_scanEnd, pat, "xxxxxxx");
        }

        // Max Pet Friendship: function prolog push rbp/r15/r14
        // Pattern: 55 41 57 41 56 41 55 41 54 57
        {
            const uint8_t pat[] = { 0x55, 0x41, 0x57, 0x41, 0x56, 0x41, 0x55, 0x41, 0x54, 0x57 };
            addrPetFriend = AobScan(m_hProc, m_base, m_scanEnd, pat, "xxxxxxxxxx");
        }

        // Stackables to 999: mov eax,[rax+4C]; test eax,eax; jle
        // Pattern: 8B 40 4C 85 C0 7E
        {
            const uint8_t pat[] = { 0x8B, 0x40, 0x4C, 0x85, 0xC0, 0x7E };
            addrStackables = AobScan(m_hProc, m_base, m_scanEnd, pat, "xxxxxx");
        }
    }

    // ------------------------------------------------------------------ hook install helpers

    void EnableHealth() {
        if (hookHealth.active || !addrHealth) return;
        // Trampoline: copy maxHealth (int@rcx+6F0) -> currentHealth (int@rcx+6EC),
        //             then execute original vcvtsi2ss xmm0,[rcx+6EC].
        uint8_t shell[] = {
            0xDB, 0x81, 0xF0, 0x06, 0x00, 0x00,             // fild dword ptr [rcx+6F0]
            0xDB, 0x99, 0xEC, 0x06, 0x00, 0x00,             // fistp dword ptr [rcx+6EC]
            0xC5, 0xFA, 0x2A, 0x81, 0xEC, 0x06, 0x00, 0x00 // vcvtsi2ss xmm0,[rcx+6EC] (original)
        };
        InstallHook(m_hProc, hookHealth, addrHealth, 8, shell, sizeof(shell), addrHealth + 8);
    }

    void EnableStamina() {
        if (hookStamina.active || !addrStamina) return;
        // Trampoline: execute original chain to reach stamina object, then fld/fstp
        //             to copy maxStamina -> currentStamina.
        // Patch size 10 (jmp5 + 5 nops); bytes 10-14 (vmovss xmm9,[rcx+4C]) untouched.
        // Return to addrStamina+10 where vmovss then reloads the now-maxed stamina.
        uint8_t shell[] = {
            0x48, 0x8B, 0x09,                              // mov rcx,[rcx]       (orig 0..2)
            0x48, 0x8B, 0x89, 0xD0, 0x04, 0x00, 0x00,    // mov rcx,[rcx+4D0]   (orig 3..9)
            0xD9, 0x41, 0x54,                              // fld  dword [rcx+54] (max stamina)
            0xD9, 0x59, 0x4C                               // fstp dword [rcx+4C] (cur stamina)
        };
        InstallHook(m_hProc, hookStamina, addrStamina, 10, shell, sizeof(shell), addrStamina + 10);
    }

    void EnableSpeed() {
        if (hookSpeed.active || !addrSpeed) return;
        // Trampoline replaces the entire GetMovementSpeed function with one that returns
        // 10.0f in xmm0. The trailing ret means the jmp-back appended by InstallHook
        // is dead code; pass returnAddr=0 so a null abs-jmp occupies that slot harmlessly.
        uint8_t shell[] = {
            0x48, 0x83, 0xEC, 0x08,                       // sub rsp,8
            0xC7, 0x04, 0x24, 0x00, 0x00, 0x20, 0x41,    // mov dword [rsp],0x41200000 (10.0f)
            0xF3, 0x0F, 0x10, 0x04, 0x24,                 // movss xmm0,[rsp]
            0x48, 0x83, 0xC4, 0x08,                       // add rsp,8
            0xC3                                           // ret
        };
        InstallHook(m_hProc, hookSpeed, addrSpeed, 6, shell, sizeof(shell), 0);
    }

    void EnableWater() {
        if (hookWater.active || !addrWater) return;
        // Trampoline: execute original load, then set waterLevel to 32 (full).
        uint8_t shell[] = {
            0x4C, 0x8B, 0x86, 0x08, 0x01, 0x00, 0x00,    // mov r8,[rsi+108]  (original 7 bytes)
            0x4D, 0x85, 0xC0,                              // test r8,r8
            0x74, 0x07,                                    // je +7 (skip set)
            0x41, 0xC7, 0x40, 0x4C, 0x20, 0x00, 0x00, 0x00 // mov dword [r8+4C],32
        };
        InstallHook(m_hProc, hookWater, addrWater, 7, shell, sizeof(shell), addrWater + 7);
    }

    void EnableFishBite() {
        if (hookFishBite.active || !addrFishBite) return;
        // Trampoline: zero xmm6 (the bite progress accumulator) before original movaps pair.
        uint8_t shell[] = {
            0x0F, 0x57, 0xF6,                              // xorps xmm6,xmm6
            0xC5, 0xF8, 0x28, 0xC6,                        // vmovaps xmm0,xmm6  (original 4 bytes)
            0xC5, 0xF8, 0x28, 0x74, 0x24, 0x20            // vmovaps xmm6,[rsp+20] (original 6 bytes)
        };
        InstallHook(m_hProc, hookFishBite, addrFishBite, 10, shell, sizeof(shell), addrFishBite + 10);
    }

    void EnableFishCatch() {
        if (hookFishCatch.active || !addrFishCatch) return;
        // Trampoline: write float 1.0 (catch bar full) to [rcx+E8], skip original movss.
        uint8_t shell[] = {
            // mov dword ptr [rcx+E8], 0x3F800000  (1.0f)
            0xC7, 0x81, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x3F
        };
        InstallHook(m_hProc, hookFishCatch, addrFishCatch, 8, shell, sizeof(shell), addrFishCatch + 8);
    }

    void EnableFreeCraft() {
        if (hookFreeCraft.active || !addrFreeCraft) return;
        // Trampoline: zero the required-ingredient count at [rax+38] before the subtract,
        //             then execute original mov edx / sub edx pair.
        uint8_t shell[] = {
            0xC7, 0x40, 0x38, 0x00, 0x00, 0x00, 0x00,     // mov dword [rax+38],0
            0x8B, 0x50, 0x38,                              // mov edx,[rax+38]  (original)
            0x2B, 0x50, 0x40                               // sub edx,[rax+40]  (original)
        };
        InstallHook(m_hProc, hookFreeCraft, addrFreeCraft, 6, shell, sizeof(shell), addrFreeCraft + 6);
    }

    void EnableCropGrowth() {
        if (hookCropGrowth.active || !addrCropGrowth) return;
        // Trampoline: advance the crop's current-phase to (totalPhases-1) on each tick,
        //             so the crop is always one day from harvest.
        // Original 7 bytes split: [rsi+28] dereference (4) + mov ecx,[rcx+4C] (3).
        uint8_t shell[] = {
            0x48, 0x8B, 0x4E, 0x28,        // mov rcx,[rsi+28]   (orig 0..3)
            0x48, 0x8B, 0x46, 0x10,        // mov rax,[rsi+10]
            0x48, 0x8B, 0x40, 0x38,        // mov rax,[rax+38]
            0x8B, 0x40, 0x4C,              // mov eax,[rax+4C]  (total phases)
            0xFF, 0xC8,                    // dec eax           (last phase index)
            0x3B, 0x41, 0x4C,              // cmp [rcx+4C],eax
            0x7F, 0x03,                    // jg +3             (skip if already at/past last)
            0x89, 0x41, 0x4C,              // mov [rcx+4C],eax  (set phase = last)
            0x8B, 0x49, 0x4C               // mov ecx,[rcx+4C]  (orig 4..6)
        };
        InstallHook(m_hProc, hookCropGrowth, addrCropGrowth, 7, shell, sizeof(shell), addrCropGrowth + 7);
    }

    void EnableFriendship() {
        if (hookFriendship.active || !addrFriendship) return;
        // Trampoline: set edx=9999999 (friendship points argument) then execute the
        //             original function prolog (push r14/rdi/rsi/rbp).
        // 9999999 decimal = 0x98967F
        uint8_t shell[] = {
            0xBA, 0x7F, 0x96, 0x98, 0x00, // mov edx,9999999
            0x41, 0x56,                    // push r14  (orig 0..1)
            0x57,                          // push rdi  (orig 2)
            0x56,                          // push rsi  (orig 3)
            0x55                           // push rbp  (orig 4)
        };
        InstallHook(m_hProc, hookFriendship, addrFriendship, 5, shell, sizeof(shell), addrFriendship + 5);
    }

    void EnablePetFriend() {
        if (hookPetFriend.active || !addrPetFriend) return;
        // Trampoline: set pet's friendship int (offset 4C in friendship object at rcx+450)
        //             to 1000 (max), then execute original prolog push rbp/r15/r14.
        uint8_t shell[] = {
            0x48, 0x8B, 0x81, 0x50, 0x04, 0x00, 0x00,    // mov rax,[rcx+450]
            0x48, 0x85, 0xC0,                              // test rax,rax
            0x74, 0x07,                                    // je +7 (skip set)
            0xC7, 0x40, 0x4C, 0xE8, 0x03, 0x00, 0x00,    // mov dword [rax+4C],0x3E8 (1000)
            0x55,                                          // push rbp  (orig 0)
            0x41, 0x57,                                    // push r15  (orig 1..2)
            0x41, 0x56                                     // push r14  (orig 3..4)
        };
        InstallHook(m_hProc, hookPetFriend, addrPetFriend, 5, shell, sizeof(shell), addrPetFriend + 5);
    }

    void EnableStackables() {
        if (hookStackables.active || !addrStackables) return;
        // Trampoline: overwrite the stored stack count with 999, then execute original
        //             mov eax/test eax so callers see 999.
        uint8_t shell[] = {
            0x53,                           // push rbx
            0xBB, 0xE7, 0x03, 0x00, 0x00,  // mov ebx,999
            0x89, 0x58, 0x4C,              // mov [rax+4C],ebx
            0x5B,                           // pop rbx
            0x8B, 0x40, 0x4C,              // mov eax,[rax+4C]  (orig 0..2)
            0x85, 0xC0                      // test eax,eax      (orig 3..4)
        };
        // Return to addrStackables+6: skips the patched jle byte at +5.
        InstallHook(m_hProc, hookStackables, addrStackables, 6, shell, sizeof(shell), addrStackables + 6);
    }

    // ------------------------------------------------------------------ loop

    void Loop() {
        bool prev[15] = {};

        while (m_running.load()) {
            int idx = 0;
            for (auto& f : m_features) {
                int vk = f.vk_code.load();
                if (vk && (GetAsyncKeyState(vk) & 1))
                    f.enabled.store(!f.enabled.load());
                idx++;
            }

            idx = 0;
            for (auto& f : m_features) {
                bool en = f.enabled.load();
                if (en == prev[idx]) { idx++; continue; }
                prev[idx] = en;

                const char* id = f.info.id;

                if      (!strcmp(id, "noclip"))             en ? ApplySimplePatch(m_hProc, pNoclip)     : RemoveSimplePatch(m_hProc, pNoclip);
                else if (!strcmp(id, "unlimited_health"))   en ? EnableHealth()    : RemoveHook(m_hProc, hookHealth);
                else if (!strcmp(id, "unlimited_stamina"))  en ? EnableStamina()   : RemoveHook(m_hProc, hookStamina);
                else if (!strcmp(id, "super_speed"))        en ? EnableSpeed()     : RemoveHook(m_hProc, hookSpeed);
                else if (!strcmp(id, "unlimited_items"))    en ? ApplySimplePatch(m_hProc, pItems)      : RemoveSimplePatch(m_hProc, pItems);
                else if (!strcmp(id, "unlimited_water"))    en ? EnableWater()     : RemoveHook(m_hProc, hookWater);
                else if (!strcmp(id, "freeze_time"))        en ? ApplySimplePatch(m_hProc, pFreezeTime) : RemoveSimplePatch(m_hProc, pFreezeTime);
                else if (!strcmp(id, "instant_fish_bite"))  en ? EnableFishBite()  : RemoveHook(m_hProc, hookFishBite);
                else if (!strcmp(id, "easy_fish_catch"))    en ? EnableFishCatch() : RemoveHook(m_hProc, hookFishCatch);
                else if (!strcmp(id, "one_hit_trees"))      en ? ApplySimplePatch(m_hProc, pTrees)      : RemoveSimplePatch(m_hProc, pTrees);
                else if (!strcmp(id, "free_crafting"))      en ? EnableFreeCraft() : RemoveHook(m_hProc, hookFreeCraft);
                else if (!strcmp(id, "instant_crop_growth"))en ? EnableCropGrowth(): RemoveHook(m_hProc, hookCropGrowth);
                else if (!strcmp(id, "max_friendship"))     en ? EnableFriendship(): RemoveHook(m_hProc, hookFriendship);
                else if (!strcmp(id, "max_pet_friendship")) en ? EnablePetFriend() : RemoveHook(m_hProc, hookPetFriend);
                else if (!strcmp(id, "stackables_999"))     en ? EnableStackables(): RemoveHook(m_hProc, hookStackables);

                idx++;
            }

            Sleep(50);
        }
    }

    // ------------------------------------------------------------------ shutdown

    void Shutdown() {
        m_running.store(false);
        if (m_thread.joinable()) m_thread.join();

        RemoveSimplePatch(m_hProc, pNoclip);
        RemoveSimplePatch(m_hProc, pItems);
        RemoveSimplePatch(m_hProc, pTrees);
        RemoveSimplePatch(m_hProc, pFreezeTime);

        RemoveHook(m_hProc, hookHealth);
        RemoveHook(m_hProc, hookStamina);
        RemoveHook(m_hProc, hookSpeed);
        RemoveHook(m_hProc, hookWater);
        RemoveHook(m_hProc, hookFishBite);
        RemoveHook(m_hProc, hookFishCatch);
        RemoveHook(m_hProc, hookFreeCraft);
        RemoveHook(m_hProc, hookCropGrowth);
        RemoveHook(m_hProc, hookFriendship);
        RemoveHook(m_hProc, hookPetFriend);
        RemoveHook(m_hProc, hookStackables);

        if (m_hProc) { CloseHandle(m_hProc); m_hProc = nullptr; }
    }

    // ------------------------------------------------------------------ API

    int          GetFeatureCount()               { return (int)m_features.size(); }
    const char*  GetName()                       { return "Stardew Valley Trainer"; }
    const char*  GetVersion()                    { return "2.0.0"; }

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
    __declspec(dllexport) void*       trainer_create()                              { return new StardewTrainer(); }
    __declspec(dllexport) void        trainer_destroy(void* h)                      { delete static_cast<StardewTrainer*>(h); }
    __declspec(dllexport) int         trainer_initialize(void* h)                   { return static_cast<StardewTrainer*>(h)->Initialize() ? 1 : 0; }
    __declspec(dllexport) void        trainer_shutdown(void* h)                     { static_cast<StardewTrainer*>(h)->Shutdown(); }
    __declspec(dllexport) const char* trainer_get_name(void* h)                     { return static_cast<StardewTrainer*>(h)->GetName(); }
    __declspec(dllexport) const char* trainer_get_version(void* h)                  { return static_cast<StardewTrainer*>(h)->GetVersion(); }
    __declspec(dllexport) int         trainer_get_feature_count(void* h)            { return static_cast<StardewTrainer*>(h)->GetFeatureCount(); }
    __declspec(dllexport) const TrainerFeatureInfo* trainer_get_feature_info(void* h, int idx) { return static_cast<StardewTrainer*>(h)->GetFeatureInfo(idx); }
    __declspec(dllexport) int         trainer_get_feature_enabled(void* h, const char* id)     { return static_cast<StardewTrainer*>(h)->GetFeatureEnabled(id); }
    __declspec(dllexport) void        trainer_set_feature_enabled(void* h, const char* id, int en) { static_cast<StardewTrainer*>(h)->SetFeatureEnabled(id, en); }
    __declspec(dllexport) void        trainer_activate_feature(void* h, const char* id)        { static_cast<StardewTrainer*>(h)->ActivateFeature(id); }
    __declspec(dllexport) void        trainer_set_keybind(void* h, const char* id, int vk)     { static_cast<StardewTrainer*>(h)->SetKeybind(id, vk); }
    __declspec(dllexport) int         trainer_get_keybind(void* h, const char* id)             { return static_cast<StardewTrainer*>(h)->GetKeybind(id); }
    __declspec(dllexport) const char* trainer_get_last_error()                      { return ""; }
}
