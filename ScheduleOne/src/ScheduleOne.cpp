#include <windows.h>
#include <tlhelp32.h>
#include <vector>
#include <list>
#include <thread>
#include <atomic>
#include <cstdint>
#include <cstring>

// ============================================================
//  ScheduleOne Trainer
//  Target exe   : Schedule I.exe
//  Target module: GameAssembly.dll
// ============================================================

struct TrainerFeatureInfo {
    const char* id;
    const char* name;
    const char* description;
    int is_toggle;   // 1 = toggle, 0 = one-shot
    int hotkey;
};

// ─────────────────────────────────────────────────────────────
//  Utilities
// ─────────────────────────────────────────────────────────────

static DWORD FindPid(const wchar_t* exe) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32W pe{ sizeof(pe) };
    DWORD pid = 0;
    if (Process32FirstW(snap, &pe))
        do {
            if (_wcsicmp(pe.szExeFile, exe) == 0) { pid = pe.th32ProcessID; break; }
        } while (Process32NextW(snap, &pe));
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
            if (_wcsicmp(me.szModule, modName) == 0) { base = (uintptr_t)me.modBaseAddr; break; }
        } while (Module32NextW(snap, &me));
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

static bool MemRead(HANDLE hProc, uintptr_t addr, void* buf, size_t size) {
    SIZE_T r;
    return ReadProcessMemory(hProc, (LPCVOID)addr, buf, size, &r) && r == size;
}

static void MemWriteFloat(HANDLE hProc, uintptr_t addr, float val) {
    MemWrite(hProc, addr, &val, sizeof(float));
}

static void MemWriteInt(HANDLE hProc, uintptr_t addr, int32_t val) {
    MemWrite(hProc, addr, &val, sizeof(int32_t));
}

// pat: 0x00 = wildcard byte
static uintptr_t AobScan(HANDLE hProc, uintptr_t base, size_t sz,
                          const uint8_t* pat, size_t len) {
    std::vector<uint8_t> buf(sz);
    SIZE_T r = 0;
    if (!ReadProcessMemory(hProc, (LPCVOID)base, buf.data(), sz, &r)) return 0;
    for (size_t i = 0; i + len <= r; ++i) {
        bool match = true;
        for (size_t j = 0; j < len; j++)
            if (pat[j] != 0x00 && buf[i + j] != pat[j]) { match = false; break; }
        if (match) return base + i;
    }
    return 0;
}

// Build a 14-byte absolute indirect JMP:  FF 25 00000000 <8-byte addr>
static void BuildAbsJmp(uint8_t out[14], uintptr_t target) {
    out[0] = 0xFF; out[1] = 0x25;
    out[2] = out[3] = out[4] = out[5] = 0x00;
    memcpy(&out[6], &target, 8);
}

// ─────────────────────────────────────────────────────────────
//  Feature
// ─────────────────────────────────────────────────────────────

struct Feature {
    TrainerFeatureInfo info;
    std::atomic<bool>  enabled{ false };
    std::atomic<int>   vk_code{ 0 };
    Feature(const char* i, const char* n, const char* d, int tog, int vk)
        : info{ i, n, d, tog, vk }, vk_code(vk) {}
};

// ─────────────────────────────────────────────────────────────
//  ScheduleOneTrainer
// ─────────────────────────────────────────────────────────────

class ScheduleOneTrainer {
public:
    HANDLE            m_hProc  = nullptr;
    std::atomic<bool> m_running{ false };
    std::thread       m_thread;
    std::list<Feature> m_features;

    // ── Pointer cache (resolved at Initialize) ────────────────
    uintptr_t ptr_MoneyEdit      = 0; // float* → on-hand cash
    uintptr_t ptr_BankMoneyEdit  = 0; // float* → bank balance
    uintptr_t ptr_TimeEdit       = 0; // int*   → in-game hour counter
    uintptr_t ptr_WantedLevel    = 0; // int*   → police wanted level

    // ── AOB addresses (patched in/out) ────────────────────────
    uintptr_t addr_HP            = 0;
    uint8_t   orig_HP[4]         = { 0xF3, 0x0F, 0x5C, 0xCE };
    uint8_t   patch_HP[4]        = { 0x0F, 0x58, 0xCE, 0x90 }; // addss xmm1,xmm6

    uintptr_t addr_MoveSpeed     = 0;
    uint8_t   orig_MoveSpeed[14] = {};
    uintptr_t cave_MoveSpeed     = 0;

    uintptr_t addr_Visibility    = 0;
    uint8_t   orig_Visibility[5] = {};
    uintptr_t cave_Visibility    = 0;

    uintptr_t addr_RelationCalc  = 0;
    uint8_t   orig_RelCalc[2]    = { 0x76, 0x08 };

    uintptr_t addr_Curfew        = 0;
    uint8_t   orig_Curfew[2]     = { 0x75, 0x0F };

    uintptr_t addr_Growth        = 0;
    uint8_t   orig_Growth[5]     = {};
    uintptr_t cave_Growth        = 0;

    uintptr_t addr_MultItem      = 0;
    uint8_t   orig_MultItem[6]   = {};
    uintptr_t cave_MultItem      = 0;

    uintptr_t addr_Cost          = 0;
    uint8_t   orig_Cost[7]       = {};
    uintptr_t cave_Cost          = 0;

    uintptr_t addr_ShopBuy       = 0;
    uint8_t   orig_ShopBuy[2]    = { 0x75, 0x08 };

    uintptr_t addr_Mixing        = 0;
    uint8_t   orig_Mixing[3]     = { 0x8D, 0x0C, 0x16 };
    uint8_t   patch_Mixing[3]    = { 0x8D, 0x4A, 0x77 };

    uintptr_t addr_Watering      = 0;
    uint8_t   orig_Watering[2]   = { 0x76, 0x08 };

    uintptr_t addr_EXP           = 0;
    uint8_t   orig_EXP[6]        = {};
    uintptr_t cave_EXP           = 0;

    uintptr_t addr_TimeSet       = 0;
    uint8_t   orig_TimeSet[3]    = { 0x8D, 0x46, 0x01 };

    // ── Previous-state for edge detection ─────────────────────
    bool p_cash=false, p_bank=false, p_exp=false, p_rel=false;
    bool p_speed=false, p_hp=false, p_invis=false, p_noinvest=false;
    bool p_zawarudo=false, p_watering=false, p_nocurfew=false;
    bool p_growth=false, p_clone=false, p_freeshop=false;
    bool p_shopunlock=false, p_mixing=false;

    // ─────────────────────────────────────────────────────────
    ScheduleOneTrainer() {
        // Toggles
        m_features.emplace_back("unlimited_cash",              "Unlimited Cash",               "On-hand money locked to $777,777",       1, VK_F1);
        m_features.emplace_back("unlimited_balance",           "Unlimited Bank Balance",        "Bank balance locked to $777,777",        1, VK_F2);
        m_features.emplace_back("multiply_exp_gain",           "EXP x7",                        "Multiplies XP gain by 7",                1, VK_F3);
        m_features.emplace_back("instant_max_relationship",    "Instant Max Relationship",      "NPC relationship calc always passes",    1, VK_F4);
        m_features.emplace_back("multiply_run_speed",          "Run Speed x3",                  "Multiplies movement speed by 3",         1, VK_F5);
        m_features.emplace_back("unlimited_health",            "Unlimited Health",              "HP never decreases",                     1, VK_F6);
        m_features.emplace_back("invisibility",                "Invisibility",                  "Player visibility forced to 0",          1, VK_F7);
        m_features.emplace_back("no_investigate_no_body_search","No Investigate / Body Search", "Police skip investigation checks",       1, VK_F8);
        m_features.emplace_back("za_warudo",                   "Za Warudo (Freeze Time)",       "Game clock stops advancing",             1, VK_F9);
        m_features.emplace_back("refill_watering_can_after_use","Refill Watering Can",          "Watering can never runs out",            1, VK_F10);
        m_features.emplace_back("no_curfew",                   "No Curfew",                     "Curfew restrictions removed",            1, VK_F11);
        m_features.emplace_back("plants_instant_grown",        "Plants Instant Grown",          "Plants skip to fully grown stage",       1, VK_F12);
        m_features.emplace_back("clone_items_when_click",      "Clone Items on Pick-up",        "Item quantities doubled on collection",  1, 0);
        m_features.emplace_back("free_shopping",               "Free Shopping",                 "All shop costs zeroed",                  1, 0);
        m_features.emplace_back("shop_unlock_all_items",       "Shop: Unlock All Items",        "Bypasses item unlock checks",            1, 0);
        m_features.emplace_back("instant_mixing_ingredient",   "Instant Mixing",                "Drug mixing timer set to instant",       1, 0);
        // One-shots
        m_features.emplace_back("edit_cash",          "Set Cash to $999,999",     "Write $999,999 to on-hand wallet",       0, 0);
        m_features.emplace_back("edit_bank_balance",  "Set Bank to $999,999",     "Write $999,999 to bank balance",         0, 0);
        m_features.emplace_back("add_1_hour",         "+1 Hour",                   "Advance game clock by 1 hour",           0, 0);
        m_features.emplace_back("sub_1_hour",         "-1 Hour",                   "Rewind game clock by 1 hour",            0, 0);
        m_features.emplace_back("raise_wanted_level", "Raise Wanted Level",        "Increment police wanted level",          0, 0);
        m_features.emplace_back("reduce_wanted_level","Reduce Wanted Level",       "Decrement police wanted level",          0, 0);
    }

    bool Initialize() {
        DWORD pid = FindPid(L"Schedule I.exe");
        if (!pid) return false;
        m_hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
        if (!m_hProc) return false;
        uintptr_t mod = GetModuleBase(pid, L"GameAssembly.dll");
        if (!mod) return false;
        constexpr size_t SCAN_SIZE = 0x5000000;

        // unlimited_health: F3 0F 10 8B ?? ?? 00 00 F3 0F 5C CE 0F 57 F6
        {
            uint8_t p[] = {0xF3,0x0F,0x10,0x8B,0x00,0x00,0x00,0x00,
                           0xF3,0x0F,0x5C,0xCE,0x0F,0x57,0xF6};
            uintptr_t hit = AobScan(m_hProc, mod, SCAN_SIZE, p, sizeof(p));
            if (hit) { addr_HP = hit + 8; MemRead(m_hProc, addr_HP, orig_HP, 4); }
        }

        // multiply_run_speed: 0F 28 CE F3 41 0F 59 C3 F3 41
        {
            uint8_t p[] = {0x0F,0x28,0xCE,0xF3,0x41,0x0F,0x59,0xC3,0xF3,0x41};
            uintptr_t hit = AobScan(m_hProc, mod, SCAN_SIZE, p, sizeof(p));
            if (hit) {
                addr_MoveSpeed = hit;
                MemRead(m_hProc, addr_MoveSpeed, orig_MoveSpeed, 14);
                cave_MoveSpeed = (uintptr_t)VirtualAllocEx(m_hProc, nullptr, 256,
                                     MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
                if (cave_MoveSpeed) {
                    float mult = 3.0f;
                    uint8_t cave[64] = {};
                    size_t off = 0;
                    uintptr_t floatAddr = cave_MoveSpeed + 48;
                    int32_t rel = (int32_t)(floatAddr - (cave_MoveSpeed + off + 8));
                    cave[off++]=0xF3; cave[off++]=0x0F; cave[off++]=0x59; cave[off++]=0x35;
                    memcpy(&cave[off], &rel, 4); off += 4;
                    cave[off++]=0x0F; cave[off++]=0x28; cave[off++]=0xCE;
                    cave[off++]=0xF3; cave[off++]=0x41; cave[off++]=0x0F;
                    cave[off++]=0x59; cave[off++]=0xC3;
                    uintptr_t ret = addr_MoveSpeed + 10;
                    uint8_t jmp14[14]; BuildAbsJmp(jmp14, ret);
                    memcpy(&cave[off], jmp14, 14); off += 14;
                    memcpy(&cave[48], &mult, 4);
                    MemWrite(m_hProc, cave_MoveSpeed, cave, 64);
                }
            }
        }

        // invisibility: F3 0F 11 43 1C 48 8B 8E ?? ?? 00 00
        {
            uint8_t p[] = {0xF3,0x0F,0x11,0x43,0x1C,0x48,0x8B,0x8E,0x00,0x00,0x00,0x00};
            uintptr_t hit = AobScan(m_hProc, mod, SCAN_SIZE, p, sizeof(p));
            if (hit) {
                addr_Visibility = hit;
                MemRead(m_hProc, addr_Visibility, orig_Visibility, 5);
                cave_Visibility = (uintptr_t)VirtualAllocEx(m_hProc, nullptr, 128,
                                      MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
                if (cave_Visibility) {
                    uint8_t cave[64] = {};
                    size_t off = 0;
                    cave[off++]=0x0F; cave[off++]=0x57; cave[off++]=0xC0; // xorps xmm0,xmm0
                    cave[off++]=0xF3; cave[off++]=0x0F; cave[off++]=0x11;
                    cave[off++]=0x43; cave[off++]=0x1C;  // movss [rbx+1C],xmm0
                    uintptr_t ret = addr_Visibility + 5;
                    uint8_t jmp14[14]; BuildAbsJmp(jmp14, ret);
                    memcpy(&cave[off], jmp14, 14);
                    MemWrite(m_hProc, cave_Visibility, cave, 64);
                }
            }
        }

        // no_investigate / instant_max_relationship: 76 08 0F 28 F0 EB 03 0F 57 F6 0F 28 C6
        {
            uint8_t p[] = {0x76,0x08,0x0F,0x28,0xF0,0xEB,0x03,0x0F,0x57,0xF6,0x0F,0x28,0xC6};
            uintptr_t hit = AobScan(m_hProc, mod, SCAN_SIZE, p, sizeof(p));
            if (hit) addr_RelationCalc = hit;
        }

        // no_curfew: 75 0F 66 C7 83 ?? ?? 00 00 00 00
        {
            uint8_t p[] = {0x75,0x0F,0x66,0xC7,0x83,0x00,0x00,0x00,0x00,0x00,0x00};
            uintptr_t hit = AobScan(m_hProc, mod, SCAN_SIZE, p, sizeof(p));
            if (hit) addr_Curfew = hit;
        }

        // plants_instant_grown: F3 0F 58 73 28 49 8B
        {
            uint8_t p[] = {0xF3,0x0F,0x58,0x73,0x28,0x49,0x8B};
            uintptr_t hit = AobScan(m_hProc, mod, SCAN_SIZE, p, sizeof(p));
            if (hit) {
                addr_Growth = hit;
                MemRead(m_hProc, addr_Growth, orig_Growth, 5);
                cave_Growth = (uintptr_t)VirtualAllocEx(m_hProc, nullptr, 128,
                                  MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
                if (cave_Growth) {
                    float one = 1.0f;
                    uint8_t cave[64] = {};
                    size_t off = 0;
                    cave[off++]=0x68; memcpy(&cave[off],&one,4); off+=4; // push 1.0f
                    cave[off++]=0xF3; cave[off++]=0x0F; cave[off++]=0x10;
                    cave[off++]=0x34; cave[off++]=0x24; // movss xmm6,[rsp]
                    cave[off++]=0x48; cave[off++]=0x83; cave[off++]=0xC4; cave[off++]=0x08; // add rsp,8
                    uintptr_t ret = addr_Growth + 5;
                    uint8_t jmp14[14]; BuildAbsJmp(jmp14, ret);
                    memcpy(&cave[off], jmp14, 14);
                    MemWrite(m_hProc, cave_Growth, cave, 64);
                }
            }
        }

        // clone_items_when_click: 48 8B CB 8B 52 10 ?? ?? 80
        {
            uint8_t p[] = {0x48,0x8B,0xCB,0x8B,0x52,0x10,0x00,0x00,0x80};
            uintptr_t hit = AobScan(m_hProc, mod, SCAN_SIZE, p, sizeof(p));
            if (hit) {
                addr_MultItem = hit;
                MemRead(m_hProc, addr_MultItem, orig_MultItem, 6);
                cave_MultItem = (uintptr_t)VirtualAllocEx(m_hProc, nullptr, 128,
                                    MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
                if (cave_MultItem) {
                    uint8_t cave[64] = {};
                    size_t off = 0;
                    cave[off++]=0x50;                         // push rax
                    cave[off++]=0x8B; cave[off++]=0x42; cave[off++]=0x10; // mov eax,[rdx+10]
                    cave[off++]=0x6B; cave[off++]=0xC0; cave[off++]=0x02; // imul eax,eax,2
                    cave[off++]=0x89; cave[off++]=0x42; cave[off++]=0x10; // mov [rdx+10],eax
                    cave[off++]=0x58;                         // pop rax
                    cave[off++]=0x48; cave[off++]=0x8B; cave[off++]=0xCB; // mov rcx,rbx
                    cave[off++]=0x8B; cave[off++]=0x52; cave[off++]=0x10; // mov edx,[rdx+10]
                    uintptr_t ret = addr_MultItem + 6;
                    uint8_t jmp14[14]; BuildAbsJmp(jmp14, ret);
                    memcpy(&cave[off], jmp14, 14);
                    MemWrite(m_hProc, cave_MultItem, cave, 64);
                }
            }
        }

        // free_shopping: 0F 28 F0 F3 0F 58 F7 75
        {
            uint8_t p[] = {0x0F,0x28,0xF0,0xF3,0x0F,0x58,0xF7,0x75};
            uintptr_t hit = AobScan(m_hProc, mod, SCAN_SIZE, p, sizeof(p));
            if (hit) {
                addr_Cost = hit;
                MemRead(m_hProc, addr_Cost, orig_Cost, 7);
                cave_Cost = (uintptr_t)VirtualAllocEx(m_hProc, nullptr, 128,
                                MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
                if (cave_Cost) {
                    uint8_t cave[64] = {};
                    size_t off = 0;
                    cave[off++]=0x0F; cave[off++]=0x28; cave[off++]=0xF0; // movaps xmm6,xmm0
                    cave[off++]=0x0F; cave[off++]=0x57; cave[off++]=0xF6; // xorps  xmm6,xmm6
                    cave[off++]=0xF3; cave[off++]=0x0F; cave[off++]=0x58; cave[off++]=0xF7; // addss xmm6,xmm7
                    uintptr_t ret = addr_Cost + 7;
                    uint8_t jmp14[14]; BuildAbsJmp(jmp14, ret);
                    memcpy(&cave[off], jmp14, 14);
                    MemWrite(m_hProc, cave_Cost, cave, 64);
                }
            }
        }

        // shop_unlock_all_items: 00 00 00 00 75 08 B0 01 48 83 C4 20
        {
            uint8_t p[] = {0x00,0x00,0x00,0x00,0x75,0x08,0xB0,0x01,0x48,0x83,0xC4,0x20};
            uintptr_t hit = AobScan(m_hProc, mod, SCAN_SIZE, p, sizeof(p));
            if (hit) addr_ShopBuy = hit + 4;
        }

        // instant_mixing: 8D 0C 16 89 8B ?? ?? 00 00 48 8B 83 ?? ?? 00 00
        {
            uint8_t p[] = {0x8D,0x0C,0x16,0x89,0x8B,0x00,0x00,0x00,0x00,
                           0x48,0x8B,0x83,0x00,0x00,0x00,0x00};
            uintptr_t hit = AobScan(m_hProc, mod, SCAN_SIZE, p, sizeof(p));
            if (hit) addr_Mixing = hit;
        }

        // refill_watering_can: 76 08 0F 28 C1
        {
            uint8_t p[] = {0x76,0x08,0x0F,0x28,0xC1};
            uintptr_t hit = AobScan(m_hProc, mod, SCAN_SIZE, p, sizeof(p));
            if (hit) addr_Watering = hit;
        }

        // EXP x7: 01 BB ?? ?? 00 00 BA 07 00 00 00
        {
            uint8_t p[] = {0x01,0xBB,0x00,0x00,0x00,0x00,0xBA,0x07,0x00,0x00,0x00};
            uintptr_t hit = AobScan(m_hProc, mod, SCAN_SIZE, p, sizeof(p));
            if (hit) {
                addr_EXP = hit;
                MemRead(m_hProc, addr_EXP, orig_EXP, 6);
                cave_EXP = (uintptr_t)VirtualAllocEx(m_hProc, nullptr, 128,
                               MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
                if (cave_EXP) {
                    uint8_t cave[64] = {};
                    size_t off = 0;
                    cave[off++]=0x6B; cave[off++]=0xFF; cave[off++]=0x07; // imul edi,edi,7
                    MemRead(m_hProc, addr_EXP, &cave[off], 6); off += 6;  // original bytes
                    uintptr_t ret = addr_EXP + 6;
                    uint8_t jmp14[14]; BuildAbsJmp(jmp14, ret);
                    memcpy(&cave[off], jmp14, 14);
                    MemWrite(m_hProc, cave_EXP, cave, 64);
                }
            }
        }

        // za_warudo: 8D 46 01 89 83 ?? ?? 00 00
        {
            uint8_t p[] = {0x8D,0x46,0x01,0x89,0x83,0x00,0x00,0x00,0x00};
            uintptr_t hit = AobScan(m_hProc, mod, SCAN_SIZE, p, sizeof(p));
            if (hit) addr_TimeSet = hit;
        }

        // Cash pointer AOB: F3 0F 58 49 30 0F 57
        {
            uint8_t p[] = {0xF3,0x0F,0x58,0x49,0x30,0x0F,0x57};
            uintptr_t hit = AobScan(m_hProc, mod, SCAN_SIZE, p, sizeof(p));
            if (hit) ptr_MoneyEdit = hit;
        }

        // Bank pointer AOB: F3 0F 10 81 ?? ?? 00 00 45 33 C9 45 33 C0 33 D2
        {
            uint8_t p[] = {0xF3,0x0F,0x10,0x81,0x00,0x00,0x00,0x00,
                           0x45,0x33,0xC9,0x45,0x33,0xC0,0x33,0xD2};
            uintptr_t hit = AobScan(m_hProc, mod, SCAN_SIZE, p, sizeof(p));
            if (hit) ptr_BankMoneyEdit = hit;
        }

        // Time pointer AOB: 81 BB 28 01 00 00 90 01 00 00 48
        {
            uint8_t p[] = {0x81,0xBB,0x28,0x01,0x00,0x00,0x90,0x01,0x00,0x00,0x48};
            uintptr_t hit = AobScan(m_hProc, mod, SCAN_SIZE, p, sizeof(p));
            if (hit) ptr_TimeEdit = hit;
        }

        m_running = true;
        m_thread = std::thread(&ScheduleOneTrainer::Loop, this);
        return true;
    }

    // ─────────────────────────────────────────────────────────
    void ApplyNop2(bool enable, uintptr_t addr, const uint8_t orig[2]) {
        if (!addr) return;
        if (enable) { uint8_t n[2]={0x90,0x90}; MemWrite(m_hProc,addr,n,2); }
        else          MemWrite(m_hProc,addr,orig,2);
    }
    void ApplyNop3(bool enable, uintptr_t addr, const uint8_t orig[3]) {
        if (!addr) return;
        if (enable) { uint8_t n[3]={0x90,0x90,0x90}; MemWrite(m_hProc,addr,n,3); }
        else          MemWrite(m_hProc,addr,orig,3);
    }
    void ApplyHook5(bool enable, uintptr_t addr, uintptr_t cave, const uint8_t orig[5]) {
        if (!addr||!cave) return;
        if (enable) {
            int32_t rel=(int32_t)(cave-addr-5);
            uint8_t hook[5]={0xE9}; memcpy(&hook[1],&rel,4);
            MemWrite(m_hProc,addr,hook,5);
        } else MemWrite(m_hProc,addr,orig,5);
    }

    // ─────────────────────────────────────────────────────────
    void Loop() {
        while (m_running) {
            for (auto& f : m_features)
                if (f.info.is_toggle && f.vk_code.load() &&
                    (GetAsyncKeyState(f.vk_code.load()) & 1))
                    f.enabled = !f.enabled.load();

            auto it = m_features.begin();

            // 1. unlimited_cash
            { bool en=it->enabled.load();
              if (en && ptr_MoneyEdit) MemWriteFloat(m_hProc, ptr_MoneyEdit, 777777.0f); }
            ++it;

            // 2. unlimited_balance
            { bool en=it->enabled.load();
              if (en && ptr_BankMoneyEdit) MemWriteFloat(m_hProc, ptr_BankMoneyEdit, 777777.0f); }
            ++it;

            // 3. multiply_exp_gain
            { bool en=it->enabled.load();
              if (en!=p_exp) { ApplyHook5(en,addr_EXP,cave_EXP,orig_EXP); p_exp=en; } }
            ++it;

            // 4. instant_max_relationship
            { bool en=it->enabled.load();
              if (en!=p_rel) { ApplyNop2(en,addr_RelationCalc,orig_RelCalc); p_rel=en; } }
            ++it;

            // 5. multiply_run_speed (14-byte hook, 10 bytes used + 4 nop pad)
            { bool en=it->enabled.load();
              if (en!=p_speed && cave_MoveSpeed) {
                  if (en) {
                      uint8_t hook[14]; BuildAbsJmp(hook,cave_MoveSpeed);
                      MemWrite(m_hProc,addr_MoveSpeed,hook,10);
                      uint8_t nops[4]={0x90,0x90,0x90,0x90};
                      MemWrite(m_hProc,addr_MoveSpeed+10,nops,4);
                  } else MemWrite(m_hProc,addr_MoveSpeed,orig_MoveSpeed,14);
                  p_speed=en;
              } }
            ++it;

            // 6. unlimited_health
            { bool en=it->enabled.load();
              if (en!=p_hp && addr_HP) {
                  if (en) MemWrite(m_hProc,addr_HP,patch_HP,4);
                  else    MemWrite(m_hProc,addr_HP,orig_HP,4);
                  p_hp=en;
              } }
            ++it;

            // 7. invisibility
            { bool en=it->enabled.load();
              if (en!=p_invis) { ApplyHook5(en,addr_Visibility,cave_Visibility,orig_Visibility); p_invis=en; } }
            ++it;

            // 8. no_investigate_no_body_search
            { bool en=it->enabled.load();
              if (en!=p_noinvest) { ApplyNop2(en,addr_RelationCalc,orig_RelCalc); p_noinvest=en; } }
            ++it;

            // 9. za_warudo
            { bool en=it->enabled.load();
              if (en!=p_zawarudo) { ApplyNop3(en,addr_TimeSet,orig_TimeSet); p_zawarudo=en; } }
            ++it;

            // 10. refill_watering_can
            { bool en=it->enabled.load();
              if (en!=p_watering) { ApplyNop2(en,addr_Watering,orig_Watering); p_watering=en; } }
            ++it;

            // 11. no_curfew
            { bool en=it->enabled.load();
              if (en!=p_nocurfew) { ApplyNop2(en,addr_Curfew,orig_Curfew); p_nocurfew=en; } }
            ++it;

            // 12. plants_instant_grown
            { bool en=it->enabled.load();
              if (en!=p_growth) { ApplyHook5(en,addr_Growth,cave_Growth,orig_Growth); p_growth=en; } }
            ++it;

            // 13. clone_items_when_click (6-byte hook)
            { bool en=it->enabled.load();
              if (en!=p_clone && cave_MultItem && addr_MultItem) {
                  if (en) { uint8_t hook[14]; BuildAbsJmp(hook,cave_MultItem); MemWrite(m_hProc,addr_MultItem,hook,6); }
                  else      MemWrite(m_hProc,addr_MultItem,orig_MultItem,6);
                  p_clone=en;
              } }
            ++it;

            // 14. free_shopping (7-byte hook)
            { bool en=it->enabled.load();
              if (en!=p_freeshop && cave_Cost && addr_Cost) {
                  if (en) { uint8_t hook[14]; BuildAbsJmp(hook,cave_Cost); MemWrite(m_hProc,addr_Cost,hook,7); }
                  else      MemWrite(m_hProc,addr_Cost,orig_Cost,7);
                  p_freeshop=en;
              } }
            ++it;

            // 15. shop_unlock_all_items
            { bool en=it->enabled.load();
              if (en!=p_shopunlock) { ApplyNop2(en,addr_ShopBuy,orig_ShopBuy); p_shopunlock=en; } }
            ++it;

            // 16. instant_mixing_ingredient
            { bool en=it->enabled.load();
              if (en!=p_mixing && addr_Mixing) {
                  if (en) MemWrite(m_hProc,addr_Mixing,patch_Mixing,3);
                  else    MemWrite(m_hProc,addr_Mixing,orig_Mixing,3);
                  p_mixing=en;
              } }
            ++it;

            // One-shots 17-22 are handled in ActivateFeature()

            Sleep(10);
        }
    }

    void Shutdown() {
        m_running = false;
        if (m_thread.joinable()) m_thread.join();
        if (addr_HP)          MemWrite(m_hProc,addr_HP,orig_HP,4);
        if (addr_MoveSpeed)   MemWrite(m_hProc,addr_MoveSpeed,orig_MoveSpeed,14);
        if (addr_Visibility)  MemWrite(m_hProc,addr_Visibility,orig_Visibility,5);
        if (addr_RelationCalc)MemWrite(m_hProc,addr_RelationCalc,orig_RelCalc,2);
        if (addr_Curfew)      MemWrite(m_hProc,addr_Curfew,orig_Curfew,2);
        if (addr_Growth)      MemWrite(m_hProc,addr_Growth,orig_Growth,5);
        if (addr_MultItem)    MemWrite(m_hProc,addr_MultItem,orig_MultItem,6);
        if (addr_Cost)        MemWrite(m_hProc,addr_Cost,orig_Cost,7);
        if (addr_ShopBuy)     MemWrite(m_hProc,addr_ShopBuy,orig_ShopBuy,2);
        if (addr_Mixing)      MemWrite(m_hProc,addr_Mixing,orig_Mixing,3);
        if (addr_Watering)    MemWrite(m_hProc,addr_Watering,orig_Watering,2);
        if (addr_TimeSet)     MemWrite(m_hProc,addr_TimeSet,orig_TimeSet,3);
        if (addr_EXP)         MemWrite(m_hProc,addr_EXP,orig_EXP,6);
        auto FreeCave = [&](uintptr_t c) {
            if (c) VirtualFreeEx(m_hProc,(LPVOID)c,0,MEM_RELEASE);
        };
        FreeCave(cave_MoveSpeed); FreeCave(cave_Visibility);
        FreeCave(cave_Growth);    FreeCave(cave_MultItem);
        FreeCave(cave_Cost);      FreeCave(cave_EXP);
        if (m_hProc) { CloseHandle(m_hProc); m_hProc=nullptr; }
    }

    void ActivateFeature(const char* id) {
        if      (!strcmp(id,"edit_cash")          && ptr_MoneyEdit)
                    MemWriteFloat(m_hProc, ptr_MoneyEdit, 999999.0f);
        else if (!strcmp(id,"edit_bank_balance")  && ptr_BankMoneyEdit)
                    MemWriteFloat(m_hProc, ptr_BankMoneyEdit, 999999.0f);
        else if (!strcmp(id,"add_1_hour")         && ptr_TimeEdit) {
                    int32_t t=0; MemRead(m_hProc,ptr_TimeEdit,&t,4);
                    MemWriteInt(m_hProc,ptr_TimeEdit,t+1); }
        else if (!strcmp(id,"sub_1_hour")         && ptr_TimeEdit) {
                    int32_t t=0; MemRead(m_hProc,ptr_TimeEdit,&t,4);
                    MemWriteInt(m_hProc,ptr_TimeEdit,t-1); }
        else if (!strcmp(id,"raise_wanted_level") && ptr_WantedLevel) {
                    int32_t w=0; MemRead(m_hProc,ptr_WantedLevel,&w,4);
                    if (w<5) MemWriteInt(m_hProc,ptr_WantedLevel,w+1); }
        else if (!strcmp(id,"reduce_wanted_level")&& ptr_WantedLevel) {
                    int32_t w=0; MemRead(m_hProc,ptr_WantedLevel,&w,4);
                    if (w>0) MemWriteInt(m_hProc,ptr_WantedLevel,w-1); }
    }

    int GetFeatureCount() { return (int)m_features.size(); }
    const TrainerFeatureInfo* GetFeatureInfo(int idx) {
        auto it=m_features.begin(); std::advance(it,idx); return &it->info; }
    int  GetFeatureEnabled(const char* id) {
        for (auto& f:m_features) if (!strcmp(f.info.id,id)) return f.enabled?1:0; return 0; }
    void SetFeatureEnabled(const char* id, int en) {
        for (auto& f:m_features) if (!strcmp(f.info.id,id)) f.enabled=(en!=0); }
    void SetKeybind(const char* id, int vk) {
        for (auto& f:m_features) if (!strcmp(f.info.id,id)) f.vk_code=vk; }
    int  GetKeybind(const char* id) {
        for (auto& f:m_features) if (!strcmp(f.info.id,id)) return f.vk_code.load(); return 0; }
    const char* GetName()    { return "ScheduleOne Trainer"; }
    const char* GetVersion() { return "1.0.0"; }
};

// ─────────────────────────────────────────────────────────────
//  Exported C API
// ─────────────────────────────────────────────────────────────
extern "C" {
    __declspec(dllexport) void*       trainer_create()                                         { return new ScheduleOneTrainer(); }
    __declspec(dllexport) void        trainer_destroy(void* h)                                 { delete static_cast<ScheduleOneTrainer*>(h); }
    __declspec(dllexport) int         trainer_initialize(void* h)                              { return static_cast<ScheduleOneTrainer*>(h)->Initialize()?1:0; }
    __declspec(dllexport) void        trainer_shutdown(void* h)                                { static_cast<ScheduleOneTrainer*>(h)->Shutdown(); }
    __declspec(dllexport) const char* trainer_get_name(void* h)                                { return static_cast<ScheduleOneTrainer*>(h)->GetName(); }
    __declspec(dllexport) const char* trainer_get_version(void* h)                             { return static_cast<ScheduleOneTrainer*>(h)->GetVersion(); }
    __declspec(dllexport) int         trainer_get_feature_count(void* h)                       { return static_cast<ScheduleOneTrainer*>(h)->GetFeatureCount(); }
    __declspec(dllexport) const TrainerFeatureInfo* trainer_get_feature_info(void* h, int idx) { return static_cast<ScheduleOneTrainer*>(h)->GetFeatureInfo(idx); }
    __declspec(dllexport) int         trainer_get_feature_enabled(void* h, const char* id)     { return static_cast<ScheduleOneTrainer*>(h)->GetFeatureEnabled(id); }
    __declspec(dllexport) void        trainer_set_feature_enabled(void* h, const char* id, int en) { static_cast<ScheduleOneTrainer*>(h)->SetFeatureEnabled(id,en); }
    __declspec(dllexport) void        trainer_activate_feature(void* h, const char* id)        { static_cast<ScheduleOneTrainer*>(h)->ActivateFeature(id); }
    __declspec(dllexport) void        trainer_set_keybind(void* h, const char* id, int vk)     { static_cast<ScheduleOneTrainer*>(h)->SetKeybind(id,vk); }
    __declspec(dllexport) int         trainer_get_keybind(void* h, const char* id)             { return static_cast<ScheduleOneTrainer*>(h)->GetKeybind(id); }
    __declspec(dllexport) const char* trainer_get_last_error()                                 { return ""; }
}