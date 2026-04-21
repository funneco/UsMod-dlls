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

static uintptr_t AobScan(HANDLE hProc, uintptr_t base, size_t sz, const uint8_t* pat, const uint8_t* mask, size_t len) {
    std::vector<uint8_t> buf(sz);
    SIZE_T r = 0;
    if (!ReadProcessMemory(hProc, (LPCVOID)base, buf.data(), sz, &r)) return 0;
    for (size_t i = 0; i + len <= r; ++i) {
        bool match = true;
        for (size_t j = 0; j < len; j++) {
            if (mask[j] == 0xFF && buf[i + j] != pat[j]) { match = false; break; }
        }
        if (match) return base + i;
    }
    return 0;
}

struct Feature {
    TrainerFeatureInfo info;
    std::atomic<bool> enabled{ false };
    std::atomic<int> vk_code{ 0 };
    Feature(const char* i, const char* n, const char* d, int tog, int vk)
        : info{ i,n,d,tog,vk }, vk_code(vk) {}
};

class FarmingGameTrainer {
public:
    HANDLE m_hProc = nullptr;
    std::atomic<bool> m_running{ false };
    std::thread m_thread;
    std::list<Feature> m_features;

    // AOB addresses and caves
    uintptr_t addrNoclip = 0;
    uint8_t origNoclip[7] = { 0 };
    uintptr_t caveNoclip = 0;

    uintptr_t addrStamina = 0;
    uint8_t origStamina[10] = { 0 };
    uintptr_t caveStamina = 0;
    uintptr_t staminaPtr = 0;
    std::atomic<bool> enableStamina{ false };

    uintptr_t addrHealth = 0;
    uint8_t origHealth[8] = { 0 };
    uintptr_t caveHealth = 0;

    uintptr_t addrSpeed = 0;
    uint8_t origSpeed[6] = { 0 };
    uintptr_t caveSpeed = 0;

    uintptr_t addrItems = 0;
    uint8_t origItems[6] = { 0 };
    uintptr_t caveItems = 0;

    uintptr_t addrWater = 0;
    uint8_t origWater[7] = { 0 };
    uintptr_t caveWater = 0;

    uintptr_t addrFreezeTime = 0;
    uint8_t origFreezeTime[1] = { 0 };

    uintptr_t addrFishBite = 0;
    uint8_t origFishBite[10] = { 0 };
    uintptr_t caveFishBite = 0;

    uintptr_t addrFishCatch = 0;
    uint8_t origFishCatch[8] = { 0 };
    uintptr_t caveFishCatch = 0;

    uintptr_t addrTrees = 0;
    uint8_t origTrees[5] = { 0 };
    uintptr_t caveTrees = 0;

    uintptr_t addrCrafting = 0;
    uint8_t origCrafting[6] = { 0 };
    uintptr_t caveCrafting = 0;

    uintptr_t addrCropGrowth = 0;
    uint8_t origCropGrowth[7] = { 0 };
    uintptr_t caveCropGrowth = 0;

    uintptr_t addrFriendship = 0;
    uint8_t origFriendship[5] = { 0 };
    uintptr_t caveFriendship = 0;

    uintptr_t addrPetFriendship = 0;
    uint8_t origPetFriendship[5] = { 0 };
    uintptr_t cavePetFriendship = 0;

    uintptr_t addrGold = 0;
    uint8_t origGold[7] = { 0 };
    uintptr_t caveGold = 0;
    std::atomic<int> goldValue{ 0 };

    uintptr_t addrStackables = 0;
    uint8_t origStackables[5] = { 0 };
    uintptr_t caveStackables = 0;

    uintptr_t addrAnimalStats = 0;
    uint8_t origAnimalStats[5] = { 0 };
    uintptr_t caveAnimalStats = 0;
    std::atomic<bool> enableFullness{ false };
    std::atomic<bool> enableHappiness{ false };
    std::atomic<bool> enableFriendliness{ false };

    FarmingGameTrainer() {
        m_features.emplace_back("noclip", "No Clip", "Walk through walls", 1, VK_F1);
        m_features.emplace_back("unlimited_stamina", "Unlimited Stamina", "Infinite stamina", 1, VK_F2);
        m_features.emplace_back("unlimited_health", "Unlimited Health", "Infinite health", 1, VK_F3);
        m_features.emplace_back("super_speed", "Super Speed (10x)", "Move 10x faster", 1, VK_F4);
        m_features.emplace_back("unlimited_items", "Unlimited Items", "Items don't decrease", 1, VK_F5);
        m_features.emplace_back("unlimited_water", "Unlimited Water", "Watering can never empties", 1, VK_F6);
        m_features.emplace_back("freeze_time", "Freeze Game Time", "Time stops", 1, VK_F7);
        m_features.emplace_back("instant_fish_bite", "Instant Fish Bite", "Fish bite immediately", 1, VK_F8);
        m_features.emplace_back("easy_fish_catch", "Easy Fish Catch", "Instant catch", 1, VK_F9);
        m_features.emplace_back("one_hit_trees", "One Hit Trees", "Trees fall in one hit", 1, VK_F10);
        m_features.emplace_back("free_crafting", "Free Crafting", "Craft without resources", 1, VK_F11);
        m_features.emplace_back("instant_crop_growth", "Instant Crop Growth", "Crops grow instantly", 1, VK_F12);
        m_features.emplace_back("max_friendship", "Max Friendship", "Max friendship when talking", 1, VK_NUMPAD1);
        m_features.emplace_back("max_pet_friendship", "Max Pet Friendship", "Max pet friendship", 1, VK_NUMPAD2);
        m_features.emplace_back("stackables_999", "Stackables to 999", "Stack items to 999", 1, VK_NUMPAD3);
        m_features.emplace_back("max_animal_fullness", "Max Animal Fullness", "Animals always full", 1, VK_NUMPAD4);
        m_features.emplace_back("max_animal_happiness", "Max Animal Happiness", "Animals always happy", 1, VK_NUMPAD5);
        m_features.emplace_back("max_animal_friendliness", "Max Animal Friendliness", "Animals max friendly", 1, VK_NUMPAD6);
    }

    bool Initialize() {
        DWORD pid = FindPid(L"Stardew Valley.exe"); // Adjust exe name as needed
        if (!pid) return false;
        m_hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
        if (!m_hProc) return false;

        uintptr_t baseAddr = GetModuleBase(pid, L"Stardew Valley.exe"); // Adjust as needed
        if (!baseAddr) return false;

        // Initialize all AOB scans and caves
        InitNoclip(baseAddr);
        InitStamina(baseAddr);
        InitHealth(baseAddr);
        InitSpeed(baseAddr);
        InitItems(baseAddr);
        InitWater(baseAddr);
        InitFreezeTime(baseAddr);
        InitFishBite(baseAddr);
        InitFishCatch(baseAddr);
        InitTrees(baseAddr);
        InitCrafting(baseAddr);
        InitCropGrowth(baseAddr);
        InitFriendship(baseAddr);
        InitPetFriendship(baseAddr);
        InitGold(baseAddr);
        InitStackables(baseAddr);
        InitAnimalStats(baseAddr);

        m_running = true;
        m_thread = std::thread(&FarmingGameTrainer::Loop, this);
        return true;
    }

    void InitNoclip(uintptr_t base) {
        uint8_t pat[] = { 0x0F, 0xB6, 0x8E, 0x4E, 0x07, 0x00, 0x00 };
        uint8_t mask[] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
        addrNoclip = AobScan(m_hProc, base, 0x10000000, pat, mask, 7);
        if (addrNoclip) {
            ReadProcessMemory(m_hProc, (LPCVOID)addrNoclip, origNoclip, 7, nullptr);
            caveNoclip = (uintptr_t)VirtualAllocEx(m_hProc, nullptr, 1024, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            
            // mov ecx, 1; jmp return
            uint8_t code[] = {
                0xB9, 0x01, 0x00, 0x00, 0x00,                   // mov ecx, 1
                0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,             // jmp [return]
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  // return address
            };
            uintptr_t retAddr = addrNoclip + 7;
            memcpy(&code[11], &retAddr, 8);
            WriteProcessMemory(m_hProc, (LPVOID)caveNoclip, code, sizeof(code), nullptr);
        }
    }

    void InitStamina(uintptr_t base) {
        uint8_t pat[] = { 0x48, 0x8B, 0x09, 0x48, 0x8B, 0x89, 0xD0, 0x04, 0x00, 0x00, 0xC5, 0x7A, 0x10, 0x49, 0x4C };
        uint8_t mask[] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
        addrStamina = AobScan(m_hProc, base, 0x10000000, pat, mask, 15);
        if (addrStamina) {
            ReadProcessMemory(m_hProc, (LPCVOID)addrStamina, origStamina, 10, nullptr);
            caveStamina = (uintptr_t)VirtualAllocEx(m_hProc, nullptr, 2048, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            staminaPtr = caveStamina + 1024;
            
            // Complex stamina logic from CE table
            uint8_t code[] = {
                0x48, 0x8B, 0x09,                               // mov rcx,[rcx]
                0x48, 0x89, 0x0D, 0x00, 0x00, 0x00, 0x00,       // mov [staminaPtr],rcx
                0x48, 0x8B, 0x89, 0xD0, 0x04, 0x00, 0x00,       // mov rcx,[rcx+04D0]
                0x48, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00,       // mov rax,[staminaPtr]
                0x83, 0x78, 0x08, 0x00,                         // cmp dword ptr [rax+8],0
                0x74, 0x0D,                                     // je skip
                0xD9, 0x41, 0x54,                               // fld dword ptr [rcx+54]
                0xD9, 0x59, 0x4C,                               // fstp dword ptr [rcx+4C]
                // skip:
                0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,             // jmp [return]
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  // return address
            };
            
            int32_t ptrOff = (int32_t)(staminaPtr - (caveStamina + 10));
            memcpy(&code[6], &ptrOff, 4);
            
            int32_t ptrOff2 = (int32_t)(staminaPtr - (caveStamina + 24));
            memcpy(&code[20], &ptrOff2, 4);
            
            uintptr_t retAddr = addrStamina + 10;
            memcpy(&code[39], &retAddr, 8);
            
            WriteProcessMemory(m_hProc, (LPVOID)caveStamina, code, sizeof(code), nullptr);
        }
    }

    void InitHealth(uintptr_t base) {
        uint8_t pat[] = { 0xC5, 0xFA, 0x2A, 0x81, 0xEC, 0x06, 0x00, 0x00, 0xC5, 0xF0, 0x57, 0xC9, 0xC5, 0xF2, 0x2A, 0xCA };
        uint8_t mask[] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
        addrHealth = AobScan(m_hProc, base, 0x10000000, pat, mask, 16);
        if (addrHealth) {
            ReadProcessMemory(m_hProc, (LPCVOID)addrHealth, origHealth, 8, nullptr);
            caveHealth = (uintptr_t)VirtualAllocEx(m_hProc, nullptr, 1024, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            
            // Set health to max health
            uint8_t code[] = {
                0xDB, 0x81, 0xF0, 0x06, 0x00, 0x00,             // fild dword ptr [rcx+6F0]
                0xDB, 0x99, 0xEC, 0x06, 0x00, 0x00,             // fistp dword ptr [rcx+6EC]
                0xC5, 0xFA, 0x2A, 0x81, 0xEC, 0x06, 0x00, 0x00, // original instruction
                0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,             // jmp [return]
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  // return address
            };
            
            uintptr_t retAddr = addrHealth + 8;
            memcpy(&code[26], &retAddr, 8);
            WriteProcessMemory(m_hProc, (LPVOID)caveHealth, code, sizeof(code), nullptr);
        }
    }

    void InitSpeed(uintptr_t base) {
        uint8_t pat[] = { 0x57, 0x56, 0x48, 0x83, 0xEC, 0x68, 0xC5, 0xF8, 0x77, 0xC5, 0xF8, 0x29, 0x74, 0x24, 0x50 };
        uint8_t mask[] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
        addrSpeed = AobScan(m_hProc, base, 0x10000000, pat, mask, 15);
        if (addrSpeed) {
            ReadProcessMemory(m_hProc, (LPCVOID)addrSpeed, origSpeed, 6, nullptr);
            caveSpeed = (uintptr_t)VirtualAllocEx(m_hProc, nullptr, 1024, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            
            float speed = 10.0f;
            uintptr_t speedData = caveSpeed + 512;
            
            uint8_t code[] = {
                0xF3, 0x0F, 0x10, 0x05, 0x00, 0x00, 0x00, 0x00, // movss xmm0,[speedData]
                0xC3                                            // ret
            };
            
            int32_t off = (int32_t)(speedData - (caveSpeed + 8));
            memcpy(&code[4], &off, 4);
            
            WriteProcessMemory(m_hProc, (LPVOID)caveSpeed, code, sizeof(code), nullptr);
            WriteProcessMemory(m_hProc, (LPVOID)speedData, &speed, 4, nullptr);
        }
    }

    void InitItems(uintptr_t base) {
        uint8_t pat[] = { 0x8D, 0x68, 0xFF, 0x48, 0x8B, 0xCF, 0x8B, 0xD5, 0xFF, 0x53, 0x10 };
        uint8_t mask[] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
        addrItems = AobScan(m_hProc, base, 0x10000000, pat, mask, 11);
        if (addrItems) {
            ReadProcessMemory(m_hProc, (LPCVOID)addrItems, origItems, 6, nullptr);
            caveItems = (uintptr_t)VirtualAllocEx(m_hProc, nullptr, 1024, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            
            // lea ebp,[rax] instead of lea ebp,[rax-1]
            uint8_t code[] = {
                0x8D, 0x28,                                     // lea ebp,[rax]
                0x48, 0x8B, 0xCF,                               // mov rcx,rdi
                0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,             // jmp [return]
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  // return address
            };
            
            uintptr_t retAddr = addrItems + 6;
            memcpy(&code[11], &retAddr, 8);
            WriteProcessMemory(m_hProc, (LPVOID)caveItems, code, sizeof(code), nullptr);
        }
    }

    void InitWater(uintptr_t base) {
        uint8_t pat[] = { 0x4C, 0x8B, 0x86, 0x08, 0x01, 0x00, 0x00, 0x45, 0x8B, 0x40, 0x4C };
        uint8_t mask[] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
        addrWater = AobScan(m_hProc, base, 0x10000000, pat, mask, 11);
        if (addrWater) {
            ReadProcessMemory(m_hProc, (LPCVOID)addrWater, origWater, 7, nullptr);
            caveWater = (uintptr_t)VirtualAllocEx(m_hProc, nullptr, 1024, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            
            uint8_t code[] = {
                0x4C, 0x8B, 0x86, 0x08, 0x01, 0x00, 0x00,       // mov r8,[rsi+108]
                0x4D, 0x85, 0xC0,                               // test r8,r8
                0x74, 0x08,                                     // je skip
                0x41, 0xC7, 0x40, 0x4C, 0x20, 0x00, 0x00, 0x00, // mov [r8+4C],32
                // skip:
                0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,             // jmp [return]
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  // return address
            };
            
            uintptr_t retAddr = addrWater + 7;
            memcpy(&code[25], &retAddr, 8);
            WriteProcessMemory(m_hProc, (LPVOID)caveWater, code, sizeof(code), nullptr);
        }
    }

    void InitFreezeTime(uintptr_t base) {
        uint8_t pat[] = { 0x83, 0x05, 0x00, 0x00, 0x00, 0x00, 0x0A, 0x8B, 0x0D };
        uint8_t mask[] = { 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF };
        addrFreezeTime = AobScan(m_hProc, base, 0x10000000, pat, mask, 9);
        if (addrFreezeTime) {
            ReadProcessMemory(m_hProc, (LPCVOID)(addrFreezeTime + 6), origFreezeTime, 1, nullptr);
        }
    }

    void InitFishBite(uintptr_t base) {
        uint8_t pat[] = { 0xC5, 0xF8, 0x28, 0xC6, 0xC5, 0xF8, 0x28, 0x74, 0x24, 0x20 };
        uint8_t mask[] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
        addrFishBite = AobScan(m_hProc, base, 0x10000000, pat, mask, 10);
        if (addrFishBite) {
            ReadProcessMemory(m_hProc, (LPCVOID)addrFishBite, origFishBite, 10, nullptr);
            caveFishBite = (uintptr_t)VirtualAllocEx(m_hProc, nullptr, 1024, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            
            uint8_t code[] = {
                0x0F, 0x57, 0xF6,                               // xorps xmm6,xmm6
                0xC5, 0xF8, 0x28, 0xC6,                         // vmovaps xmm0,xmm6
                0xC5, 0xF8, 0x28, 0x74, 0x24, 0x20,             // vmovaps xmm6,[rsp+20]
                0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,             // jmp [return]
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  // return address
            };
            
            uintptr_t retAddr = addrFishBite + 10;
            memcpy(&code[19], &retAddr, 8);
            WriteProcessMemory(m_hProc, (LPVOID)caveFishBite, code, sizeof(code), nullptr);
        }
    }

    void InitFishCatch(uintptr_t base) {
        uint8_t pat[] = { 0xF3, 0x0F, 0x11, 0x81, 0xE8, 0x00, 0x00, 0x00, 0xF3, 0x0F, 0x10, 0x89 };
        uint8_t mask[] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
        addrFishCatch = AobScan(m_hProc, base, 0x10000000, pat, mask, 12);
        if (addrFishCatch) {
            ReadProcessMemory(m_hProc, (LPCVOID)addrFishCatch, origFishCatch, 8, nullptr);
            caveFishCatch = (uintptr_t)VirtualAllocEx(m_hProc, nullptr, 1024, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            
            float one = 1.0f;
            uintptr_t oneData = caveFishCatch + 512;
            
            uint8_t code[] = {
                0xF3, 0x0F, 0x10, 0x05, 0x00, 0x00, 0x00, 0x00, // movss xmm0,[oneData]
                0xF3, 0x0F, 0x11, 0x81, 0xE8, 0x00, 0x00, 0x00, // movss [rcx+E8],xmm0
                0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,             // jmp [return]
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  // return address
            };
            
            int32_t off = (int32_t)(oneData - (caveFishCatch + 8));
            memcpy(&code[4], &off, 4);
            
            uintptr_t retAddr = addrFishCatch + 8;
            memcpy(&code[22], &retAddr, 8);
            
            WriteProcessMemory(m_hProc, (LPVOID)caveFishCatch, code, sizeof(code), nullptr);
            WriteProcessMemory(m_hProc, (LPVOID)oneData, &one, 4, nullptr);
        }
    }

    void InitTrees(uintptr_t base) {
        uint8_t pat[] = { 0xC5, 0xFA, 0x10, 0x49, 0x4C, 0xC4, 0xC1, 0x72, 0x5C, 0xC8 };
        uint8_t mask[] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
        addrTrees = AobScan(m_hProc, base, 0x10000000, pat, mask, 10);
        if (addrTrees) {
            ReadProcessMemory(m_hProc, (LPCVOID)addrTrees, origTrees, 5, nullptr);
            caveTrees = (uintptr_t)VirtualAllocEx(m_hProc, nullptr, 1024, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            
            uint8_t code[] = {
                0x0F, 0x57, 0xC9,                               // xorps xmm1,xmm1
                0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,             // jmp [return]
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  // return address
            };
            
            uintptr_t retAddr = addrTrees + 5;
            memcpy(&code[7], &retAddr, 8);
            WriteProcessMemory(m_hProc, (LPVOID)caveTrees, code, sizeof(code), nullptr);
        }
    }

    void InitCrafting(uintptr_t base) {
        uint8_t pat[] = { 0x8B, 0x50, 0x38, 0x2B, 0x50, 0x40, 0x8D, 0x04, 0xD2 };
        uint8_t mask[] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
        addrCrafting = AobScan(m_hProc, base, 0x10000000, pat, mask, 9);
        if (addrCrafting) {
            ReadProcessMemory(m_hProc, (LPCVOID)addrCrafting, origCrafting, 6, nullptr);
            caveCrafting = (uintptr_t)VirtualAllocEx(m_hProc, nullptr, 1024, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            
            uint8_t code[] = {
                0xC7, 0x40, 0x38, 0x00, 0x00, 0x00, 0x00,       // mov [rax+38],0
                0x8B, 0x50, 0x38,                               // mov edx,[rax+38]
                0x2B, 0x50, 0x40,                               // sub edx,[rax+40]
                0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,             // jmp [return]
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  // return address
            };
            
            uintptr_t retAddr = addrCrafting + 6;
            memcpy(&code[19], &retAddr, 8);
            WriteProcessMemory(m_hProc, (LPVOID)caveCrafting, code, sizeof(code), nullptr);
        }
    }

    void InitCropGrowth(uintptr_t base) {
        uint8_t pat[] = { 0x48, 0x8B, 0x4E, 0x28, 0x8B, 0x49, 0x4C, 0x48 };
        uint8_t mask[] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
        addrCropGrowth = AobScan(m_hProc, base, 0x10000000, pat, mask, 8);
        if (addrCropGrowth) {
            ReadProcessMemory(m_hProc, (LPCVOID)addrCropGrowth, origCropGrowth, 7, nullptr);
            caveCropGrowth = (uintptr_t)VirtualAllocEx(m_hProc, nullptr, 1024, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            
            uint8_t code[] = {
                0x48, 0x8B, 0x4E, 0x28,                         // mov rcx,[rsi+28]
                0x48, 0x8B, 0x46, 0x10,                         // mov rax,[rsi+10]
                0x48, 0x8B, 0x40, 0x38,                         // mov rax,[rax+38]
                0x8B, 0x40, 0x4C,                               // mov eax,[rax+4C]
                0xFF, 0xC8,                                     // dec eax
                0x39, 0x41, 0x4C,                               // cmp [rcx+4C],eax
                0x7F, 0x03,                                     // jg skip
                0x89, 0x41, 0x4C,                               // mov [rcx+4C],eax
                // skip:
                0x8B, 0x49, 0x4C,                               // mov ecx,[rcx+4C]
                0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,             // jmp [return]
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  // return address
            };
            
            uintptr_t retAddr = addrCropGrowth + 7;
            memcpy(&code[35], &retAddr, 8);
            WriteProcessMemory(m_hProc, (LPVOID)caveCropGrowth, code, sizeof(code), nullptr);
        }
    }

    void InitFriendship(uintptr_t base) {
        uint8_t pat[] = { 0x41, 0x56, 0x57, 0x56, 0x55, 0x53, 0x48 };
        uint8_t mask[] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
        addrFriendship = AobScan(m_hProc, base, 0x10000000, pat, mask, 7);
        if (addrFriendship) {
            ReadProcessMemory(m_hProc, (LPCVOID)addrFriendship, origFriendship, 5, nullptr);
            caveFriendship = (uintptr_t)VirtualAllocEx(m_hProc, nullptr, 1024, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            
            uint8_t code[] = {
                0xBA, 0x7F, 0x96, 0x98, 0x00,                   // mov edx,9999999
                0x41, 0x56,                                     // push r14
                0x57,                                           // push rdi
                0x56,                                           // push rsi
                0x55,                                           // push rbp
                0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,             // jmp [return]
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  // return address
            };
            
            uintptr_t retAddr = addrFriendship + 5;
            memcpy(&code[15], &retAddr, 8);
            WriteProcessMemory(m_hProc, (LPVOID)caveFriendship, code, sizeof(code), nullptr);
        }
    }

    void InitPetFriendship(uintptr_t base) {
        uint8_t pat[] = { 0x55, 0x41, 0x57, 0x41, 0x56 };
        uint8_t mask[] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
        addrPetFriendship = AobScan(m_hProc, base, 0x10000000, pat, mask, 5);
        if (addrPetFriendship) {
            ReadProcessMemory(m_hProc, (LPCVOID)addrPetFriendship, origPetFriendship, 5, nullptr);
            cavePetFriendship = (uintptr_t)VirtualAllocEx(m_hProc, nullptr, 1024, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            
            uint8_t code[] = {
                0x48, 0x8B, 0x81, 0x50, 0x04, 0x00, 0x00,       // mov rax,[rcx+450]
                0x48, 0x85, 0xC0,                               // test rax,rax
                0x74, 0x0B,                                     // je skip
                0xC7, 0x40, 0x4C, 0xE8, 0x03, 0x00, 0x00,       // mov [rax+4C],3E8
                // skip:
                0x55,                                           // push rbp
                0x41, 0x57,                                     // push r15
                0x41, 0x56,                                     // push r14
                0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,             // jmp [return]
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  // return address
            };
            
            uintptr_t retAddr = addrPetFriendship + 5;
            memcpy(&code[29], &retAddr, 8);
            WriteProcessMemory(m_hProc, (LPVOID)cavePetFriendship, code, sizeof(code), nullptr);
        }
    }

    void InitGold(uintptr_t base) {
        uint8_t pat[] = { 0xFF, 0x8B, 0x40, 0x4C, 0x48, 0x83, 0xC4, 0x28 };
        uint8_t mask[] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
        addrGold = AobScan(m_hProc, base, 0x10000000, pat, mask, 8);
        if (addrGold) {
            ReadProcessMemory(m_hProc, (LPCVOID)(addrGold + 1), origGold, 7, nullptr);
            caveGold = (uintptr_t)VirtualAllocEx(m_hProc, nullptr, 1024, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            uintptr_t goldData = caveGold + 512;
            
            uint8_t code[] = {
                0x53,                                           // push rbx
                0x8B, 0x1D, 0x00, 0x00, 0x00, 0x00,             // mov ebx,[goldData]
                0x85, 0xDB,                                     // test ebx,ebx
                0x75, 0x04,                                     // jne skipinit
                0x8B, 0x58, 0x4C,                               // mov ebx,[rax+4C]
                0x89, 0x1D, 0x00, 0x00, 0x00, 0x00,             // mov [goldData],ebx
                // skipinit:
                0x8B, 0x1D, 0x00, 0x00, 0x00, 0x00,             // mov ebx,[goldData]
                0x89, 0x58, 0x4C,                               // mov [rax+4C],ebx
                0x5B,                                           // pop rbx
                0x8B, 0x40, 0x4C,                               // mov eax,[rax+4C]
                0x48, 0x83, 0xC4, 0x28,                         // add rsp,28
                0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,             // jmp [return]
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  // return address
            };
            
            int32_t off1 = (int32_t)(goldData - (caveGold + 7));
            memcpy(&code[3], &off1, 4);
            
            int32_t off2 = (int32_t)(goldData - (caveGold + 18));
            memcpy(&code[14], &off2, 4);
            
            int32_t off3 = (int32_t)(goldData - (caveGold + 25));
            memcpy(&code[21], &off3, 4);
            
            uintptr_t retAddr = addrGold + 8;
            memcpy(&code[41], &retAddr, 8);
            
            WriteProcessMemory(m_hProc, (LPVOID)caveGold, code, sizeof(code), nullptr);
            
            int zero = 0;
            WriteProcessMemory(m_hProc, (LPVOID)goldData, &zero, 4, nullptr);
        }
    }

    void InitStackables(uintptr_t base) {
        uint8_t pat[] = { 0x8B, 0x40, 0x4C, 0x85, 0xC0, 0x7E };
        uint8_t mask[] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
        addrStackables = AobScan(m_hProc, base, 0x10000000, pat, mask, 6);
        if (addrStackables) {
            ReadProcessMemory(m_hProc, (LPCVOID)addrStackables, origStackables, 5, nullptr);
            caveStackables = (uintptr_t)VirtualAllocEx(m_hProc, nullptr, 1024, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            
            uint8_t code[] = {
                0x53,                                           // push rbx
                0xBB, 0xE7, 0x03, 0x00, 0x00,                   // mov ebx,999
                0x89, 0x58, 0x4C,                               // mov [rax+4C],ebx
                0x5B,                                           // pop rbx
                0x8B, 0x40, 0x4C,                               // mov eax,[rax+4C]
                0x85, 0xC0,                                     // test eax,eax
                0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,             // jmp [return]
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  // return address
            };
            
            uintptr_t retAddr = addrStackables + 5;
            memcpy(&code[19], &retAddr, 8);
            WriteProcessMemory(m_hProc, (LPVOID)caveStackables, code, sizeof(code), nullptr);
        }
    }

    void InitAnimalStats(uintptr_t base) {
        uint8_t pat[] = { 0x55, 0x41, 0x57, 0x41, 0x56, 0x41, 0x55, 0x41, 0x54, 0x57 };
        uint8_t mask[] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
        addrAnimalStats = AobScan(m_hProc, base, 0x10000000, pat, mask, 10);
        if (addrAnimalStats) {
            ReadProcessMemory(m_hProc, (LPCVOID)addrAnimalStats, origAnimalStats, 5, nullptr);
            caveAnimalStats = (uintptr_t)VirtualAllocEx(m_hProc, nullptr, 2048, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            
            uintptr_t flagData = caveAnimalStats + 1024;
            
            uint8_t code[] = {
                // Check fullness flag
                0x83, 0x3D, 0x00, 0x00, 0x00, 0x00, 0x00,       // cmp dword ptr [flagData],0
                0x74, 0x14,                                     // je skip1
                0x48, 0x8B, 0x81, 0x90, 0x01, 0x00, 0x00,       // mov rax,[rcx+190]
                0x48, 0x85, 0xC0,                               // test rax,rax
                0x74, 0x0A,                                     // je skip1
                0xC7, 0x40, 0x4C, 0x0F, 0x27, 0x00, 0x00,       // mov [rax+4C],9999
                // skip1:
                // Check happiness flag
                0x83, 0x3D, 0x00, 0x00, 0x00, 0x00, 0x00,       // cmp dword ptr [flagData+4],0
                0x74, 0x14,                                     // je skip2
                0x48, 0x8B, 0x81, 0xD0, 0x01, 0x00, 0x00,       // mov rax,[rcx+1D0]
                0x48, 0x85, 0xC0,                               // test rax,rax
                0x74, 0x0A,                                     // je skip2
                0xC7, 0x40, 0x4C, 0x0F, 0x27, 0x00, 0x00,       // mov [rax+4C],9999
                // skip2:
                // Check friendliness flag
                0x83, 0x3D, 0x00, 0x00, 0x00, 0x00, 0x00,       // cmp dword ptr [flagData+8],0
                0x74, 0x14,                                     // je skip3
                0x48, 0x8B, 0x81, 0xC8, 0x01, 0x00, 0x00,       // mov rax,[rcx+1C8]
                0x48, 0x85, 0xC0,                               // test rax,rax
                0x74, 0x0A,                                     // je skip3
                0xC7, 0x40, 0x4C, 0x0F, 0x27, 0x00, 0x00,       // mov [rax+4C],9999
                // skip3:
                0x55,                                           // push rbp
                0x41, 0x57,                                     // push r15
                0x41, 0x56,                                     // push r14
                0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,             // jmp [return]
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  // return address
            };
            
            int32_t off1 = (int32_t)(flagData - (caveAnimalStats + 6));
            memcpy(&code[2], &off1, 4);
            
            int32_t off2 = (int32_t)((flagData + 4) - (caveAnimalStats + 29));
            memcpy(&code[25], &off2, 4);
            
            int32_t off3 = (int32_t)((flagData + 8) - (caveAnimalStats + 52));
            memcpy(&code[48], &off3, 4);
            
            uintptr_t retAddr = addrAnimalStats + 5;
            memcpy(&code[63], &retAddr, 8);
            
            WriteProcessMemory(m_hProc, (LPVOID)caveAnimalStats, code, sizeof(code), nullptr);
            
            int zero = 0;
            WriteProcessMemory(m_hProc, (LPVOID)flagData, &zero, 4, nullptr);
            WriteProcessMemory(m_hProc, (LPVOID)(flagData + 4), &zero, 4, nullptr);
            WriteProcessMemory(m_hProc, (LPVOID)(flagData + 8), &zero, 4, nullptr);
        }
    }

    void Loop() {
        std::vector<bool> prevStates(m_features.size(), false);
        int idx = 0;

        while (m_running) {
            // Handle hotkeys
            for (auto& f : m_features) {
                int vk = f.vk_code.load();
                if (vk && (GetAsyncKeyState(vk) & 1)) f.enabled = !f.enabled;
            }

            auto it = m_features.begin();
            idx = 0;

            // Feature 0: No Clip
            if (it->enabled != prevStates[idx]) {
                if (it->enabled && addrNoclip) {
                    uint8_t hook[14] = { 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00 };
                    memcpy(&hook[6], &caveNoclip, 8);
                    MemWrite(m_hProc, addrNoclip, hook, 14);
                } else if (addrNoclip) {
                    MemWrite(m_hProc, addrNoclip, origNoclip, 7);
                }
                prevStates[idx] = it->enabled;
            }
            it++; idx++;

            // Feature 1: Unlimited Stamina
            if (it->enabled != prevStates[idx]) {
                if (it->enabled && addrStamina) {
                    uint8_t hook[14] = { 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00 };
                    memcpy(&hook[6], &caveStamina, 8);
                    MemWrite(m_hProc, addrStamina, hook, 14);
                    
                    // Set enable flag
                    int one = 1;
                    WriteProcessMemory(m_hProc, (LPVOID)(staminaPtr + 8), &one, 4, nullptr);
                } else if (addrStamina) {
                    MemWrite(m_hProc, addrStamina, origStamina, 10);
                    int zero = 0;
                    WriteProcessMemory(m_hProc, (LPVOID)(staminaPtr + 8), &zero, 4, nullptr);
                }
                prevStates[idx] = it->enabled;
            }
            it++; idx++;

            // Feature 2: Unlimited Health
            if (it->enabled != prevStates[idx]) {
                if (it->enabled && addrHealth) {
                    uint8_t hook[14] = { 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00 };
                    memcpy(&hook[6], &caveHealth, 8);
                    MemWrite(m_hProc, addrHealth, hook, 14);
                } else if (addrHealth) {
                    MemWrite(m_hProc, addrHealth, origHealth, 8);
                }
                prevStates[idx] = it->enabled;
            }
            it++; idx++;

            // Feature 3: Super Speed
            if (it->enabled != prevStates[idx]) {
                if (it->enabled && addrSpeed) {
                    uint8_t hook[14] = { 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00 };
                    memcpy(&hook[6], &caveSpeed, 8);
                    MemWrite(m_hProc, addrSpeed, hook, 14);
                } else if (addrSpeed) {
                    MemWrite(m_hProc, addrSpeed, origSpeed, 6);
                }
                prevStates[idx] = it->enabled;
            }
            it++; idx++;

            // Feature 4: Unlimited Items
            if (it->enabled != prevStates[idx]) {
                if (it->enabled && addrItems) {
                    uint8_t hook[14] = { 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00 };
                    memcpy(&hook[6], &caveItems, 8);
                    MemWrite(m_hProc, addrItems, hook, 14);
                } else if (addrItems) {
                    MemWrite(m_hProc, addrItems, origItems, 6);
                }
                prevStates[idx] = it->enabled;
            }
            it++; idx++;

            // Feature 5: Unlimited Water
            if (it->enabled != prevStates[idx]) {
                if (it->enabled && addrWater) {
                    uint8_t hook[14] = { 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00 };
                    memcpy(&hook[6], &caveWater, 8);
                    MemWrite(m_hProc, addrWater, hook, 14);
                } else if (addrWater) {
                    MemWrite(m_hProc, addrWater, origWater, 7);
                }
                prevStates[idx] = it->enabled;
            }
            it++; idx++;

            // Feature 6: Freeze Time
            if (it->enabled != prevStates[idx]) {
                if (it->enabled && addrFreezeTime) {
                    uint8_t zero = 0x00;
                    MemWrite(m_hProc, addrFreezeTime + 6, &zero, 1);
                } else if (addrFreezeTime) {
                    MemWrite(m_hProc, addrFreezeTime + 6, origFreezeTime, 1);
                }
                prevStates[idx] = it->enabled;
            }
            it++; idx++;

            // Feature 7: Instant Fish Bite
            if (it->enabled != prevStates[idx]) {
                if (it->enabled && addrFishBite) {
                    uint8_t hook[14] = { 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00 };
                    memcpy(&hook[6], &caveFishBite, 8);
                    MemWrite(m_hProc, addrFishBite, hook, 14);
                } else if (addrFishBite) {
                    MemWrite(m_hProc, addrFishBite, origFishBite, 10);
                }
                prevStates[idx] = it->enabled;
            }
            it++; idx++;

            // Feature 8: Easy Fish Catch
            if (it->enabled != prevStates[idx]) {
                if (it->enabled && addrFishCatch) {
                    uint8_t hook[14] = { 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00 };
                    memcpy(&hook[6], &caveFishCatch, 8);
                    MemWrite(m_hProc, addrFishCatch, hook, 14);
                } else if (addrFishCatch) {
                    MemWrite(m_hProc, addrFishCatch, origFishCatch, 8);
                }
                prevStates[idx] = it->enabled;
            }
            it++; idx++;

            // Feature 9: One Hit Trees
            if (it->enabled != prevStates[idx]) {
                if (it->enabled && addrTrees) {
                    uint8_t hook[14] = { 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00 };
                    memcpy(&hook[6], &caveTrees, 8);
                    MemWrite(m_hProc, addrTrees, hook, 14);
                } else if (addrTrees) {
                    MemWrite(m_hProc, addrTrees, origTrees, 5);
                }
                prevStates[idx] = it->enabled;
            }
            it++; idx++;

            // Feature 10: Free Crafting
            if (it->enabled != prevStates[idx]) {
                if (it->enabled && addrCrafting) {
                    uint8_t hook[14] = { 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00 };
                    memcpy(&hook[6], &caveCrafting, 8);
                    MemWrite(m_hProc, addrCrafting, hook, 14);
                } else if (addrCrafting) {
                    MemWrite(m_hProc, addrCrafting, origCrafting, 6);
                }
                prevStates[idx] = it->enabled;
            }
            it++; idx++;

            // Feature 11: Instant Crop Growth
            if (it->enabled != prevStates[idx]) {
                if (it->enabled && addrCropGrowth) {
                    uint8_t hook[14] = { 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00 };
                    memcpy(&hook[6], &caveCropGrowth, 8);
                    MemWrite(m_hProc, addrCropGrowth, hook, 14);
                } else if (addrCropGrowth) {
                    MemWrite(m_hProc, addrCropGrowth, origCropGrowth, 7);
                }
                prevStates[idx] = it->enabled;
            }
            it++; idx++;

            // Feature 12: Max Friendship
            if (it->enabled != prevStates[idx]) {
                if (it->enabled && addrFriendship) {
                    uint8_t hook[14] = { 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00 };
                    memcpy(&hook[6], &caveFriendship, 8);
                    MemWrite(m_hProc, addrFriendship, hook, 14);
                } else if (addrFriendship) {
                    MemWrite(m_hProc, addrFriendship, origFriendship, 5);
                }
                prevStates[idx] = it->enabled;
            }
            it++; idx++;

            // Feature 13: Max Pet Friendship
            if (it->enabled != prevStates[idx]) {
                if (it->enabled && addrPetFriendship) {
                    uint8_t hook[14] = { 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00 };
                    memcpy(&hook[6], &cavePetFriendship, 8);
                    MemWrite(m_hProc, addrPetFriendship, hook, 14);
                } else if (addrPetFriendship) {
                    MemWrite(m_hProc, addrPetFriendship, origPetFriendship, 5);
                }
                prevStates[idx] = it->enabled;
            }
            it++; idx++;

            // Feature 14: Stackables to 999
            if (it->enabled != prevStates[idx]) {
                if (it->enabled && addrStackables) {
                    uint8_t hook[14] = { 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00 };
                    memcpy(&hook[6], &caveStackables, 8);
                    MemWrite(m_hProc, addrStackables, hook, 14);
                } else if (addrStackables) {
                    MemWrite(m_hProc, addrStackables, origStackables, 5);
                }
                prevStates[idx] = it->enabled;
            }
            it++; idx++;

            // Feature 15: Max Animal Fullness
            if (it->enabled != prevStates[idx]) {
                enableFullness = it->enabled;
                if (addrAnimalStats) {
                    if (!prevStates[idx] && !prevStates[idx+1] && !prevStates[idx+2]) {
                        // First animal stat enabled
                        uint8_t hook[14] = { 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00 };
                        memcpy(&hook[6], &caveAnimalStats, 8);
                        MemWrite(m_hProc, addrAnimalStats, hook, 14);
                    }
                    int val = it->enabled ? 1 : 0;
                    uintptr_t flagAddr = caveAnimalStats + 1024;
                    WriteProcessMemory(m_hProc, (LPVOID)flagAddr, &val, 4, nullptr);
                }
                prevStates[idx] = it->enabled;
            }
            it++; idx++;

            // Feature 16: Max Animal Happiness
            if (it->enabled != prevStates[idx]) {
                enableHappiness = it->enabled;
                if (addrAnimalStats) {
                    if (!prevStates[idx-1] && !prevStates[idx] && !prevStates[idx+1]) {
                        uint8_t hook[14] = { 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00 };
                        memcpy(&hook[6], &caveAnimalStats, 8);
                        MemWrite(m_hProc, addrAnimalStats, hook, 14);
                    }
                    int val = it->enabled ? 1 : 0;
                    uintptr_t flagAddr = caveAnimalStats + 1024 + 4;
                    WriteProcessMemory(m_hProc, (LPVOID)flagAddr, &val, 4, nullptr);
                }
                prevStates[idx] = it->enabled;
            }
            it++; idx++;

            // Feature 17: Max Animal Friendliness
            if (it->enabled != prevStates[idx]) {
                enableFriendliness = it->enabled;
                if (addrAnimalStats) {
                    if (!prevStates[idx-2] && !prevStates[idx-1] && !prevStates[idx]) {
                        uint8_t hook[14] = { 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00 };
                        memcpy(&hook[6], &caveAnimalStats, 8);
                        MemWrite(m_hProc, addrAnimalStats, hook, 14);
                    }
                    int val = it->enabled ? 1 : 0;
                    uintptr_t flagAddr = caveAnimalStats + 1024 + 8;
                    WriteProcessMemory(m_hProc, (LPVOID)flagAddr, &val, 4, nullptr);
                    
                    // Disable hook if all are off
                    if (!prevStates[idx-2] && !prevStates[idx-1] && !it->enabled) {
                        MemWrite(m_hProc, addrAnimalStats, origAnimalStats, 5);
                    }
                }
                prevStates[idx] = it->enabled;
            }

            Sleep(10);
        }
    }

    void Shutdown() {
        m_running = false;
        if (m_thread.joinable()) m_thread.join();
        
        // Restore all original bytes
        if (addrNoclip) MemWrite(m_hProc, addrNoclip, origNoclip, 7);
        if (addrStamina) MemWrite(m_hProc, addrStamina, origStamina, 10);
        if (addrHealth) MemWrite(m_hProc, addrHealth, origHealth, 8);
        if (addrSpeed) MemWrite(m_hProc, addrSpeed, origSpeed, 6);
        if (addrItems) MemWrite(m_hProc, addrItems, origItems, 6);
        if (addrWater) MemWrite(m_hProc, addrWater, origWater, 7);
        if (addrFreezeTime) MemWrite(m_hProc, addrFreezeTime + 6, origFreezeTime, 1);
        if (addrFishBite) MemWrite(m_hProc, addrFishBite, origFishBite, 10);
        if (addrFishCatch) MemWrite(m_hProc, addrFishCatch, origFishCatch, 8);
        if (addrTrees) MemWrite(m_hProc, addrTrees, origTrees, 5);
        if (addrCrafting) MemWrite(m_hProc, addrCrafting, origCrafting, 6);
        if (addrCropGrowth) MemWrite(m_hProc, addrCropGrowth, origCropGrowth, 7);
        if (addrFriendship) MemWrite(m_hProc, addrFriendship, origFriendship, 5);
        if (addrPetFriendship) MemWrite(m_hProc, addrPetFriendship, origPetFriendship, 5);
        if (addrGold) MemWrite(m_hProc, addrGold + 1, origGold, 7);
        if (addrStackables) MemWrite(m_hProc, addrStackables, origStackables, 5);
        if (addrAnimalStats) MemWrite(m_hProc, addrAnimalStats, origAnimalStats, 5);
        
        if (m_hProc) CloseHandle(m_hProc);
    }

    int GetFeatureCount() { return (int)m_features.size(); }
    const TrainerFeatureInfo* GetFeatureInfo(int idx) { auto it = m_features.begin(); std::advance(it, idx); return &it->info; }
    int GetFeatureEnabled(const char* id) { for (auto& f : m_features) if (strcmp(f.info.id, id) == 0) return f.enabled; return 0; }
    void SetFeatureEnabled(const char* id, int en) { for (auto& f : m_features) if (strcmp(f.info.id, id) == 0) f.enabled = (en != 0); }
    void ActivateFeature(const char* id) {}
    void SetKeybind(const char* id, int vk) { for (auto& f : m_features) if (strcmp(f.info.id, id) == 0) f.vk_code = vk; }
    int GetKeybind(const char* id) { for (auto& f : m_features) if (strcmp(f.info.id, id) == 0) return f.vk_code.load(); return 0; }
    const char* GetName() { return "Farming Game Trainer"; }
    const char* GetVersion() { return "1.0.0"; }
};

extern "C" {
    __declspec(dllexport) void* trainer_create() { return new FarmingGameTrainer(); }
    __declspec(dllexport) void  trainer_destroy(void* h) { delete static_cast<FarmingGameTrainer*>(h); }
    __declspec(dllexport) int   trainer_initialize(void* h) { return static_cast<FarmingGameTrainer*>(h)->Initialize() ? 1 : 0; }
    __declspec(dllexport) void  trainer_shutdown(void* h) { static_cast<FarmingGameTrainer*>(h)->Shutdown(); }
    __declspec(dllexport) const char* trainer_get_name(void* h) { return static_cast<FarmingGameTrainer*>(h)->GetName(); }
    __declspec(dllexport) const char* trainer_get_version(void* h) { return static_cast<FarmingGameTrainer*>(h)->GetVersion(); }
    __declspec(dllexport) int trainer_get_feature_count(void* h) { return static_cast<FarmingGameTrainer*>(h)->GetFeatureCount(); }
    __declspec(dllexport) const TrainerFeatureInfo* trainer_get_feature_info(void* h, int idx) { return static_cast<FarmingGameTrainer*>(h)->GetFeatureInfo(idx); }
    __declspec(dllexport) int trainer_get_feature_enabled(void* h, const char* id) { return static_cast<FarmingGameTrainer*>(h)->GetFeatureEnabled(id); }
    __declspec(dllexport) void trainer_set_feature_enabled(void* h, const char* id, int en) { static_cast<FarmingGameTrainer*>(h)->SetFeatureEnabled(id, en); }
    __declspec(dllexport) void trainer_activate_feature(void* h, const char* id) { static_cast<FarmingGameTrainer*>(h)->ActivateFeature(id); }
    __declspec(dllexport) void trainer_set_keybind(void* h, const char* id, int vk) { static_cast<FarmingGameTrainer*>(h)->SetKeybind(id, vk); }
    __declspec(dllexport) int trainer_get_keybind(void* h, const char* id) { return static_cast<FarmingGameTrainer*>(h)->GetKeybind(id); }
    __declspec(dllexport) const char* trainer_get_last_error() { return "No errors reported."; }
}