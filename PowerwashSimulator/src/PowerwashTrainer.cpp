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

static uintptr_t AobScan(HANDLE hProc, uintptr_t base, size_t sz, const uint8_t* pat, size_t len) {
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

struct Feature {
    TrainerFeatureInfo info;
    std::atomic<bool> enabled{ false };
    std::atomic<int> vk_code{ 0 };
    Feature(const char* i, const char* n, const char* d, int tog, int vk)
        : info{ i,n,d,tog,vk }, vk_code(vk) {}
};

class PowerWashTrainer {
public:
    HANDLE m_hProc = nullptr;
    std::atomic<bool> m_running{ false };
    std::thread m_thread;
    std::list<Feature> m_features;

    uintptr_t addrClean = 0;
    uint8_t origClean[10] = { 0 };

    uintptr_t addrDirt = 0;
    uint8_t origDirt[14] = { 0 }; // Increased for Absolute Jump safety
    uintptr_t caveDirt = 0;

    PowerWashTrainer() {
        m_features.emplace_back("instant_clean", "Instant Clean", "10k Power", 1, VK_F1);
        m_features.emplace_back("show_dirt", "Show Dirt", "Permanent Highlight", 1, VK_F3);
    }

    bool Initialize() {
        DWORD pid = FindPid(L"PowerWashSimulator.exe");
        if (!pid) return false;
        m_hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
        uintptr_t gaBase = GetModuleBase(pid, L"GameAssembly.dll");
        if (!gaBase) return false;

        // Instant Clean
        addrClean = gaBase + 0xDF4790;
        ReadProcessMemory(m_hProc, (LPCVOID)addrClean, origClean, 10, nullptr);

        // Show Dirt
        uint8_t pat[] = { 0xF3, 0x0F, 0x11, 0x43, 0x38, 0xF3, 0x0F, 0x10, 0x00, 0x28 };
        addrDirt = AobScan(m_hProc, gaBase, 0x3000000, pat, 10);

        if (addrDirt) {
            ReadProcessMemory(m_hProc, (LPCVOID)addrDirt, origDirt, 14, nullptr);
            caveDirt = (uintptr_t)VirtualAllocEx(m_hProc, nullptr, 1024, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            
            float glow_val = 1.0f;
            uintptr_t glow_data = caveDirt + 0x200;

            uint8_t code[] = { 
                0xF3, 0x0F, 0x10, 0x05, 0x00, 0x00, 0x00, 0x00, // movss xmm0, [glow_data]
                0xF3, 0x0F, 0x11, 0x43, 0x38,                   // movss [rbx+38], xmm0
                0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,             // jmp qword ptr [back]
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  // back address
            };

            int32_t glow_off = (int32_t)(glow_data - (caveDirt + 8));
            memcpy(&code[4], &glow_off, 4);

            uintptr_t retAddr = addrDirt + 10; // Jumping back past original instructions
            memcpy(&code[20], &retAddr, 8);

            WriteProcessMemory(m_hProc, (LPVOID)caveDirt, code, sizeof(code), nullptr);
            WriteProcessMemory(m_hProc, (LPVOID)glow_data, &glow_val, 4, nullptr);
        }

        m_running = true;
        m_thread = std::thread(&PowerWashTrainer::Loop, this);
        return true;
    }

    void Loop() {
        bool p1 = false, p2 = false;
        while (m_running) {
            for (auto& f : m_features) {
                int vk = f.vk_code.load();
                if (vk && (GetAsyncKeyState(vk) & 1)) f.enabled = !f.enabled;
            }

            auto it = m_features.begin();
            // Feature 1: Instant Clean
            if (it->enabled != p1) {
                if (it->enabled) {
                    uint8_t patch[10] = { 0xB8,0x10,0x27,0x00,0x00,0xF3,0x0F,0x2A,0xC0,0xC3 }; 
                    MemWrite(m_hProc, addrClean, patch, 10);
                } else {
                    MemWrite(m_hProc, addrClean, origClean, 10);
                }
                p1 = it->enabled;
            }

            it++;
            // Feature 2: Show Dirt (14-byte Absolute Jump Hook)
            if (it->enabled != p2 && addrDirt) {
                if (it->enabled) {
                    uint8_t hook[14] = { 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00 };
                    memcpy(&hook[6], &caveDirt, 8);
                    MemWrite(m_hProc, addrDirt, hook, 14);
                } else {
                    MemWrite(m_hProc, addrDirt, origDirt, 14);
                }
                p2 = it->enabled;
            }
            Sleep(10);
        }
    }

    void Shutdown() { m_running = false; if (m_thread.joinable()) m_thread.join(); }
    int GetFeatureCount() { return (int)m_features.size(); }
    const TrainerFeatureInfo* GetFeatureInfo(int idx) { auto it = m_features.begin(); std::advance(it, idx); return &it->info; }
    int GetFeatureEnabled(const char* id) { for (auto& f : m_features) if (strcmp(f.info.id, id) == 0) return f.enabled; return 0; }
    void SetFeatureEnabled(const char* id, int en) { for (auto& f : m_features) if (strcmp(f.info.id, id) == 0) f.enabled = (en != 0); }
    void ActivateFeature(const char* id) {}
    void SetKeybind(const char* id, int vk) { for (auto& f : m_features) if (strcmp(f.info.id, id) == 0) f.vk_code = vk; }
    int GetKeybind(const char* id) { for (auto& f : m_features) if (strcmp(f.info.id, id) == 0) return f.vk_code.load(); return 0; }
    const char* GetName() { return "PowerWash Simulator Trainer"; }
    const char* GetVersion() { return "1.0.0"; }
};

extern "C" {
    __declspec(dllexport) void* trainer_create() { return new PowerWashTrainer(); }
    __declspec(dllexport) void  trainer_destroy(void* h) { delete static_cast<PowerWashTrainer*>(h); }
    __declspec(dllexport) int   trainer_initialize(void* h) { return static_cast<PowerWashTrainer*>(h)->Initialize() ? 1 : 0; }
    __declspec(dllexport) void  trainer_shutdown(void* h) { static_cast<PowerWashTrainer*>(h)->Shutdown(); }
    __declspec(dllexport) const char* trainer_get_name(void* h) { return static_cast<PowerWashTrainer*>(h)->GetName(); }
    __declspec(dllexport) const char* trainer_get_version(void* h) { return static_cast<PowerWashTrainer*>(h)->GetVersion(); }
    __declspec(dllexport) int trainer_get_feature_count(void* h) { return static_cast<PowerWashTrainer*>(h)->GetFeatureCount(); }
    __declspec(dllexport) const TrainerFeatureInfo* trainer_get_feature_info(void* h, int idx) { return static_cast<PowerWashTrainer*>(h)->GetFeatureInfo(idx); }
    __declspec(dllexport) int trainer_get_feature_enabled(void* h, const char* id) { return static_cast<PowerWashTrainer*>(h)->GetFeatureEnabled(id); }
    __declspec(dllexport) void trainer_set_feature_enabled(void* h, const char* id, int en) { static_cast<PowerWashTrainer*>(h)->SetFeatureEnabled(id, en); }
    __declspec(dllexport) void trainer_activate_feature(void* h, const char* id) { static_cast<PowerWashTrainer*>(h)->ActivateFeature(id); }
    __declspec(dllexport) void trainer_set_keybind(void* h, const char* id, int vk) { static_cast<PowerWashTrainer*>(h)->SetKeybind(id, vk); }
    __declspec(dllexport) int trainer_get_keybind(void* h, const char* id) { return static_cast<PowerWashTrainer*>(h)->GetKeybind(id); }
    __declspec(dllexport) const char* trainer_get_last_error() { return "No errors reported."; }
}