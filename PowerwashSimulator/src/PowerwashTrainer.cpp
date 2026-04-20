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
    int type; // 1 = Toggle
    int hotkey;
};

static char g_lastError[256] = "";
static void SetLastErr(const char* msg) { strncpy(g_lastError, msg, sizeof(g_lastError) - 1); }

// --- Utils ---
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
    FlushInstructionCache(hProc, (LPVOID)addr, size);
    return ok;
}

static uintptr_t AobScan(HANDLE hProc, uintptr_t base, size_t sz, const uint8_t* pat, size_t len) {
    std::vector<uint8_t> buf(sz);
    SIZE_T r = 0;
    if (!ReadProcessMemory(hProc, (LPCVOID)base, buf.data(), sz, &r)) return 0;
    for (size_t i = 0; i + len <= r; ++i) if (memcmp(buf.data() + i, pat, len) == 0) return base + i;
    return 0;
}

// --- Logic ---
struct PatchSite {
    uintptr_t addr = 0;
    uint8_t orig[15] = {0};
    size_t len = 0;
    uintptr_t cave = 0;
    bool active = false;
};

struct Feature {
    TrainerFeatureInfo info;
    std::atomic<bool> enabled{ false };
    Feature(const char* i, const char* n, const char* d, int k) : info{i,n,d,1,k} {}
};

class PWSTrainer {
public:
    HANDLE m_hProc = nullptr;
    std::atomic<bool> m_running{ false };
    std::thread m_thread;
    std::list<Feature> m_features;
    PatchSite m_siteClean, m_siteDirt;

    PWSTrainer() {
        m_features.emplace_back("instant_clean", "Instant Clean", "10k Power", VK_F1);
        m_features.emplace_back("show_dirt", "Show Dirt", "Always Highlight", VK_F3);
    }

    bool Initialize() {
        DWORD pid = FindPid(L"PowerWashSimulator.exe");
        if (!pid) return false;
        m_hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
        uintptr_t gaBase = GetModuleBase(pid, L"GameAssembly.dll");
        if (!gaBase) return false;

        // Instant Clean - Steam Offset
        m_siteClean.addr = gaBase + 0xDF4790;
        m_siteClean.len = 10;
        ReadProcessMemory(m_hProc, (LPCVOID)m_siteClean.addr, m_siteClean.orig, 10, nullptr);

        // Show Dirt - AOB
        uint8_t pat[] = { 0xF3, 0x0F, 0x11, 0x43, 0x38, 0xF3, 0x0F, 0x10 };
        m_siteDirt.addr = AobScan(m_hProc, gaBase, 0x2000000, pat, 8);
        if (m_siteDirt.addr) {
            m_siteDirt.len = 5;
            ReadProcessMemory(m_hProc, (LPCVOID)m_siteDirt.addr, m_siteDirt.orig, 5, nullptr);
            m_siteDirt.cave = (uintptr_t)VirtualAllocEx(m_hProc, nullptr, 128, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            float val = 1.0f;
            uint8_t code[] = { 0xF3, 0x0F, 0x10, 0x05, 0x0A, 0x00, 0x00, 0x00, 0xF3, 0x0F, 0x11, 0x43, 0x38, 0xE9, 0,0,0,0 };
            int32_t rel = (int32_t)(m_siteDirt.addr + 5 - (m_siteDirt.cave + 18));
            memcpy(&code[14], &rel, 4);
            WriteProcessMemory(m_hProc, (LPVOID)m_siteDirt.cave, code, 18, nullptr);
            WriteProcessMemory(m_hProc, (LPVOID)(m_siteDirt.cave + 18), &val, 4, nullptr);
        }

        m_running = true;
        m_thread = std::thread([this](){
            bool p1=false, p2=false;
            while(m_running){
                for(auto& f : m_features) if(GetAsyncKeyState(f.info.hotkey)&1) f.enabled = !f.enabled;
                auto it = m_features.begin();
                if(it->enabled != p1){
                    if(it->enabled){ uint8_t p[]={0xB8,0x10,0x27,0x00,0x00,0xF3,0x0F,0x2A,0xC0,0xC3}; MemWrite(m_hProc, m_siteClean.addr, p, 10); m_siteClean.active=true; }
                    else { MemWrite(m_hProc, m_siteClean.addr, m_siteClean.orig, 10); m_siteClean.active=false; }
                    p1=it->enabled;
                }
                it++;
                if(it->enabled != p2 && m_siteDirt.cave){
                    if(it->enabled){ uint8_t j[5]={0xE9,0,0,0,0}; int32_t r=(int32_t)(m_siteDirt.cave-m_siteDirt.addr-5); memcpy(&j[1],&r,4); MemWrite(m_hProc, m_siteDirt.addr, j, 5); m_siteDirt.active=true; }
                    else { MemWrite(m_hProc, m_siteDirt.addr, m_siteDirt.orig, 5); m_siteDirt.active=false; }
                    p2=it->enabled;
                }
                Sleep(10);
            }
        });
        return true;
    }
};

// --- Exports ---
extern "C" {
    __declspec(dllexport) void* trainer_create() { return new PWSTrainer(); }
    __declspec(dllexport) void trainer_destroy(void* h) { auto t=(PWSTrainer*)h; t->m_running=false; if(t->m_thread.joinable()) t->m_thread.join(); delete t; }
    __declspec(dllexport) int trainer_initialize(void* h) { return ((PWSTrainer*)h)->Initialize() ? 1 : 0; }
    __declspec(dllexport) const char* trainer_get_name(void* h) { return "PWS Steam Alpha"; }
    __declspec(dllexport) int trainer_get_feature_count(void* h) { return 2; }
    __declspec(dllexport) const TrainerFeatureInfo* trainer_get_feature_info(void* h, int idx) { auto t=(PWSTrainer*)h; auto it=t->m_features.begin(); std::advance(it, idx); return &it->info; }
    __declspec(dllexport) int trainer_get_feature_enabled(void* h, const char* id) { for(auto& f:((PWSTrainer*)h)->m_features) if(strcmp(f.info.id, id)==0) return f.enabled; return 0; }
    __declspec(dllexport) void trainer_set_feature_enabled(void* h, const char* id, int en) { for(auto& f:((PWSTrainer*)h)->m_features) if(strcmp(f.info.id, id)==0) f.enabled=(en!=0); }
    __declspec(dllexport) const char* trainer_get_last_error() { return g_lastError; }
}