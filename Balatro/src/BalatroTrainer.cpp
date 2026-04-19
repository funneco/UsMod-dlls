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

// Balatro (Steam App 2379780) trainer — build 17459173 (v1.0.1f)
// Scans LOVE2D engine memory for the gold float via AOB pattern.

static const uint8_t GOLD_PATTERN[] = {
    0x48, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00,
    0xF3, 0x0F, 0x10, 0x81, 0x00, 0x00, 0x00, 0x00
};
static const char GOLD_MASK[]      = "xxx????xxxx????";
static const int  GOLD_FLOAT_OFFSET = 11;

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

static uintptr_t GetModuleBase(HANDLE hProc, const wchar_t* mod) {
    HMODULE mods[1024]; DWORD needed;
    if (!EnumProcessModulesEx(hProc, mods, sizeof(mods), &needed, LIST_MODULES_64BIT))
        return 0;
    wchar_t name[MAX_PATH];
    for (DWORD i = 0; i < needed / sizeof(HMODULE); ++i) {
        GetModuleBaseNameW(hProc, mods[i], name, MAX_PATH);
        if (_wcsicmp(name, mod) == 0)
            return reinterpret_cast<uintptr_t>(mods[i]);
    }
    return 0;
}

static uintptr_t AobFirst(HANDLE hProc, uintptr_t base, size_t size,
                            const uint8_t* pat, const char* mask, size_t len) {
    std::vector<uint8_t> buf(size);
    SIZE_T r;
    if (!ReadProcessMemory(hProc, reinterpret_cast<LPCVOID>(base), buf.data(), size, &r))
        return 0;
    for (size_t i = 0; i + len <= r; ++i) {
        bool ok = true;
        for (size_t j = 0; j < len; ++j)
            if (mask[j] == 'x' && buf[i+j] != pat[j]) { ok = false; break; }
        if (ok) return base + i;
    }
    return 0;
}

struct Feature {
    TrainerFeatureInfo info;
    std::atomic<bool>  enabled{false};
    std::atomic<int>   vk_code{0};
    Feature(const char* id_, const char* n, const char* d, int tog, int vk)
        : info{id_, n, d, tog, vk}, vk_code(vk) {}
};

class BalatroTrainer {
public:
    BalatroTrainer() : m_running(false), m_hProc(nullptr), m_goldAddr(0) {
        m_features.emplace_back("add_gold",      "Add Gold",      "Set gold to 9999",    0, VK_F1);
        m_features.emplace_back("add_secondary", "Add Secondary", "Set secondary to 99", 0, VK_F2);
    }

    ~BalatroTrainer() { Shutdown(); }

    bool Initialize() {
        DWORD pid = FindPid(L"balatro.exe");
        if (!pid) return false;

        m_hProc = OpenProcess(
            PROCESS_VM_READ | PROCESS_VM_WRITE |
            PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION,
            FALSE, pid);
        if (!m_hProc) return false;

        uintptr_t base = GetModuleBase(m_hProc, L"balatro.exe");
        if (!base) { CloseHandle(m_hProc); m_hProc = nullptr; return false; }

        IMAGE_DOS_HEADER dos; SIZE_T r;
        ReadProcessMemory(m_hProc, reinterpret_cast<LPCVOID>(base), &dos, sizeof(dos), &r);
        IMAGE_NT_HEADERS64 nt;
        ReadProcessMemory(m_hProc, reinterpret_cast<LPCVOID>(base + dos.e_lfanew), &nt, sizeof(nt), &r);

        m_goldAddr = AobFirst(m_hProc, base, nt.OptionalHeader.SizeOfImage,
                              GOLD_PATTERN, GOLD_MASK, sizeof(GOLD_PATTERN) - 1);
        if (m_goldAddr) m_goldAddr += GOLD_FLOAT_OFFSET;

        m_running = true;
        m_thread  = std::thread(&BalatroTrainer::Loop, this);
        return true;
    }

    void Shutdown() {
        m_running = false;
        if (m_thread.joinable()) m_thread.join();
        if (m_hProc) { CloseHandle(m_hProc); m_hProc = nullptr; }
    }

    const char* GetName()    const { return "Balatro Trainer"; }
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
        if (!m_goldAddr || !m_hProc) return;
        if (strcmp(id, "add_gold") == 0)
            WriteFloat(m_goldAddr, 9999.0f);
        else if (strcmp(id, "add_secondary") == 0)
            WriteFloat(m_goldAddr + 0x4, 99.0f);
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
    std::atomic<bool>  m_running;
    HANDLE             m_hProc;
    uintptr_t          m_goldAddr;
    std::thread        m_thread;
    std::list<Feature> m_features;

    void WriteFloat(uintptr_t addr, float v) {
        WriteProcessMemory(m_hProc, reinterpret_cast<LPVOID>(addr), &v, sizeof(v), nullptr);
    }

    void Loop() {
        while (m_running) {
            for (auto& f : m_features) {
                int vk = f.vk_code.load();
                if (vk && (GetAsyncKeyState(vk) & 1)) {
                    if (f.info.is_toggle)
                        f.enabled = !f.enabled.load();
                    else
                        ActivateFeature(f.info.id);
                }
            }
            Sleep(10);
        }
    }
};

// ── C ABI exports ────────────────────────────────────────────────────────────

extern "C" {

void* trainer_create()            { return new BalatroTrainer(); }
void  trainer_destroy(void* h)    { delete static_cast<BalatroTrainer*>(h); }
int   trainer_initialize(void* h) { return static_cast<BalatroTrainer*>(h)->Initialize() ? 1 : 0; }
void  trainer_shutdown(void* h)   { static_cast<BalatroTrainer*>(h)->Shutdown(); }

const char* trainer_get_name(void* h)    { return static_cast<BalatroTrainer*>(h)->GetName(); }
const char* trainer_get_version(void* h) { return static_cast<BalatroTrainer*>(h)->GetVersion(); }

int trainer_get_feature_count(void* h)
    { return static_cast<BalatroTrainer*>(h)->GetFeatureCount(); }
const TrainerFeatureInfo* trainer_get_feature_info(void* h, int idx)
    { return static_cast<BalatroTrainer*>(h)->GetFeatureInfo(idx); }
int trainer_get_feature_enabled(void* h, const char* id)
    { return static_cast<BalatroTrainer*>(h)->GetFeatureEnabled(id); }
void trainer_set_feature_enabled(void* h, const char* id, int en)
    { static_cast<BalatroTrainer*>(h)->SetFeatureEnabled(id, en); }
void trainer_activate_feature(void* h, const char* id)
    { static_cast<BalatroTrainer*>(h)->ActivateFeature(id); }
void trainer_set_keybind(void* h, const char* id, int vk)
    { static_cast<BalatroTrainer*>(h)->SetKeybind(id, vk); }
int trainer_get_keybind(void* h, const char* id)
    { return static_cast<BalatroTrainer*>(h)->GetKeybind(id); }

} // extern "C"
