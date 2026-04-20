// Goat Simulator Trainer — Steam App 265930, build 1629888
// Target: GoatGame-Win32-Shipping.exe (32-bit UE3)
// Pointer chains use 32-bit reads; all coords are float.

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

static uintptr_t GetModuleBase(HANDLE hProc, const wchar_t* mod) {
    HMODULE mods[1024]; DWORD needed;
    if (!EnumProcessModulesEx(hProc, mods, sizeof(mods), &needed, LIST_MODULES_32BIT))
        return 0;
    wchar_t name[MAX_PATH];
    for (DWORD i = 0; i < needed / sizeof(HMODULE); ++i) {
        GetModuleBaseNameW(hProc, mods[i], name, MAX_PATH);
        if (_wcsicmp(name, mod) == 0)
            return reinterpret_cast<uintptr_t>(mods[i]);
    }
    return 0;
}

template<typename T>
static bool MemRead(HANDLE hProc, uintptr_t addr, T& out) {
    SIZE_T r;
    return ReadProcessMemory(hProc, (LPCVOID)addr, &out, sizeof(T), &r) && r == sizeof(T);
}

template<typename T>
static bool MemWrite(HANDLE hProc, uintptr_t addr, const T& val) {
    SIZE_T r;
    return WriteProcessMemory(hProc, (LPVOID)addr, &val, sizeof(T), &r) && r == sizeof(T);
}

// 32-bit pointer chain — game is Win32, pointers are 4 bytes
static uintptr_t FindPointerAddr(HANDLE hProc, uintptr_t ptr, const std::vector<uint32_t>& offsets) {
    uintptr_t addr = ptr;
    for (auto off : offsets) {
        uint32_t next = 0;
        if (!MemRead(hProc, addr, next)) return 0;
        addr = static_cast<uintptr_t>(next) + off;
    }
    return addr;
}

// ── Feature ───────────────────────────────────────────────────────────────────

struct Feature {
    TrainerFeatureInfo info;
    std::atomic<bool>  enabled{false};
    std::atomic<int>   vk_code{0};
    Feature(const char* id_, const char* n, const char* d, int tog, int vk)
        : info{id_, n, d, tog, vk}, vk_code(vk) {}
};

// ── Trainer ───────────────────────────────────────────────────────────────────

class GoatSimulatorTrainer {
public:
    GoatSimulatorTrainer() : m_running(false), m_hProc(nullptr) {
        // Movement
        m_features.emplace_back("fly_up",          "Fly Up",           "Move goat up by fly force",          0, VK_NUMPAD3);
        m_features.emplace_back("fly_down",         "Fly Down",         "Move goat down by fly force",        0, VK_NUMPAD4);
        m_features.emplace_back("hover_mode",       "Hover Mode",       "Lock goat height in place",          1, VK_NUMPAD6);
        m_features.emplace_back("anti_aim",         "Anti-Aim",         "Spin goat yaw continuously",         1, 0);
        // Teleport
        m_features.emplace_back("teleport",         "Save/Restore Pos", "First press saves, second restores", 0, VK_NUMPAD7);
        m_features.emplace_back("tp_origin",        "TP to Origin",     "Teleport to trainer load position",  0, 0);
        // Goat mods
        m_features.emplace_back("chunky_mode",      "Chunky Mode",      "Toggle chunky goat hitbox",          1, 0);
        m_features.emplace_back("max_speed",        "Max Speed",        "Set tick speed to 1000",             0, 0);
        m_features.emplace_back("normal_speed",     "Normal Speed",     "Reset tick speed to 1.0",            0, 0);
        m_features.emplace_back("giant_goat",       "Giant Goat",       "Set goat size to 100",               0, 0);
        m_features.emplace_back("normal_size",      "Normal Size",      "Reset goat size to 1",               0, 0);
        m_features.emplace_back("add_score",        "Add 9999 Score",   "Add 9999 to current score",          0, 0);
        // Goatvile
        m_features.emplace_back("tp_flappy_goat",   "TP: Flappy Goat",  "Goatvile — Flappy Goat minigame",    0, 0);
        m_features.emplace_back("tp_sacrifice",     "TP: Sacrifice",    "Goatvile — Sacrifice jahit",         0, 0);
        m_features.emplace_back("tp_roboter",       "TP: Da Roboter",   "Goatvile — Da Roboter",              0, 0);
        m_features.emplace_back("tp_goat_house",    "TP: Goat House",   "Goatvile — Goat House",              0, 0);
        m_features.emplace_back("tp_goat_kingdom",  "TP: Goat Kingdom", "Goatvile — Goat Kingdom",            0, 0);
        // Goatcity
        m_features.emplace_back("tp_skate_park",    "TP: Skate Park",   "Goatcity — Skate Park",              0, 0);
        m_features.emplace_back("tp_dude_dancing",  "TP: Dude Dancing", "Goatcity — Dude Dancing",            0, 0);
        m_features.emplace_back("tp_drug_island",   "TP: Drug Island",  "Goatcity — Drug Island",             0, 0);
        m_features.emplace_back("tp_graveyard",     "TP: Graveyard",    "Goatcity — Graveyard",               0, 0);
        m_features.emplace_back("tp_minecraft",     "TP: Minecraft",    "Goatcity — Minecraft Block",         0, 0);
        m_features.emplace_back("tp_fun",           "TP: Fun",          "Goatcity — Fun area",                0, 0);
        m_features.emplace_back("tp_ninja_shreks",  "TP: Ninja Shreks", "Goatcity — Ninja Shreks",            0, 0);
        m_features.emplace_back("tp_casino",        "TP: Casino",       "Goatcity — Casino",                  0, 0);
        // Battery spots
        m_features.emplace_back("tp_battery_1",     "TP: Battery 1",    "Goatcity — Battery Spot 1",          0, 0);
        m_features.emplace_back("tp_battery_2",     "TP: Battery 2",    "Goatcity — Battery Spot 2",          0, 0);
        m_features.emplace_back("tp_battery_3",     "TP: Battery 3",    "Goatcity — Battery Spot 3",          0, 0);
        m_features.emplace_back("tp_battery_4",     "TP: Battery 4",    "Goatcity — Battery Spot 4",          0, 0);
        m_features.emplace_back("tp_battery_5",     "TP: Battery 5",    "Goatcity — Battery Spot 5",          0, 0);
        m_features.emplace_back("tp_battery_6",     "TP: Battery 6",    "Goatcity — Battery Spot 6",          0, 0);

        auto it = m_features.begin();
        m_fFlyUp    = &(*it++);
        m_fFlyDown  = &(*it++);
        m_fHover    = &(*it++);
        m_fAntiAim  = &(*it++);
        ++it; // teleport
        ++it; // tp_origin
        m_fChunky   = &(*it++);
    }

    ~GoatSimulatorTrainer() { Shutdown(); }

    bool Initialize() {
        DWORD pid = FindPid(L"GoatGame-Win32-Shipping.exe");
        if (!pid) {
            SetLastErr("process not found — is Goat Simulator running?");
            return false;
        }
        m_hProc = OpenProcess(
            PROCESS_VM_READ | PROCESS_VM_WRITE |
            PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION,
            FALSE, pid);
        if (!m_hProc) {
            char buf[128];
            wsprintfA(buf, "OpenProcess failed (error %lu) — run as administrator", GetLastError());
            SetLastErr(buf);
            return false;
        }
        m_moduleBase = GetModuleBase(m_hProc, L"GoatGame-Win32-Shipping.exe");
        if (!m_moduleBase) {
            SetLastErr("module base not found");
            CloseHandle(m_hProc); m_hProc = nullptr;
            return false;
        }
        ResolveAddresses();
        m_running = true;
        m_thread  = std::thread(&GoatSimulatorTrainer::Loop, this);
        return true;
    }

    void Shutdown() {
        m_running = false;
        if (m_thread.joinable()) m_thread.join();
        if (m_hProc) { CloseHandle(m_hProc); m_hProc = nullptr; }
    }

    const char* GetName()    const { return "Goat Simulator Trainer"; }
    const char* GetVersion() const { return "1.0.0"; }

    int GetFeatureCount() const { return static_cast<int>(m_features.size()); }

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
                // Capture hover Y on enable
                if (strcmp(id, "hover_mode") == 0 && enabled && m_addrY)
                    MemRead(m_hProc, m_addrY, m_hoverY);
                f.enabled = (enabled != 0);
                return;
            }
    }

    void ActivateFeature(const char* id) {
        if (!m_hProc || !m_addrY) return;

        if (strcmp(id, "fly_up") == 0) {
            float y = 0; if (MemRead(m_hProc, m_addrY, y)) MemWrite(m_hProc, m_addrY, y + m_flyForce);
        }
        else if (strcmp(id, "fly_down") == 0) {
            float y = 0; if (MemRead(m_hProc, m_addrY, y)) MemWrite(m_hProc, m_addrY, y - m_flyForce);
        }
        else if (strcmp(id, "teleport") == 0) {
            if (!m_tpSaved) {
                MemRead(m_hProc, m_addrX, m_tpX);
                MemRead(m_hProc, m_addrY, m_tpY);
                MemRead(m_hProc, m_addrZ, m_tpZ);
                m_tpSaved = true;
            } else {
                MemWrite(m_hProc, m_addrX, m_tpX);
                MemWrite(m_hProc, m_addrY, m_tpY);
                MemWrite(m_hProc, m_addrZ, m_tpZ);
                m_tpSaved = false;
            }
        }
        else if (strcmp(id, "tp_origin") == 0)        { Teleport(m_originY, m_originZ, m_originX); }
        else if (strcmp(id, "max_speed") == 0)         { if (m_addrTickSpeed) MemWrite(m_hProc, m_addrTickSpeed, 1000.0f); }
        else if (strcmp(id, "normal_speed") == 0)      { if (m_addrTickSpeed) MemWrite(m_hProc, m_addrTickSpeed, 1.0f); }
        else if (strcmp(id, "giant_goat") == 0)        { if (m_addrSize) MemWrite(m_hProc, m_addrSize, 100.0f); }
        else if (strcmp(id, "normal_size") == 0)       { if (m_addrSize) MemWrite(m_hProc, m_addrSize, 1.0f); }
        else if (strcmp(id, "add_score") == 0) {
            if (m_addrScore) {
                int32_t s = 0; MemRead(m_hProc, m_addrScore, s);
                MemWrite(m_hProc, m_addrScore, s + 9999);
            }
        }
        // Goatvile
        else if (strcmp(id, "tp_flappy_goat")  == 0)  { Teleport(735.7919312f,   -21531.05273f, -10197.75488f); }
        else if (strcmp(id, "tp_sacrifice")    == 0)  { Teleport(1790.96f,       -27054.16992f,  -6027.351074f); }
        else if (strcmp(id, "tp_roboter")      == 0)  { Teleport(2769.687744f,   -20773.35938f, -24056.16406f); }
        else if (strcmp(id, "tp_goat_house")   == 0)  { Teleport(776.807f,       -16697.2f,     -14657.7f); }
        else if (strcmp(id, "tp_goat_kingdom") == 0)  { Teleport(-5595.98f,       -3084.68f,    -21446.8f); }
        // Goatcity
        else if (strcmp(id, "tp_skate_park")   == 0)  { Teleport(2514.84f,         6398.98f,     9035.25f); }
        else if (strcmp(id, "tp_dude_dancing") == 0)  { Teleport(7934.71f,       -11788.8f,    -12962.9f); }
        else if (strcmp(id, "tp_drug_island")  == 0)  { Teleport(310.313f,      -104077.0f,     5017.51f); }
        else if (strcmp(id, "tp_graveyard")    == 0)  { Teleport(2946.55f,        -8307.65f,   -16131.3f); }
        else if (strcmp(id, "tp_minecraft")    == 0)  { Teleport(2880.99f,       -10324.4f,    -15165.6f); }
        else if (strcmp(id, "tp_fun")          == 0)  { Teleport(5067.14f,         6646.3f,     -6995.29f); }
        else if (strcmp(id, "tp_ninja_shreks") == 0)  { Teleport(-9459.88f,       -9540.83f,   14313.3f); }
        else if (strcmp(id, "tp_casino")       == 0)  { Teleport(118.729f,       -16975.1f,     5145.78f); }
        // Battery spots
        else if (strcmp(id, "tp_battery_1")    == 0)  { Teleport(414.135f,        -7737.59f,    5904.24f); }
        else if (strcmp(id, "tp_battery_2")    == 0)  { Teleport(11079.4f,       -13595.1f,     3302.86f); }
        else if (strcmp(id, "tp_battery_3")    == 0)  { Teleport(2399.33f,        -4409.64f,    1593.52f); }
        else if (strcmp(id, "tp_battery_4")    == 0)  { Teleport(367.051f,       -14460.3f,    18320.7f); }
        else if (strcmp(id, "tp_battery_5")    == 0)  { Teleport(118.6f,         -16823.7f,     3740.46f); }
        else if (strcmp(id, "tp_battery_6")    == 0)  { Teleport(2442.8f,         -6525.86f,   13560.8f); }
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
    uintptr_t          m_moduleBase = 0;
    std::thread        m_thread;
    std::list<Feature> m_features;

    Feature* m_fFlyUp   = nullptr;
    Feature* m_fFlyDown = nullptr;
    Feature* m_fHover   = nullptr;
    Feature* m_fAntiAim = nullptr;
    Feature* m_fChunky  = nullptr;

    // Resolved addresses
    uintptr_t m_addrX         = 0;
    uintptr_t m_addrY         = 0;
    uintptr_t m_addrZ         = 0;
    uintptr_t m_addrMovCtrl   = 0;
    uintptr_t m_addrRotYaw    = 0;
    uintptr_t m_addrTickSpeed = 0;
    uintptr_t m_addrSize      = 0;
    uintptr_t m_addrScore     = 0;
    uintptr_t m_addrHoriSize  = 0;
    uintptr_t m_addrDiagSize  = 0;
    uintptr_t m_addrClass     = 0;

    // State
    static constexpr float k_flyForce = 120.0f;
    float m_flyForce  = k_flyForce;
    float m_originX   = 0, m_originY = 0, m_originZ = 0;
    float m_hoverY    = 0;
    float m_tpX       = 0, m_tpY = 0, m_tpZ = 0;
    bool  m_tpSaved   = false;
    float m_antiAimRot = 1.0f;
    bool  m_chunkyActive = false;

    void ResolveAddresses() {
        const uintptr_t B = m_moduleBase;
        m_addrY         = FindPointerAddr(m_hProc, B + 0x27B964C, { 0xc, 0x2e0, 0x0, 0x370, 0x5C });
        m_addrZ         = FindPointerAddr(m_hProc, B + 0x27B964C, { 0xc, 0x2e0, 0x0, 0x370, 0x54 });
        m_addrX         = FindPointerAddr(m_hProc, B + 0x27B964C, { 0xc, 0x2e0, 0x0, 0x370, 0x58 });
        m_addrRotYaw    = FindPointerAddr(m_hProc, B + 0x27B964C, { 0xc, 0x2e0, 0x0, 0x370, 0x64 });
        m_addrSize      = FindPointerAddr(m_hProc, B + 0x27B964C, { 0xc, 0x2e0, 0x0, 0x370, 0x6c });
        m_addrHoriSize  = FindPointerAddr(m_hProc, B + 0x27B964C, { 0xc, 0x2e0, 0x0, 0x370, 0x78 });
        m_addrDiagSize  = FindPointerAddr(m_hProc, B + 0x27B964C, { 0xc, 0x2e0, 0x0, 0x370, 0x75 });
        m_addrClass     = FindPointerAddr(m_hProc, B + 0x27B964C, { 0xc, 0x2e0, 0x0, 0x370, 0x50 });
        m_addrMovCtrl   = FindPointerAddr(m_hProc, B + 0x27B964C, { 0xc, 0x2e0, 0x0, 0x370, 0x94 });
        m_addrTickSpeed = FindPointerAddr(m_hProc, B + 0x27B964C, { 0xc, 0x2e0, 0x0, 0x370, 0x90 });
        m_addrScore     = FindPointerAddr(m_hProc, B + 0x27B9658, { 0x0, 0x138, 0xe0, 0xe0, 0x4aC, 0x538, 0x0 });

        MemRead(m_hProc, m_addrX, m_originX);
        MemRead(m_hProc, m_addrY, m_originY);
        MemRead(m_hProc, m_addrZ, m_originZ);
    }

    void Teleport(float y, float z, float x) {
        MemWrite(m_hProc, m_addrY, y);
        MemWrite(m_hProc, m_addrZ, z);
        MemWrite(m_hProc, m_addrX, x);
    }

    void Loop() {
        int32_t lastClass  = 0;
        bool    prevHover  = false;
        bool    prevChunky = false;

        MemRead(m_hProc, m_addrClass, lastClass);

        while (m_running) {
            // Re-resolve addresses on level change
            int32_t curClass = 0;
            if (MemRead(m_hProc, m_addrClass, curClass) && curClass != lastClass) {
                ResolveAddresses();
                lastClass = curClass;
            }

            // Hover mode — lock Y
            bool hover = m_fHover->enabled.load();
            if (hover && !prevHover)
                MemRead(m_hProc, m_addrY, m_hoverY);
            if (hover)
                MemWrite(m_hProc, m_addrY, m_hoverY);
            prevHover = hover;

            // Anti-aim — spin yaw
            if (m_fAntiAim->enabled.load()) {
                m_antiAimRot += 1.0f;
                if (m_antiAimRot < 0.0f) m_antiAimRot = 1.0f;
                MemWrite(m_hProc, m_addrRotYaw, m_antiAimRot);
            } else {
                m_antiAimRot = 1.0f;
            }

            // Chunky mode — apply/restore on toggle change
            bool chunky = m_fChunky->enabled.load();
            if (chunky != prevChunky) {
                if (chunky) {
                    MemWrite(m_hProc, m_addrDiagSize, 5.931554006E-39f);
                    MemWrite(m_hProc, m_addrHoriSize, 2.0f);
                } else {
                    MemWrite(m_hProc, m_addrDiagSize, 5.831554006E-39f);
                    MemWrite(m_hProc, m_addrHoriSize, 1.0f);
                }
                prevChunky = chunky;
            }

            // Hotkey dispatch
            for (auto& f : m_features) {
                int vk = f.vk_code.load();
                if (!vk) continue;
                if (!(GetAsyncKeyState(vk) & 1)) continue;
                if (f.info.is_toggle) {
                    bool newVal = !f.enabled.load();
                    if (strcmp(f.info.id, "hover_mode") == 0 && newVal)
                        MemRead(m_hProc, m_addrY, m_hoverY);
                    f.enabled = newVal;
                } else {
                    ActivateFeature(f.info.id);
                }
            }

            Sleep(10);
        }
    }
};

// ── C ABI exports ─────────────────────────────────────────────────────────────

extern "C" {

void* trainer_create()            { return new GoatSimulatorTrainer(); }
void  trainer_destroy(void* h)    { delete static_cast<GoatSimulatorTrainer*>(h); }
int   trainer_initialize(void* h) { return static_cast<GoatSimulatorTrainer*>(h)->Initialize() ? 1 : 0; }
void  trainer_shutdown(void* h)   { static_cast<GoatSimulatorTrainer*>(h)->Shutdown(); }

const char* trainer_get_name(void* h)    { return static_cast<GoatSimulatorTrainer*>(h)->GetName(); }
const char* trainer_get_version(void* h) { return static_cast<GoatSimulatorTrainer*>(h)->GetVersion(); }

int trainer_get_feature_count(void* h)
    { return static_cast<GoatSimulatorTrainer*>(h)->GetFeatureCount(); }
const TrainerFeatureInfo* trainer_get_feature_info(void* h, int idx)
    { return static_cast<GoatSimulatorTrainer*>(h)->GetFeatureInfo(idx); }
int trainer_get_feature_enabled(void* h, const char* id)
    { return static_cast<GoatSimulatorTrainer*>(h)->GetFeatureEnabled(id); }
void trainer_set_feature_enabled(void* h, const char* id, int en)
    { static_cast<GoatSimulatorTrainer*>(h)->SetFeatureEnabled(id, en); }
void trainer_activate_feature(void* h, const char* id)
    { static_cast<GoatSimulatorTrainer*>(h)->ActivateFeature(id); }
void trainer_set_keybind(void* h, const char* id, int vk)
    { static_cast<GoatSimulatorTrainer*>(h)->SetKeybind(id, vk); }
int trainer_get_keybind(void* h, const char* id)
    { return static_cast<GoatSimulatorTrainer*>(h)->GetKeybind(id); }

const char* trainer_get_last_error() { return g_lastError; }

} // extern "C"
