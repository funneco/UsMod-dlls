#include "ITrainerModule.h"
#include <windows.h>
#include <thread>
#include <atomic>
#include <vector>

// --- Mono API Function Signatures ---
typedef void* (*mono_get_root_domain)();
typedef void* (*mono_thread_attach)(void* domain);
typedef void* (*mono_assembly_open)(void* domain, const char* name);
typedef void* (*mono_assembly_get_image)(void* assembly);
typedef void* (*mono_class_from_name)(void* image, const char* name_space, const char* name);
typedef void* (*mono_class_get_method_from_name)(void* klass, const char* name, int param_count);
typedef void* (*mono_compile_method)(void* method);

// Shellcode: mov eax, 10000; cvtsi2ss xmm0, eax; ret
static const uint8_t CLEAN_PATCH[] = { 0xB8, 0x10, 0x27, 0x00, 0x00, 0xF3, 0x0F, 0x2A, 0xC0, 0xC3 };

struct Feature {
    TrainerFeatureInfo info;
    std::atomic<bool> enabled{false};
    std::atomic<int> vk_code{0};

    Feature(const char* id_, const char* n, const char* d, int tog, int vk)
        : info{id_, n, d, tog, vk}, vk_code(vk) {}
};

class PowerWashTrainer {
public:
    PowerWashTrainer() : m_running(false), m_patchAddr(0) {
        // Feature ID "instant_wash", Name "Instant Wash", Description, IsToggle = 1, Default Key = F1
        m_features.emplace_back("instant_wash", "Instant Wash", "Sets effectiveness to 10,000", 1, VK_F1);
    }

    ~PowerWashTrainer() { Shutdown(); }

    bool Initialize() {
        m_patchAddr = GetMonoMethodAddress();
        if (!m_patchAddr) return false;

        // Store original bytes for safe disabling
        memcpy(m_originalBytes, (void*)m_patchAddr, sizeof(CLEAN_PATCH));

        m_running = true;
        m_thread = std::thread(&PowerWashTrainer::Loop, this);
        return true;
    }

    void Shutdown() {
        m_running = false;
        if (m_thread.joinable()) m_thread.join();
        TogglePatch(false); // Restore original code on exit
    }

    // --- ITrainerModule Interface Implementation ---
    const char* GetName()    const { return "PowerWash Simulator Trainer"; }
    const char* GetVersion() const { return "1.1.0"; }
    int GetFeatureCount()    const { return (int)m_features.size(); }

    const TrainerFeatureInfo* GetFeatureInfo(int idx) const {
        if (idx < 0 || idx >= m_features.size()) return nullptr;
        return &m_features[idx].info;
    }

    int GetFeatureEnabled(const char* id) const {
        for (const auto& f : m_features)
            if (strcmp(f.info.id, id) == 0) return f.enabled.load() ? 1 : 0;
        return 0;
    }

    void SetFeatureEnabled(const char* id, int enabled) {
        for (auto& f : m_features) {
            if (strcmp(f.info.id, id) == 0) {
                f.enabled = (enabled != 0);
                TogglePatch(enabled != 0);
                return;
            }
        }
    }

    void ActivateFeature(const char* id) {
        // For non-toggle buttons, put logic here.
    }

private:
    std::atomic<bool> m_running;
    uintptr_t m_patchAddr;
    uint8_t m_originalBytes[sizeof(CLEAN_PATCH)];
    std::thread m_thread;
    std::vector<Feature> m_features;

    uintptr_t GetMonoMethodAddress() {
        HMODULE hMono = GetModuleHandleA("mono-2.0-bdwgc.dll");
        if (!hMono) return 0;

        auto GetRootDomain = (mono_get_root_domain)GetProcAddress(hMono, "mono_get_root_domain");
        auto ThreadAttach = (mono_thread_attach)GetProcAddress(hMono, "mono_thread_attach");
        auto AssemblyOpen = (mono_assembly_open)GetProcAddress(hMono, "mono_assembly_open");
        auto AssemblyGetImage = (mono_assembly_get_image)GetProcAddress(hMono, "mono_assembly_get_image");
        auto ClassFromName = (mono_class_from_name)GetProcAddress(hMono, "mono_class_from_name");
        auto GetMethodFromName = (mono_class_get_method_from_name)GetProcAddress(hMono, "mono_class_get_method_from_name");
        auto CompileMethod = (mono_compile_method)GetProcAddress(hMono, "mono_compile_method");

        void* domain = GetRootDomain();
        ThreadAttach(domain);

        // GameAssembly.dll contains the PWS namespace
        void* assembly = AssemblyOpen(domain, "GameAssembly.dll");
        if (!assembly) return 0;
        void* image = AssemblyGetImage(assembly);

        // Find PWS.WasherClassNozzleSettings
        void* klass = ClassFromName(image, "PWS", "WasherClassNozzleSettings");
        if (!klass) return 0;

        // Find GetEffectivenessAgainst(target)
        void* method = GetMethodFromName(klass, "GetEffectivenessAgainst", 1);
        if (!method) return 0;

        // Compile and return pointer
        return (uintptr_t)CompileMethod(method);
    }

    void TogglePatch(bool enable) {
        if (!m_patchAddr) return;

        DWORD oldProtect;
        VirtualProtect((void*)m_patchAddr, sizeof(CLEAN_PATCH), PAGE_EXECUTE_READWRITE, &oldProtect);
        
        if (enable) {
            memcpy((void*)m_patchAddr, CLEAN_PATCH, sizeof(CLEAN_PATCH));
        } else {
            memcpy((void*)m_patchAddr, m_originalBytes, sizeof(CLEAN_PATCH));
        }

        VirtualProtect((void*)m_patchAddr, sizeof(CLEAN_PATCH), oldProtect, &oldProtect);
    }

    void Loop() {
        while (m_running) {
            for (auto& f : m_features) {
                int vk = f.vk_code.load();
                if (vk && (GetAsyncKeyState(vk) & 1)) {
                    bool newState = !f.enabled.load();
                    SetFeatureEnabled(f.info.id, newState ? 1 : 0);
                }
            }
            Sleep(10);
        }
    }
};

// --- C ABI Exports ---
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
}