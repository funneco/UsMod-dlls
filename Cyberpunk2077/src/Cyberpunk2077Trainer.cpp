#include "ITrainerModule.h"
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <vector>
#include <thread>
#include <atomic>
#include <cstdint>
#include <cstring>

// Cyberpunk 2077 v2.12 (Steam build 14000000–14199999)
// Godmode: patches mulss (damage scale) → xorps xmm1,xmm1 (zero damage).

static const uint8_t HP_PATTERN[] = {
    0x48, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00,   // mov rax,[rip+?]
    0xF3, 0x0F, 0x59, 0x88, 0x00, 0x00, 0x00, 0x00, // mulss xmm1,[rax+?]
    0xC3                                          // ret
};
static const char HP_MASK[]         = "xxx????xxxx????x";
static const size_t PATCH_OFFSET    = 7;  // byte offset within pattern to patch
static const uint8_t GODMODE_NOP[]  = { 0xF3, 0x0F, 0x57, 0xC9, 0x90, 0x90, 0x90, 0x90 };
static const size_t PATCH_SIZE      = sizeof(GODMODE_NOP);

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
    if (!EnumProcessModulesEx(hProc, mods, sizeof(mods), &needed, LIST_MODULES_64BIT)) return 0;
    wchar_t name[MAX_PATH];
    for (DWORD i = 0; i < needed / sizeof(HMODULE); ++i) {
        GetModuleBaseNameW(hProc, mods[i], name, MAX_PATH);
        if (_wcsicmp(name, mod) == 0) return reinterpret_cast<uintptr_t>(mods[i]);
    }
    return 0;
}

static uintptr_t AobFirst(HANDLE hProc, uintptr_t base, size_t size,
                            const uint8_t* pat, const char* mask, size_t len) {
    std::vector<uint8_t> buf(size);
    SIZE_T r;
    if (!ReadProcessMemory(hProc, reinterpret_cast<LPCVOID>(base), buf.data(), size, &r)) return 0;
    for (size_t i = 0; i + len <= r; ++i) {
        bool ok = true;
        for (size_t j = 0; j < len; ++j)
            if (mask[j] == 'x' && buf[i+j] != pat[j]) { ok = false; break; }
        if (ok) return base + i;
    }
    return 0;
}

static bool PatchMemory(HANDLE hProc, uintptr_t addr,
                         const uint8_t* patch, size_t size,
                         std::vector<uint8_t>& saved) {
    saved.resize(size);
    SIZE_T r;
    if (!ReadProcessMemory(hProc, reinterpret_cast<LPCVOID>(addr), saved.data(), size, &r))
        return false;
    DWORD old;
    VirtualProtectEx(hProc, reinterpret_cast<LPVOID>(addr), size, PAGE_EXECUTE_READWRITE, &old);
    bool ok = WriteProcessMemory(hProc, reinterpret_cast<LPVOID>(addr), patch, size, &r);
    VirtualProtectEx(hProc, reinterpret_cast<LPVOID>(addr), size, old, &old);
    return ok;
}

class Cyberpunk2077Trainer {
public:
    Cyberpunk2077Trainer()
        : m_running(false), m_hProc(nullptr), m_patchAddr(0), m_godmode(false) {}

    ~Cyberpunk2077Trainer() { Shutdown(); }

    bool Initialize() {
        DWORD pid = FindPid(L"Cyberpunk2077.exe");
        if (!pid) return false;

        m_hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
        if (!m_hProc) return false;

        uintptr_t base = GetModuleBase(m_hProc, L"Cyberpunk2077.exe");
        if (!base) { CloseHandle(m_hProc); m_hProc = nullptr; return false; }

        IMAGE_DOS_HEADER dos; SIZE_T r;
        ReadProcessMemory(m_hProc, reinterpret_cast<LPCVOID>(base), &dos, sizeof(dos), &r);
        IMAGE_NT_HEADERS64 nt;
        ReadProcessMemory(m_hProc, reinterpret_cast<LPCVOID>(base + dos.e_lfanew), &nt, sizeof(nt), &r);

        m_patchAddr = AobFirst(m_hProc, base, nt.OptionalHeader.SizeOfImage,
                               HP_PATTERN, HP_MASK, sizeof(HP_PATTERN) - 1);

        m_running = true;
        m_thread  = std::thread(&Cyberpunk2077Trainer::Loop, this);
        return true;
    }

    void Shutdown() {
        m_running = false;
        if (m_thread.joinable()) m_thread.join();
        if (m_godmode && m_patchAddr && m_hProc)
            PatchMemory(m_hProc, m_patchAddr + PATCH_OFFSET,
                        m_original.data(), PATCH_SIZE, m_original);
        if (m_hProc) { CloseHandle(m_hProc); m_hProc = nullptr; }
    }

    const char* GetName()    const { return "Cyberpunk 2077 Trainer"; }
    const char* GetVersion() const { return "1.0.0"; }

private:
    std::atomic<bool>    m_running;
    HANDLE               m_hProc;
    uintptr_t            m_patchAddr;
    bool                 m_godmode;
    std::vector<uint8_t> m_original;
    std::thread          m_thread;

    void ToggleGodmode() {
        if (!m_patchAddr) return;
        if (!m_godmode) {
            if (PatchMemory(m_hProc, m_patchAddr + PATCH_OFFSET,
                            GODMODE_NOP, PATCH_SIZE, m_original))
                m_godmode = true;
        } else {
            std::vector<uint8_t> dummy;
            if (PatchMemory(m_hProc, m_patchAddr + PATCH_OFFSET,
                            m_original.data(), PATCH_SIZE, dummy))
                m_godmode = false;
        }
    }

    void Loop() {
        while (m_running) {
            if (GetAsyncKeyState(VK_F1) & 1) { ToggleGodmode(); Sleep(300); }
            Sleep(10);
        }
    }
};

// ── C ABI exports ───────────────────────────────────────────────────────────

extern "C" {

void* trainer_create() {
    return new Cyberpunk2077Trainer();
}
void trainer_destroy(void* h) {
    delete static_cast<Cyberpunk2077Trainer*>(h);
}
int trainer_initialize(void* h) {
    return static_cast<Cyberpunk2077Trainer*>(h)->Initialize() ? 1 : 0;
}
void trainer_shutdown(void* h) {
    static_cast<Cyberpunk2077Trainer*>(h)->Shutdown();
}
const char* trainer_get_name(void* h) {
    return static_cast<Cyberpunk2077Trainer*>(h)->GetName();
}
const char* trainer_get_version(void* h) {
    return static_cast<Cyberpunk2077Trainer*>(h)->GetVersion();
}

} // extern "C"
