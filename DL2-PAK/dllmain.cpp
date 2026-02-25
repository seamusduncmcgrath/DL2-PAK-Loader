#include <windows.h>
#include <filesystem>
#include <string>
#include <vector>
#include <fstream>
#include <unordered_set>
#include <algorithm>

#include "MinHook.h"

// Settings & Logging System, might remove later
bool g_EnableConsole = false;
std::filesystem::path g_LogFilePath;

void Log(const std::string& message) {
    // 1. Log to File
    if (!g_LogFilePath.empty()) {
        std::ofstream logFile(g_LogFilePath, std::ios_base::app);
        if (logFile.is_open()) {
            logFile << message;
        }
    }

    // 2. Log to Console (if enabled by user)
    if (g_EnableConsole) {
        HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
        if (hConsole) {
            DWORD written;
            WriteConsoleA(hConsole, message.c_str(), (DWORD)message.length(), &written, NULL);
        }
    }
}

void InitSettingsAndLogging() {
    std::filesystem::path exePath = std::filesystem::current_path();
    std::filesystem::path iniPath = exePath / "CustomPaksLoader.ini";
    g_LogFilePath = exePath / "CustomPaksLoader.log";

    // Clear previous log on startup
    std::ofstream clearLog(g_LogFilePath, std::ios_base::trunc);
    clearLog.close();

    // Create default INI if it doesn't exist
    if (!std::filesystem::exists(iniPath)) {
        std::ofstream iniFile(iniPath);
        iniFile << "[Settings]\n";
        iniFile << "; Set to 1 to open a debug console window alongside the game.\n";
        iniFile << "EnableConsole=0\n";
    }

    // Read Settings
    g_EnableConsole = GetPrivateProfileIntA("Settings", "EnableConsole", 0, iniPath.string().c_str()) == 1;

    if (g_EnableConsole) {
        AllocConsole();
        SetConsoleTitleA("DL2 Custom PAK Loader - Debug");
    }

    Log("==================================================\n");
    Log("          Dying Light 2 Custom PAK Loader         \n");
    Log("==================================================\n");
}

uintptr_t FindPattern(const char* moduleName, const char* pattern) {
    HMODULE hModule = GetModuleHandleA(moduleName);
    if (!hModule) return 0;

    auto PatternToBytes = [](const char* pattern) {
        std::vector<int> bytes;
        char* start = const_cast<char*>(pattern);
        char* end = const_cast<char*>(pattern) + strlen(pattern);
        for (char* current = start; current < end; ++current) {
            if (*current == '?') {
                ++current;
                if (*current == '?') ++current;
                bytes.push_back(-1);
            }
            else {
                bytes.push_back(strtoul(current, &current, 16));
            }
        }
        return bytes;
        };

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((std::uint8_t*)hModule + dosHeader->e_lfanew);
    DWORD sizeOfImage = ntHeaders->OptionalHeader.SizeOfImage;
    std::vector<int> patternBytes = PatternToBytes(pattern);
    std::uint8_t* scanBytes = reinterpret_cast<std::uint8_t*>(hModule);

    size_t s = patternBytes.size();
    int* d = patternBytes.data();

    for (size_t i = 0; i < sizeOfImage - s; ++i) {
        bool found = true;
        for (size_t j = 0; j < s; ++j) {
            if (scanBytes[i + j] != d[j] && d[j] != -1) {
                found = false;
                break;
            }
        }
        if (found) return reinterpret_cast<uintptr_t>(&scanBytes[i]);
    }
    return 0;
}

//Prob should put this stuff in a header

typedef LPVOID(*CResourceLoadingRuntimeCreate_t)(bool);
CResourceLoadingRuntimeCreate_t pOriginalCResourceLoadingRuntimeCreate = nullptr;

namespace fs {
    struct mount_path {
        const char* gamePath;
        const char* pakPath;
        const char* fullPakPath;
    };

    static DWORD64 mount(mount_path* path, USHORT flags, LPVOID* a3) {
        typedef DWORD64(*pMount_t)(mount_path*, USHORT, LPVOID*);
        static pMount_t pMount = (pMount_t)GetProcAddress(GetModuleHandleA("filesystem_x64_rwdi.dll"), "?mount@fs@@YA_NAEBUmount_path@1@GPEAPEAVCFsMount@@@Z");
        if (!pMount) return 0;
        return pMount(path, flags, a3);
    }
}

LPVOID detourCResourceLoadingRuntimeCreate(bool noTexStreaming) {
    std::filesystem::path exePath = std::filesystem::current_path();
    std::filesystem::path customPaksPath = exePath / "CustomPaks";
    std::filesystem::path loadOrderPath = customPaksPath / "LoadOrder.txt";

    if (!std::filesystem::exists(customPaksPath)) {
        std::filesystem::create_directory(customPaksPath);
        Log("[Info] Created 'CustomPaks' directory.\n");
    }

    std::vector<std::string> loadOrder;

    if (std::filesystem::exists(loadOrderPath)) {
        std::ifstream file(loadOrderPath);
        std::string line;
        while (std::getline(file, line)) {
            line.erase(line.find_last_not_of(" \n\r\t") + 1);
            line.erase(0, line.find_first_not_of(" \n\r\t"));
            if (!line.empty() && line[0] != ';' && line[0] != '#') {
                loadOrder.push_back(line);
            }
        }
        Log("[Info] Parsed LoadOrder.txt with " + std::to_string(loadOrder.size()) + " target entries.\n");
    }
    else {
        std::ofstream file(loadOrderPath);
        file << "; List your .pak files here in the order you want them to load.\n";
        file << "; Files not listed here will be loaded automatically afterwards.\n";
        file << "; Lines starting with ';' or '#' are ignored.\n";
        Log("[Info] Generated default LoadOrder.txt.\n");
    }

    std::string gamePathStr = customPaksPath.string();
    fs::mount_path pathPtr = {};
    pathPtr.gamePath = gamePathStr.c_str();

    int pakCount = 0;
    std::unordered_set<std::string> mountedPaks;

    auto MountPak = [&](const std::string& relPath, const std::string& fullPath) {
        std::string lowerRelPath = relPath;
        std::transform(lowerRelPath.begin(), lowerRelPath.end(), lowerRelPath.begin(), ::tolower);

        if (mountedPaks.find(lowerRelPath) != mountedPaks.end()) {
            return false;
        }

        pathPtr.pakPath = relPath.c_str();
        pathPtr.fullPakPath = fullPath.c_str();

        Log("  -> Mounting: " + relPath + "\n");
        fs::mount(&pathPtr, 1, nullptr);

        mountedPaks.insert(lowerRelPath);
        return true;
        };

    try {
        Log("[Info] Processing priority paks from LoadOrder.txt...\n");
        for (const auto& pakName : loadOrder) {
            std::filesystem::path fullPakPath = customPaksPath / pakName;
            if (std::filesystem::exists(fullPakPath) && !std::filesystem::is_directory(fullPakPath)) {
                if (MountPak(pakName, fullPakPath.string())) pakCount++;
            }
            else {
                Log("[Warning] Could not find file specified in load order: " + pakName + "\n");
            }
        }

        Log("[Info] Scanning for unlisted .pak files...\n");
        if (std::filesystem::exists(customPaksPath)) {
            for (const auto& entry : std::filesystem::recursive_directory_iterator(customPaksPath)) {
                if (entry.is_directory()) continue;

                std::string fullPakPath = entry.path().string();
                if (fullPakPath.length() >= 4 && _stricmp(fullPakPath.c_str() + fullPakPath.length() - 4, ".pak") == 0) {
                    std::string pakPath = fullPakPath;
                    pakPath.erase(0, gamePathStr.size() + 1);
                    if (MountPak(pakPath, fullPakPath)) pakCount++;
                }
            }
        }
    }
    catch (const std::exception& e) {
        Log(std::string("[Error] File system exception: ") + e.what() + "\n");
    }

    Log("[Info] Successfully mounted " + std::to_string(pakCount) + " custom PAKs in total.\n");
    Log("==================================================\n");

    return pOriginalCResourceLoadingRuntimeCreate(noTexStreaming);
}

// 2. MountDataPaks Hook
typedef DWORD64(*MountDataPaks_t)(DWORD64, UINT, UINT, DWORD64*, DWORD64(*)(DWORD64, DWORD, DWORD64, char*, int), INT16, DWORD64, UINT);
MountDataPaks_t pOriginalMountDataPaks = nullptr;

DWORD64 detourMountDataPaks(DWORD64 a1, UINT a2, UINT a3, DWORD64* a4, DWORD64(*a5)(DWORD64, DWORD, DWORD64, char*, int), INT16 a6, DWORD64 a7, UINT a8) {
    return pOriginalMountDataPaks(a1, a2, a3, a4, a5, a6, a7, 200);
}

// 3. FsCheckZipCrc Hook
typedef bool(*FsCheckZipCrc_t)(LPVOID);
FsCheckZipCrc_t pOriginalFsCheckZipCrc = nullptr;

bool detourFsCheckZipCrc(LPVOID instance) {
    return true;
}

// ========================================================================
// Plugin Initialization
// ========================================================================
void InitializeHooks() {
    InitSettingsAndLogging();

    if (MH_Initialize() != MH_OK) {
        Log("[Error] Failed to initialize MinHook.\n");
        return;
    }

    HMODULE hEngine = GetModuleHandleA("engine_x64_rwdi.dll");
    HMODULE hFileSystem = GetModuleHandleA("filesystem_x64_rwdi.dll");

    if (hEngine) {
        LPVOID pCreateRuntime = (LPVOID)GetProcAddress(hEngine, "?Create@CResourceLoadingRuntime@@SAPEAV1@_N@Z");
        if (pCreateRuntime) {
            MH_CreateHook(pCreateRuntime, &detourCResourceLoadingRuntimeCreate, (LPVOID*)&pOriginalCResourceLoadingRuntimeCreate);
            MH_EnableHook(pCreateRuntime);
            Log("[Hook] CResourceLoadingRuntimeCreate initialized successfully.\n");
        }
        else {
            Log("[Error] Failed to find CResourceLoadingRuntimeCreate export!\n");
        }

        uintptr_t mountDataPaksAddr = FindPattern("engine_x64_rwdi.dll", "4C 8B DC 4D 89 4B ?? 45 89 43 ?? 89 54 24 ?? 49 89 4B");
        if (mountDataPaksAddr) {
            MH_CreateHook((LPVOID)mountDataPaksAddr, &detourMountDataPaks, (LPVOID*)&pOriginalMountDataPaks);
            MH_EnableHook((LPVOID)mountDataPaksAddr);
            Log("[Hook] MountDataPaks initialized successfully.\n");
        }
        else {
            Log("[Error] Failed to find MountDataPaks via pattern scan! The game may have updated.\n");
        }
    }
    else {
        Log("[Error] engine_x64_rwdi.dll not found!\n");
    }

    if (hFileSystem) {
        LPVOID pCheckZipCrc = (LPVOID)GetProcAddress(hFileSystem, "?check_zip_crc@izipped_buffer_file@fs@@QEAA_NXZ");
        if (pCheckZipCrc) {
            MH_CreateHook(pCheckZipCrc, &detourFsCheckZipCrc, (LPVOID*)&pOriginalFsCheckZipCrc);
            MH_EnableHook(pCheckZipCrc);
            Log("[Hook] FsCheckZipCrc initialized successfully.\n");
        }
        else {
            Log("[Error] Failed to find check_zip_crc export!\n");
        }
    }
    else {
        Log("[Error] filesystem_x64_rwdi.dll not found!\n");
    }
}

// ASI Entry Point
BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH: {
        char exePath[MAX_PATH];
        GetModuleFileNameA(NULL, exePath, MAX_PATH);
        std::string exeStr(exePath);

        if (exeStr.find("crashpad_handler") != std::string::npos) {
            return TRUE;
        }

        DisableThreadLibraryCalls(hModule);
        CreateThread(nullptr, 0, (LPTHREAD_START_ROUTINE)InitializeHooks, nullptr, 0, nullptr);
        break;
    }
    case DLL_PROCESS_DETACH:
        MH_Uninitialize();
        break;
    }
    return TRUE;
}