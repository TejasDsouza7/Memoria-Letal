#include "Utils.h"
#include <Psapi.h>
#include <iostream>
#include <tlhelp32.h>
#include <locale>
#include <codecvt>
#include <sstream> 

std::vector<ProcessInfo> listProcesses() {
    std::vector<ProcessInfo> processList;

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        std::wcerr << L"[!] Failed to take process snapshot.\n";
        return processList;
    }

    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);

    if (Process32FirstW(hSnapshot, &pe32)) {
        do {
            ProcessInfo info;
            info.pid = pe32.th32ProcessID;
            info.name = pe32.szExeFile;
            processList.push_back(info);
        } while (Process32NextW(hSnapshot, &pe32));
    }
    else {
        std::wcerr << L"[!] Failed to enumerate processes.\n";
    }

    CloseHandle(hSnapshot);
    return processList;
}

std::vector<ModuleInfo> GetModules(DWORD pid) {
    std::vector<ModuleInfo> result;

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) {
        std::cerr << "[!] Failed to open process for module enumeration.\n";
        return result;
    }

    HMODULE hMods[1024];
    DWORD cbNeeded;
    if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
        size_t count = cbNeeded / sizeof(HMODULE);
        for (size_t i = 0; i < count; ++i) {
            MODULEINFO modInfo;
            char szModName[MAX_PATH] = { 0 };

            if (GetModuleInformation(hProcess, hMods[i], &modInfo, sizeof(modInfo)) &&
                GetModuleBaseNameA(hProcess, hMods[i], szModName, sizeof(szModName))) {
                ModuleInfo mi;
                mi.name = szModName;
                mi.base = reinterpret_cast<uintptr_t>(modInfo.lpBaseOfDll);
                mi.size = static_cast<size_t>(modInfo.SizeOfImage);
                result.push_back(mi);
            }
        }
    }
    else {
        std::cerr << "[!] EnumProcessModules failed.\n";
    }

    CloseHandle(hProcess);
    return result;
}

std::string ResolveModuleName(uintptr_t address, const std::vector<ModuleInfo>& modules) {
    for (const auto& mod : modules) {
        if (address >= mod.base && address < mod.base + mod.size) {
            std::stringstream ss; 
            ss << mod.name << " + 0x" << std::hex << (address - mod.base);
            return ss.str();
        }
    }
    return "[no module]";
}

#pragma comment(lib, "Psapi.lib")
