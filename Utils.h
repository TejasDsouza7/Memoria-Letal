#pragma once
#include <Windows.h>
#include <string>
#include <vector>

struct ProcessInfo {
    DWORD pid;
    std::wstring name;
};

struct ModuleInfo {
    std::string name;
    uintptr_t base;
    size_t size;
};

std::vector<ProcessInfo> listProcesses();
std::vector<ModuleInfo> GetModules(DWORD pid);
std::string ResolveModuleName(uintptr_t address, const std::vector<ModuleInfo>& modules);