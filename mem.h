#pragma once
#include <Windows.h>
#include <string>

void scanProcessMemory(DWORD pid, const std::string& pattern, bool includePrivate, bool includeImage, bool includeMapped);
