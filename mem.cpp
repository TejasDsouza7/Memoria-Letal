#include "mem.h"
#include "Utils.h"
#include <iostream>
#include <fstream>
#include <vector>
#include <regex>
#include <sstream>
#include <Psapi.h>
#include <cctype>
#include <iomanip>
#include <locale>
#include <codecvt>

#define PAGE_READABLE_FLAGS (PAGE_READWRITE | PAGE_READONLY | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)

std::string wstringToString(const std::wstring& wstr) {
    std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;
    return converter.to_bytes(wstr);
}

bool starts_with(const std::string& str, const std::string& prefix) {
    return str.rfind(prefix, 0) == 0;
}

bool ends_with(const std::string& str, const std::string& suffix) {
    return str.size() >= suffix.size() &&
        str.compare(str.size() - suffix.size(), suffix.size(), suffix) == 0;
}

void PrintHexDump(const BYTE* data, SIZE_T size, uintptr_t baseAddr, std::ostream& out = std::cout) {
    const size_t bytesPerLine = 16;
    for (SIZE_T i = 0; i < size; i += bytesPerLine) {
        out << "0x" << std::hex << (baseAddr + i) << "  ";
        for (size_t j = 0; j < bytesPerLine; ++j) {
            if (i + j < size) {
                out << std::hex << std::uppercase << std::setw(2) << std::setfill('0') << (int)data[i + j] << " ";
            }
            else {
                out << "   ";
            }
        }
        out << "  ";
        for (size_t j = 0; j < bytesPerLine && (i + j < size); ++j) {
            BYTE ch = data[i + j];
            out << (std::isprint(ch) ? (char)ch : '.');
        }
        out << std::endl;
    }
}

std::vector<BYTE> parseHexPattern(const std::string& hex) {
    std::vector<BYTE> bytes;
    std::stringstream ss(hex);
    std::string token;
    size_t pos = 0;

    while ((pos = ss.str().find("\\x")) != std::string::npos) {
        ss.seekg(pos + 2);
        std::string hexByte;
        ss >> std::setw(2) >> hexByte;
        bytes.push_back((BYTE)std::stoul(hexByte, nullptr, 16));
        ss.ignore(2);
    }
    return bytes;
}

void scanProcessMemory(DWORD pid, const std::string& pattern, bool includePrivate, bool includeImage, bool includeMapped) {
    HANDLE hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProcess) {
        std::cerr << "[-] Failed to open process.\n";
        return;
    }

    std::ofstream log("memoria_log.txt");
    std::vector<ModuleInfo> modules = GetModules(pid);

    bool isRegex = starts_with(pattern, "r\"") && ends_with(pattern, "\"");
    bool isHexPattern = starts_with(pattern, "\\x");

    std::regex regexPattern;
    if (isRegex) {
        regexPattern = std::regex(pattern.substr(2, pattern.size() - 3), std::regex::icase);
    }

    std::vector<BYTE> hexPattern;
    if (isHexPattern) {
        hexPattern = parseHexPattern(pattern);
    }

    MEMORY_BASIC_INFORMATION mbi;
    unsigned char* addr = nullptr;

    while (VirtualQueryEx(hProcess, addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        if (mbi.State == MEM_COMMIT && (mbi.Protect & PAGE_READABLE_FLAGS)) {
            bool validType =
                (includePrivate && mbi.Type == MEM_PRIVATE) ||
                (includeImage && mbi.Type == MEM_IMAGE) ||
                (includeMapped && mbi.Type == MEM_MAPPED);

            if (validType) {
                std::vector<BYTE> buffer(mbi.RegionSize);
                SIZE_T bytesRead;

                if (ReadProcessMemory(hProcess, mbi.BaseAddress, buffer.data(), mbi.RegionSize, &bytesRead)) {
                    for (SIZE_T i = 0; i < bytesRead; ++i) {
                        bool matched = false;

                        if (isRegex) {
                            std::string chunk((char*)buffer.data(), bytesRead);
                            auto match = std::sregex_iterator(chunk.begin(), chunk.end(), regexPattern);
                            for (; match != std::sregex_iterator(); ++match) {
                                uintptr_t matchAddress = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + match->position();
                                std::string moduleName = ResolveModuleName(matchAddress, modules);
                                if (moduleName.empty()) moduleName = "[no module]";

                                std::wstringstream ws;
                                ws << L"[+] Pattern found at address: 0x" << std::hex << matchAddress
                                    << L" (Module: " << moduleName.c_str() << L")\n";
                                std::wcout << ws.str();
                                log << wstringToString(ws.str());

                                const SIZE_T bytesAround = 32;
                                BYTE dumpBuffer[bytesAround * 2] = { 0 };
                                uintptr_t dumpAddr = matchAddress - bytesAround;
                                SIZE_T bytesDumped;
                                if (ReadProcessMemory(hProcess, (LPCVOID)dumpAddr, dumpBuffer, sizeof(dumpBuffer), &bytesDumped)) {
                                    log << "[+] Hexdump around 0x" << std::hex << matchAddress << ":\n";
                                    PrintHexDump(dumpBuffer, bytesDumped, dumpAddr, log);
                                }
                            }
                            break;
                        }
                        else if (isHexPattern) {
                            if (i + hexPattern.size() <= bytesRead &&
                                memcmp(buffer.data() + i, hexPattern.data(), hexPattern.size()) == 0) {
                                matched = true;
                            }
                        }
                        else {
                            if (i + pattern.size() <= bytesRead &&
                                memcmp(buffer.data() + i, pattern.c_str(), pattern.size()) == 0) {
                                matched = true;
                            }
                        }

                        if (matched) {
                            uintptr_t matchAddress = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + i;
                            std::string moduleName = ResolveModuleName(matchAddress, modules);
                            if (moduleName.empty()) moduleName = "[no module]";

                            std::wstringstream ws;
                            ws << L"[+] Pattern found at address: 0x" << std::hex << matchAddress
                                << L" (Module: " << moduleName.c_str() << L")\n";
                            std::wcout << ws.str();
                            log << wstringToString(ws.str());

                            const SIZE_T bytesAround = 32;
                            BYTE dumpBuffer[bytesAround * 2] = { 0 };
                            uintptr_t dumpAddr = matchAddress - bytesAround;
                            SIZE_T bytesDumped;

                            if (ReadProcessMemory(hProcess, (LPCVOID)dumpAddr, dumpBuffer, sizeof(dumpBuffer), &bytesDumped)) {
                                log << "[+] Hexdump around 0x" << std::hex << matchAddress << std::dec << ":\n";
                                PrintHexDump(dumpBuffer, bytesDumped, dumpAddr, log);
                            }
                        }
                    }
                }
            }
        }
        addr += mbi.RegionSize;
    }

    CloseHandle(hProcess);
    log.close();
}
