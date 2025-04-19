#include "mem.h"
#include "Utils.h"
#include <iostream>
#include <string>
#include <Windows.h>

int main() {
    std::wcout << L"=== Memoria Letal ===\n";
    std::vector<ProcessInfo> processes = listProcesses();

    if (processes.empty()) {
        std::wcout << L"No processes found.\n";
        return 1;
    }

    std::wcout << L"\nAvailable Processes:\n";
    for (size_t i = 0; i < processes.size(); ++i) {
        std::wcout << i << L": " << processes[i].name << L" (PID: " << processes[i].pid << L")\n";
    }

    int selection = -1;
    std::wcout << L"\nEnter process index: ";
    std::wcin >> selection;

    if (selection < 0 || selection >= static_cast<int>(processes.size())) {
        std::wcout << L"Invalid selection.\n";
        return 1;
    }

    DWORD pid = processes[selection].pid;
    std::string pattern;
    std::cout << "Enter pattern (ASCII string, or r\"regex\", or \\x90\\x90 hex): ";
    std::cin.ignore(); 
    std::getline(std::cin, pattern);

    char choice;
    bool includePrivate = true, includeImage = true, includeMapped = true;

    std::cout << "Include MEM_PRIVATE regions? (y/n): ";
    std::cin >> choice;
    includePrivate = (choice == 'y' || choice == 'Y');

    std::cout << "Include MEM_IMAGE regions? (y/n): ";
    std::cin >> choice;
    includeImage = (choice == 'y' || choice == 'Y');

    std::cout << "Include MEM_MAPPED regions? (y/n): ";
    std::cin >> choice;
    includeMapped = (choice == 'y' || choice == 'Y');

    std::wcout << L"\n[+] Starting memory scan on PID " << pid << L"...\n";
    scanProcessMemory(pid, pattern, includePrivate, includeImage, includeMapped);

    std::wcout << L"\n[+] Scan complete. Results logged to memoria_log.txt\n";
    return 0;
}
