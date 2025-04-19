# **Memoria Letal**

Memoria Letal is a C++ project for scanning the memory of running processes on Windows. It allows you to search for patterns in memory using **ASCII strings**, **regular expressions (regex)**, or **hexadecimal byte sequences**.

---

## **Features**
- Search memory for:
  - **ASCII Strings**: Plain text.
  - **Regex**: Text patterns.
  - **Hexadecimal**: Binary data or machine instructions.
- Provides a hex dump of memory around matches.
- Logs results to `memoria_log.txt`.

---

## **Requirements**
- **Operating System**: Windows
- **Compiler**: Any C++14-compatible compiler (e.g., GCC, Clang, MSVC)
- **Libraries**: Windows API (`Psapi.h`, `tlhelp32.h`)

---

## **How to Compile**
### **Using Command Line**
1. Open a terminal and navigate to the project directory:
   



```shell
cd memoria-letal
   




```
2. Compile the project:

- **Using MSVC**:
      




```shell
cl /EHsc /std:c++14 /Fe:MemoriaLetal.exe MemoriaLetal.cpp mem.cpp Utils.cpp /link Psapi.lib Kernel32.lib
```       




- **Using GCC/MinGW**:
      




```shell
g++ -std=c++14 -o MemoriaLetal.exe MemoriaLetal.cpp mem.cpp Utils.cpp -lpsapi
       




```
3. Run the executable:
   




```shell
MemoriaLetal.exe
   




```

---

## **How to Use**
1. Run the program.
2. Select a process from the list by entering its index.
3. Enter a search pattern:
   - **ASCII String**: Input plain text (e.g., `pid`).
   - **Regex**: Input a pattern in the format `r"regex"` (e.g., `r"\d{3}-\d{2}-\d{4}"`).
   - **Hexadecimal**: Input a pattern in the format `\xXX\xXX` (e.g., `\x90\x90\x90`).
4. Specify memory regions to include:
   - **MEM_PRIVATE**: Private memory regions.
   - **MEM_IMAGE**: Executable files or DLLs.
   - **MEM_MAPPED**: Mapped files or shared memory.
5. View results in the console and `memoria_log.txt`.

---

## **Example**
### **Input**




```plaintext
253: Memoria Letal.exe (PID: 6912)
254: RuntimeBroker.exe (PID: 22244)
255: WmiPrvSE.exe (PID: 14032)
256: msvsmon.exe (PID: 9504)

Enter process index: 253
Enter pattern (ASCII string, or r"regex", or \x90\x90 hex): r"\d{3}-\d{2}-\d{4}"
Include MEM_PRIVATE regions? (y/n): y
Include MEM_IMAGE regions? (y/n): y
Include MEM_MAPPED regions? (y/n): n
    




```
### **Output**




```plaintext
[+] Pattern found at address: 0x7FF6A1234567 (Module: example.dll)
[+] Hexdump around 0x7FF6A1234567:
0x7FF6A1234547  31 32 33 2D 34 35 2D 36 37 38 39 00 00 00 00 00  123-45-6789.....
0x7FF6A1234557  90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90  ................





```

---

## **Files**
- **`MemoriaLetal.cpp`**: Entry point for the program.
- **`mem.cpp`**: Implements memory scanning.
- **`Utils.cpp`**: Provides utility functions for process and module enumeration.
- **`mem.h`**: Header file for memory scanning.
- **`Utils.h`**: Header file for utility functions.

---
