"use strict";

let textAdded = "";
let index = 0;
let startTime = Date.now();
let hackerCodeHTML = `#define WIN32_LEAN_AND_MEAN
#define CREATE_THREAD_ACCESS (PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION)

BOOL Inject(DWORD pID, const char * DLL_NAME);
DWORD GetTargetThreadIDFromProcName(const char * ProcName);

int main(int ar
   DWORD pID = GetTargetThreadIDFromProcName("Engi
   char buf[MAX_PATH] = {0};
   GetFullPathName("HACKS.dll", MAX_PATH, buf, NULL);
   printf(bu
   if(!Inject(pID, buf))
   {
        printf("DLL Not Loaded!");
    }else{
        printf("DLL Loaded!");
    }

    _getch();
   return 0;
}

BOOL Inject(DWORD pID, const char * DLL_NAME)
{
   HANDLE Proc;
   HMODULE hLib;
   char buf[50] = {0};
   LPVOID RemoteString, LoadLibAddy;

   if(!pID)
      return false;

   Proc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pID);
   if(!Proc)
   {
      sprintf(buf, "OpenProcess() failed: %d", GetLastError());
      printf(buf);
      return false;
   }
   
   LoadLibAddy = (LPVOID)GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");
   
   
   RemoteString = (LPVOID)VirtualAllocEx(Proc, NULL, strlen(DLL_NAME), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

   
   WriteProcessMemory(Proc, (LPVOID)RemoteString, DLL_NAME, strlen(DLL_NAME), NULL);
   CreateRemoteThread(Proc, NULL, NULL, (LPTHREAD_START_ROUTINE)LoadLibAddy, (LPVOID)RemoteString, NULL, NULL);

   CloseHandle(Proc);
   return true;
}

DWORD GetTargetThreadIDFromProcName(const char * ProcName)
{
   PROCESSENTRY32 pe;
   HANDLE thSnapShot;
   BOOL retval, ProcFound = false;

   thSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
   if(thSnapShot == INVALID_HANDLE_VALUE)
   {
      printf("Error: Unable to create toolhelp snapshot!");
      return false;
   }

   pe.dwSize = sizeof(PROCESSENTRY32);
   
   retval = Process32First(thSnapShot, &pe);
   while(retval)
   {
      if(StrStrI(pe.szExeFile, ProcName))
      {
         return pe.th32ProcessID;
      }
      retval = Process32Next(thSnapShot, &pe);
   }
   return 0;
}
`;
let aborted = false;

console.log(hackerCodeHTML);

$(document).keypress(function () {
  if (!aborted) {
    let textToAdd = hackerCodeHTML.slice(index, index + 10);
    index = index + 10;
    textAdded += textToAdd;

    $(".code").html(`<pre><code>${textAdded}</code></pre>`);
    document
      .querySelector(".code")
      .scrollIntoView({ behavior: "smooth", block: "end" });
  }
});

function updateCpuUsage() {
  let randomUsage = Math.trunc(Math.random() * 101);
  $(".cpu-usage").text(randomUsage);
}
function updateRamUsage() {
  let randomUsage = Math.trunc(Math.random() * 32000);
  $(".ram-usage").text(randomUsage);
}
function updateUptime() {
  let currentTime = Date.now();

  $(".uptime").text(Math.trunc((currentTime - startTime) / 1000));
}

function abort() {
  $(".abort").removeClass("abort").addClass("abort-active");
  $(".network-status").text("DISCONNECTED").css("color", "red");
  $("body").css("color", "red");
}

setInterval(updateCpuUsage, 1000);
setInterval(updateRamUsage, 1000);
setInterval(updateUptime, 1000);
