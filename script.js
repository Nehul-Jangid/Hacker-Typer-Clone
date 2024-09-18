"use strict";

let textAdded = "";
let index = 0;
let startTime = Date.now();
let charsTyped = 0;

let locked = false;
const hackerCodeHTML = `#define WIN32_LEAN_AND_MEAN
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

function app(e) {
  if (!aborted) {
    if (!locked) {
      charsTyped++;
      let textToAdd = hackerCodeHTML.slice(index, index + 10);
      index += 10;
      textAdded += textToAdd;

      $(".code").html(`<pre><code>${textAdded}</code></pre>`);
      document
        .querySelector(".code")
        .scrollIntoView({ behavior: "smooth", block: "end" });
      if (charsTyped % 100 === 0) {
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
