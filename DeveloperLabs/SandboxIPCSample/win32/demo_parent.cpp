#include <windows.h>
#include <aclapi.h>
#include <sddl.h>
#include <stdio.h>
#include <string>
#include <userenv.h>

#pragma comment(lib, "userenv.lib")

#define PIPE_NAME L"\\\\.\\pipe\\IPCDemoPipe"
#define BUFFER_SIZE 512
#define APPCONTAINER_NAME L"IPCDemo.ChildContainer"

// Function to get and display the current process integrity level
void DisplayProcessSecurityInfo()
{
  HANDLE hToken = nullptr;

  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
  {
    printf("[Parent] Failed to open process token. Error: %lu\n", GetLastError());
    return;
  }

  // Get integrity level
  DWORD dwLengthNeeded = 0;
  GetTokenInformation(hToken, TokenIntegrityLevel, nullptr, 0, &dwLengthNeeded);

  TOKEN_MANDATORY_LABEL* pTIL = (TOKEN_MANDATORY_LABEL*)LocalAlloc(0, dwLengthNeeded);
  if (pTIL)
  {
    if (GetTokenInformation(hToken, TokenIntegrityLevel, pTIL, dwLengthNeeded, &dwLengthNeeded))
    {
      DWORD dwIntegrityLevel = *GetSidSubAuthority(pTIL->Label.Sid,
        (DWORD)(UCHAR)(*GetSidSubAuthorityCount(pTIL->Label.Sid) - 1));

      const char* integrityLevelStr = "Unknown";
      if (dwIntegrityLevel < SECURITY_MANDATORY_LOW_RID)
        integrityLevelStr = "Untrusted";
      else if (dwIntegrityLevel < SECURITY_MANDATORY_MEDIUM_RID)
        integrityLevelStr = "Low";
      else if (dwIntegrityLevel < SECURITY_MANDATORY_HIGH_RID)
        integrityLevelStr = "Medium";
      else if (dwIntegrityLevel >= SECURITY_MANDATORY_HIGH_RID)
        integrityLevelStr = "High/System";

      printf("[Parent] *** Process Integrity Level: %s (0x%X) ***\n", integrityLevelStr, dwIntegrityLevel);

      // Convert SID to string for display
      LPWSTR szIntegritySid = nullptr;
      if (ConvertSidToStringSidW(pTIL->Label.Sid, &szIntegritySid))
      {
        printf("[Parent] *** Integrity SID: %ls ***\n", szIntegritySid);
        LocalFree(szIntegritySid);
      }
    }
    LocalFree(pTIL);
  }

  // Check if running in AppContainer
  DWORD dwIsAppContainer = 0;
  dwLengthNeeded = sizeof(DWORD);
  if (GetTokenInformation(hToken, TokenIsAppContainer, &dwIsAppContainer, sizeof(DWORD), &dwLengthNeeded))
  {
    printf("[Parent] *** Running in AppContainer: %s ***\n", dwIsAppContainer ? "YES" : "NO");
  }

  CloseHandle(hToken);
}

// Create a security descriptor that allows AppContainer access
PSECURITY_DESCRIPTOR CreateAppContainerAccessibleSD()
{
  PSECURITY_DESCRIPTOR pSD = nullptr;

  // SDDL string that grants:
  // - Generic All access to the current user (GA)
  // - Generic Read/Write access to ALL APPLICATION PACKAGES (AC) - AppContainer processes
  // S-1-15-2-1 is the well-known SID for ALL APPLICATION PACKAGES
  LPCWSTR sddl = L"D:(A;;GA;;;WD)(A;;GRGW;;;AC)";

  if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
    sddl,
    SDDL_REVISION_1,
    &pSD,
    nullptr))
  {
    printf("Failed to create security descriptor. Error: %lu\n", GetLastError());
    return nullptr;
  }

  return pSD;
}

bool SendMessage(HANDLE hPipe, const char* message)
{
  DWORD bytesWritten;
  DWORD messageLen = (DWORD)strlen(message) + 1;

  printf("[Parent] Sending: %s\n", message);

  if (!WriteFile(hPipe, message, messageLen, &bytesWritten, nullptr))
  {
    printf("[Parent] Failed to write to pipe. Error: %lu\n", GetLastError());
    return false;
  }

  return true;
}

bool ReceiveMessage(HANDLE hPipe, char* buffer, DWORD bufferSize)
{
  DWORD bytesRead;

  if (!ReadFile(hPipe, buffer, bufferSize, &bytesRead, nullptr))
  {
    printf("[Parent] Failed to read from pipe. Error: %lu\n", GetLastError());
    return false;
  }

  printf("[Parent] Received: %s\n", buffer);
  return true;
}

int main()
{
  printf("=== IPC Demo - Parent Process ===\n");
  printf("[Parent] Starting...\n");

  // Display security information
  printf("\n[Parent] === Security Context Information ===\n");
  DisplayProcessSecurityInfo();
  printf("[Parent] ==========================================\n\n");

  // Create security attributes for the pipe
  SECURITY_ATTRIBUTES sa = { 0 };
  sa.nLength = sizeof(SECURITY_ATTRIBUTES);
  sa.lpSecurityDescriptor = CreateAppContainerAccessibleSD();
  sa.bInheritHandle = FALSE;

  if (sa.lpSecurityDescriptor == nullptr)
  {
    printf("[Parent] Failed to create security descriptor\n");
    return 1;
  }

  // Create named pipe BEFORE launching child process
  printf("[Parent] Creating named pipe: %ls\n", PIPE_NAME);

  HANDLE hPipe = CreateNamedPipeW(
    PIPE_NAME,
    PIPE_ACCESS_DUPLEX,
    PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
    1,
    BUFFER_SIZE,
    BUFFER_SIZE,
    0,
    &sa);

  if (hPipe == INVALID_HANDLE_VALUE)
  {
    printf("[Parent] Failed to create named pipe. Error: %lu\n", GetLastError());
    LocalFree(sa.lpSecurityDescriptor);
    return 1;
  }

  printf("[Parent] Named pipe created successfully\n");

  // Create or get AppContainer profile for the child process
  PSID pAppContainerSid = nullptr;
  HRESULT hr = CreateAppContainerProfile(
    APPCONTAINER_NAME,
    L"IPC Demo Child AppContainer",
    L"Sandboxed child process for IPC demonstration",
    nullptr,  // No capabilities for now
    0,
    &pAppContainerSid);

  if (FAILED(hr) && hr != HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS))
  {
    printf("[Parent] Failed to create AppContainer profile. HRESULT: 0x%08X\n", hr);
    CloseHandle(hPipe);
    LocalFree(sa.lpSecurityDescriptor);
    return 1;
  }

  // If already exists, get the SID
  if (hr == HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS))
  {
    hr = DeriveAppContainerSidFromAppContainerName(APPCONTAINER_NAME, &pAppContainerSid);
    if (FAILED(hr))
    {
      printf("[Parent] Failed to get AppContainer SID. HRESULT: 0x%08X\n", hr);
      CloseHandle(hPipe);
      LocalFree(sa.lpSecurityDescriptor);
      return 1;
    }
  }

  printf("[Parent] AppContainer profile created/retrieved successfully\n");

  // Set up security capabilities for the AppContainer
  SECURITY_CAPABILITIES securityCapabilities = { 0 };
  securityCapabilities.AppContainerSid = pAppContainerSid;
  securityCapabilities.Capabilities = nullptr;
  securityCapabilities.CapabilityCount = 0;
  securityCapabilities.Reserved = 0;

  // Set up process attribute list
  SIZE_T attributeListSize = 0;
  InitializeProcThreadAttributeList(nullptr, 1, 0, &attributeListSize);

  LPPROC_THREAD_ATTRIBUTE_LIST pAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(
    GetProcessHeap(), 0, attributeListSize);

  if (!pAttributeList)
  {
    printf("[Parent] Failed to allocate attribute list\n");
    FreeSid(pAppContainerSid);
    CloseHandle(hPipe);
    LocalFree(sa.lpSecurityDescriptor);
    return 1;
  }

  if (!InitializeProcThreadAttributeList(pAttributeList, 1, 0, &attributeListSize))
  {
    printf("[Parent] Failed to initialize attribute list. Error: %lu\n", GetLastError());
    HeapFree(GetProcessHeap(), 0, pAttributeList);
    FreeSid(pAppContainerSid);
    CloseHandle(hPipe);
    LocalFree(sa.lpSecurityDescriptor);
    return 1;
  }

  if (!UpdateProcThreadAttribute(
    pAttributeList,
    0,
    PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
    &securityCapabilities,
    sizeof(securityCapabilities),
    nullptr,
    nullptr))
  {
    printf("[Parent] Failed to update proc thread attribute. Error: %lu\n", GetLastError());
    DeleteProcThreadAttributeList(pAttributeList);
    HeapFree(GetProcessHeap(), 0, pAttributeList);
    FreeSid(pAppContainerSid);
    CloseHandle(hPipe);
    LocalFree(sa.lpSecurityDescriptor);
    return 1;
  }

  // NOW launch the child process
  STARTUPINFOW si = { 0 };
  PROCESS_INFORMATION pi = { 0 };
  si.cb = sizeof(si);

  // Use STARTUPINFOEX to pass the attribute list
  STARTUPINFOEXW siex = { 0 };
  siex.StartupInfo.cb = sizeof(STARTUPINFOEXW);
  siex.lpAttributeList = pAttributeList;

  // Get the current module path to find the child exe
  wchar_t modulePath[MAX_PATH];
  GetModuleFileNameW(nullptr, modulePath, MAX_PATH);

  // Remove the exe name to get just the directory
  wchar_t* lastSlash = wcsrchr(modulePath, L'\\');
  if (lastSlash)
  {
    *(lastSlash + 1) = L'\0';
  }

  // Construct full path to child executable
  wchar_t cmdLine[MAX_PATH];
  swprintf_s(cmdLine, MAX_PATH, L"\"%sdemo_child.exe\"", modulePath);

  printf("[Parent] Launching child process: %ls\n", cmdLine);

  if (!CreateProcessW(
    nullptr,
    cmdLine,
    nullptr,
    nullptr,
    FALSE,
    EXTENDED_STARTUPINFO_PRESENT | CREATE_NEW_CONSOLE,  // Use extended startup info
    nullptr,
    nullptr,
    &siex.StartupInfo,  // Use the extended startup info
    &pi))
  {
    printf("[Parent] Failed to create child process. Error: %lu\n", GetLastError());
    DeleteProcThreadAttributeList(pAttributeList);
    HeapFree(GetProcessHeap(), 0, pAttributeList);
    FreeSid(pAppContainerSid);
    CloseHandle(hPipe);
    LocalFree(sa.lpSecurityDescriptor);
    return 1;
  }

  printf("[Parent] Child process created. PID: %lu\n", pi.dwProcessId);

  // Clean up attribute list and AppContainer SID
  DeleteProcThreadAttributeList(pAttributeList);
  HeapFree(GetProcessHeap(), 0, pAttributeList);
  FreeSid(pAppContainerSid);
  // Clean up security descriptor - no longer needed
  LocalFree(sa.lpSecurityDescriptor);

  // Wait for child to connect to the pipe
  printf("[Parent] Waiting for child to connect...\n");

  if (!ConnectNamedPipe(hPipe, nullptr))
  {
    DWORD error = GetLastError();
    if (error != ERROR_PIPE_CONNECTED)
    {
      printf("[Parent] Failed to connect to pipe. Error: %lu\n", error);
      CloseHandle(hPipe);
      TerminateProcess(pi.hProcess, 1);
      CloseHandle(pi.hProcess);
      CloseHandle(pi.hThread);
      return 1;
    }
  }

  printf("[Parent] Child connected to pipe\n");

  char buffer[BUFFER_SIZE];

  // Send first message
  if (!SendMessage(hPipe, "Hello from parent!"))
  {
    CloseHandle(hPipe);
    TerminateProcess(pi.hProcess, 1);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return 1;
  }

  // Receive response
  if (!ReceiveMessage(hPipe, buffer, BUFFER_SIZE))
  {
    CloseHandle(hPipe);
    TerminateProcess(pi.hProcess, 1);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return 1;
  }

  // Send second message
  if (!SendMessage(hPipe, "This is message number 2"))
  {
    CloseHandle(hPipe);
    TerminateProcess(pi.hProcess, 1);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return 1;
  }

  // Receive response
  if (!ReceiveMessage(hPipe, buffer, BUFFER_SIZE))
  {
    CloseHandle(hPipe);
    TerminateProcess(pi.hProcess, 1);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return 1;
  }

  // Send exit message
  printf("[Parent] Sending exit command\n");
  SendMessage(hPipe, "EXIT");

  // Close pipe
  printf("[Parent] Closing pipe\n");
  FlushFileBuffers(hPipe);
  DisconnectNamedPipe(hPipe);
  CloseHandle(hPipe);

  // Wait for child to exit (wait indefinitely for user to close child console)
  printf("[Parent] Waiting for child process to exit...\n");
  printf("[Parent] (Child console is waiting for user input - press Enter in child window)\n");
  WaitForSingleObject(pi.hProcess, INFINITE);

  DWORD exitCode;
  GetExitCodeProcess(pi.hProcess, &exitCode);
  printf("[Parent] Child process exited with code: %lu\n", exitCode);

  CloseHandle(pi.hProcess);
  CloseHandle(pi.hThread);

  printf("[Parent] Parent process exiting\n");

  // Wait for user input before closing the parent console
  printf("\n[Parent] *** Press Enter to close this window... ***\n");
  getchar();

  return 0;
}
