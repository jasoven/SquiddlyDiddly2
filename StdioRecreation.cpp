#include "VxHeader.h"

static unsigned long int OffsetNext = 1;

VOID VxZeroMemory(PVOID Destination, SIZE_T Size)
{
	PULONG Dest = (PULONG)Destination;
	SIZE_T Count = Size / sizeof(ULONG);

	while (Count > 0)
	{
		*Dest = 0;
		Dest++;
		Count--;
	}

	return;
}

SIZE_T VxStringLength(LPCWSTR String)
{
	LPCWSTR String2;

	for (String2 = String; *String2; ++String2);

	return (String2 - String);
}

INT VxPseudoRandom(VOID)
{
	OffsetNext = OffsetNext * 1103515245 + 12345;
	return (DWORD32)(OffsetNext / 65536) % 32768;
}

PWCHAR VxStringCopyW(PWCHAR String1, PWCHAR String2)
{
	PWCHAR p = String1;

	while ((*p++ = *String2++) != 0);

	return String1;
}

PWCHAR VxStringConcatW(PWCHAR String, PWCHAR String2)
{
	VxStringCopyW(&String[VxStringLength(String)], String2);

	return String;
}

PVOID VxCopyMemory(PVOID Destination, CONST PVOID Source, SIZE_T Length)
{
	PBYTE D = (PBYTE)Destination;
	PBYTE S = (PBYTE)Source;

	while (Length--)
		*D++ = *S++;

	return Destination;
}

DWORD VxDecimalToAsciiW(PWCHAR String, LPDWORD dwArray, DWORD dwLength)
{
	DWORD dwX = ERROR_SUCCESS;

	if (String == NULL)
		return dwX;

	for (; dwX < dwLength; dwX++) { String[dwX] = (WCHAR)dwArray[dwX]; }

	return dwX;
}

PWCHAR VxStringTokenW(PWCHAR String, CONST PWCHAR Delim)
{
	PWCHAR Last;
	PWCHAR SpanP, Token;
	INT C, SC;

	if (String == NULL)
		return NULL;

CONTINUE:

	C = *String++;

	for (SpanP = (PWCHAR)Delim; (SC = *SpanP++) != ERROR_SUCCESS;)
	{
		if (C == SC)
			goto CONTINUE;
	}

	if (C == ERROR_SUCCESS) { Last = NULL; return NULL; }

	Token = String - 1;

	for (;;)
	{
		C = *String++;
		SpanP = (PWCHAR)Delim;

		do {
			if ((SC = *SpanP++) == C)
			{
				if (C == ERROR_SUCCESS)
					String = NULL;
				else
					String[-1] = '\0';

				Last = String;
				return Token;
			}
		} while (SC != ERROR_SUCCESS);
	}

	return NULL;

}

PWCHAR VxCapString(PWCHAR Ptr)
{
	PWCHAR sv = Ptr;
	while (*sv != '\0')
	{
		if (*sv >= 'a' && *sv <= 'z')
			*sv = *sv - ('a' - 'A');

		sv++;
	}
	return Ptr;
}

INT VxStringCompare(LPCWSTR String1, LPCWSTR String2)
{
	for (; *String1 == *String2; String1++, String2++)
	{
		if (*String1 == '\0')
			return 0;
	}

	return ((*(LPCWSTR)String1 < *(LPCWSTR)String2) ? -1 : +1);
}

PWCHAR VxSecureStringCopy(PWCHAR String1, LPCWSTR String2, SIZE_T Size)
{
	PWCHAR pChar = String1;

	while (Size-- && (*String1++ = *String2++) != '\0');

	return pChar;
}