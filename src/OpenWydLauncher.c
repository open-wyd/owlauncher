#include <string.h>
#include <stdio.h>
#include <winsock2.h>

#define		MAX_SERVER				10      // Max number of game servers that can connect to DB server
#define		MAX_SERVERGROUP			10		// Max number of servers that can exist
#define		MAX_SERVERNUMBER		(MAX_SERVER+1) // DB + TMSrvs

char g_pServerList[MAX_SERVERGROUP][MAX_SERVERNUMBER][64];

#ifdef __DEBUG__
void DumpServerlist()
{
	FILE *fpBin = fopen("./serverlist.bin", "rb");

	if (fpBin == NULL)
		return;

	memset(g_pServerList, 0, sizeof(g_pServerList));

	fread(g_pServerList, MAX_SERVERGROUP*MAX_SERVERNUMBER, 64, fpBin);
	fclose(fpBin);

	int szList[64] = {
		0xA4, 0xA1, 0xA4, 0xA4, 0xA4, 0xA7, 0xA4, 0xA9, 0xA4, 0xB1, 0xA4, 0xB2, 0xA4, 0xB5, 0xA4, 0xB7,
		0xA4, 0xB8, 0xA4, 0xBA, 0xA4, 0xBB, 0xA4, 0xBC, 0xA4, 0xBD, 0xA4, 0xBE, 0xA4, 0xBF, 0xA4, 0xC1,
		0xA4, 0xC3, 0xA4, 0xC5, 0xA4, 0xC7, 0xA4, 0xCB, 0xA4, 0xCC, 0xA4, 0xD0, 0xA4, 0xD1, 0xA4, 0xD3,
		0xA4, 0xBF, 0xA4, 0xC4, 0xA4, 0xD3, 0xA4, 0xC7, 0xA4, 0xCC, 0xB0, 0xA1, 0xB3, 0xAA, 0xB4, 0xD9
	};

	for (int k = 0; k < MAX_SERVERGROUP; k++)
	{
		for (int j = 0; j < MAX_SERVERNUMBER; j++)
		{
			for (int i = 0; i < 64; i++)
			{
				g_pServerList[k][j][i] -= szList[63 - i];

			}
		}
	}

	fpBin = fopen("./serverlist_dump.bin", "w");

	if (fpBin == NULL)
	{
		memset(g_pServerList, 0, sizeof(g_pServerList));
		return;
	}

	fwrite(g_pServerList, MAX_SERVERGROUP*MAX_SERVERNUMBER, 64, fpBin);
	fclose(fpBin);

	memset(g_pServerList, 0, sizeof(g_pServerList));
}

#else
#define DumpServerlist()
#endif

BOOL Initialize()
{
	WSADATA wsaData;
	int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
	
	if (iResult)
		printf("WSAStartup failed: %d\n", iResult);

	memset(g_pServerList, 0, sizeof(g_pServerList));

	DumpServerlist();

	return iResult == 0;
}

void ShowError()
{
	DWORD wsaErrorId = WSAGetLastError();
	DWORD errorId = GetLastError();

	if (wsaErrorId == WSAHOST_NOT_FOUND) {
		printf("Host not found\n");
	}
	else if (wsaErrorId == WSANO_DATA) {
		printf("No data record found\n");
	}
	
	if(wsaErrorId || errorId)
		printf("Function failed with error: %ld/%ld\n", wsaErrorId, errorId);

	system("pause");
}

//--------------------------------------------------------------------------
// Serverlist                                                              -
//--------------------------------------------------------------------------

BOOL SetChannelUrl(int svId, const char* channelUrl)
{
	if (svId < 0 || svId > MAX_SERVERGROUP)
		return FALSE;

	strcpy(g_pServerList[svId][0], channelUrl);

	return TRUE;
}

BOOL SetChannelHost(int svId, int chId, const char* channelHostName)
{
	if (chId <= 0)
		return FALSE;

	struct hostent* remoteHost = gethostbyname(channelHostName);

	if (remoteHost == NULL)
		return FALSE;

	sprintf(g_pServerList[svId][chId], "%s:%d", inet_ntoa(*(struct in_addr*)remoteHost->h_addr_list[0]), ((svId * MAX_SERVERNUMBER + chId) + 8269 + 1));

	return TRUE;
}

BOOL CreateServerList()
{
	SetChannelUrl(0, "http://openwyd.com.br/online/serverlist.php?sv=1");
	SetChannelUrl(1, "http://openwyd.com.br/online/serverlist.php?sv=1");
	SetChannelUrl(2, "http://openwyd.com.br/online/serverlist.php?sv=1");
	if (!SetChannelHost(1, 1, "test-server.openwyd.com.br"))
		ShowError();

	if (!SetChannelHost(1, 2, "test-server.openwyd.com.br"))
		ShowError();

	if (!SetChannelHost(1, 3, "test-server.openwyd.com.br"))
		ShowError();

	FILE *fpBin = fopen("./serverlist.bin", "wb");

	if (fpBin != NULL)
	{
		int szList[64] = {
			0xA4, 0xA1, 0xA4, 0xA4, 0xA4, 0xA7, 0xA4, 0xA9, 0xA4, 0xB1, 0xA4, 0xB2, 0xA4, 0xB5, 0xA4, 0xB7,
			0xA4, 0xB8, 0xA4, 0xBA, 0xA4, 0xBB, 0xA4, 0xBC, 0xA4, 0xBD, 0xA4, 0xBE, 0xA4, 0xBF, 0xA4, 0xC1,
			0xA4, 0xC3, 0xA4, 0xC5, 0xA4, 0xC7, 0xA4, 0xCB, 0xA4, 0xCC, 0xA4, 0xD0, 0xA4, 0xD1, 0xA4, 0xD3,
			0xA4, 0xBF, 0xA4, 0xC4, 0xA4, 0xD3, 0xA4, 0xC7, 0xA4, 0xCC, 0xB0, 0xA1, 0xB3, 0xAA, 0xB4, 0xD9
		};

		for (int k = 0; k < MAX_SERVERGROUP; k++)
		{
			for (int j = 0; j < MAX_SERVERNUMBER; j++)
			{
				for (int i = 0; i < 64; i++)
				{
					g_pServerList[k][j][i] += szList[63 - i];

				}
			}
		}

		fwrite(g_pServerList, MAX_SERVERGROUP*MAX_SERVERNUMBER, 64, fpBin);
		fclose(fpBin);
	}

	return TRUE;
}
//--------------------------------------------------------------------------

//--------------------------------------------------------------------------
// Manipulations of the WYD client                                         -
//--------------------------------------------------------------------------
DWORD InitializeProcess(const char* ApplicationName)
{
	/// CreateProcess API initialization
	STARTUPINFOA siStartupInfo;
	PROCESS_INFORMATION piProcessInfo;
	memset(&siStartupInfo, 0, sizeof(siStartupInfo));
	memset(&piProcessInfo, 0, sizeof(piProcessInfo));
	siStartupInfo.cb = sizeof(siStartupInfo);
	DWORD dwExitCode = -1;

	if (!CreateProcess(ApplicationName, NULL, 0, 0, FALSE, 0, 0, 0, &siStartupInfo, &piProcessInfo))
	{
		ShowError();
		return -1;
	}
	
	/// Watch the process.
	dwExitCode = WaitForSingleObject(piProcessInfo.hProcess, 100);

	/// Release handles
	CloseHandle(piProcessInfo.hProcess);
	CloseHandle(piProcessInfo.hThread);

	return piProcessInfo.dwProcessId;
}

BOOL Inject(DWORD pId, char *dllName)
{
	HANDLE h = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pId);
	if (!h)
	{
		ShowError();
		return FALSE;
	}

	LPVOID LoadLibAddr = (LPVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
	LPVOID dereercomp = VirtualAllocEx(h, NULL, strlen(dllName), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	WriteProcessMemory(h, dereercomp, dllName, strlen(dllName), NULL);
	HANDLE asdc = CreateRemoteThread(h, NULL, 0, (LPTHREAD_START_ROUTINE)LoadLibAddr, dereercomp, 0, NULL);
	WaitForSingleObject(asdc, INFINITE);
	VirtualFreeEx(h, dereercomp, strlen(dllName), MEM_RELEASE);
	CloseHandle(asdc);
	CloseHandle(h);
	
	return TRUE;
}
//--------------------------------------------------------------------------

int main()
{
	if (!Initialize())
		ShowError();

	CreateServerList();

	char lpBuffer[512];
	memset(lpBuffer, 0, sizeof(lpBuffer));
	GetCurrentDirectory(sizeof(lpBuffer), lpBuffer);

	// Open the WYD client
	DWORD pId = InitializeProcess(strncat(lpBuffer, "\\WYD.exe", sizeof(lpBuffer)));
	if (pId <= 0)
	{
		printf("Error on Initialize WYD.exe\n");
		return 0;
	}

	memset(lpBuffer, 0, sizeof(lpBuffer));
	GetCurrentDirectory(sizeof(lpBuffer), lpBuffer);

	// Inject OWSClient.dll
	Inject(pId, strncat(lpBuffer, "\\OWSClient.dll", sizeof(lpBuffer)));

    return 0;
}
