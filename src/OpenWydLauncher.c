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

BOOL CreateServerList()
{
	FILE *fpBin = fopen("./serverlist.bin", "w");

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

BOOL Initialize()
{
	WSADATA wsaData;
	int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
	
	if (iResult)
		printf("WSAStartup failed: %d\n", iResult);

	DumpServerlist();

	return iResult == 0;
}

BOOL SetChannelUrl(int svId, const char* channelUrl)
{
	if (svId < 0 || svId > MAX_SERVERGROUP)
		return FALSE;

	strcpy(g_pServerList[svId][0], channelUrl);

	return TRUE;
}

BOOL SetChannelHost(int svId, int chid, const char* channelHostName)
{
	if (chid <= 0)
		return FALSE;

	struct in_addr addr;
	struct hostent* remoteHost = gethostbyname(channelHostName);

	if (remoteHost == NULL)
		return FALSE;

	addr.s_addr = *(u_long *)remoteHost->h_addr_list[0];

	strcpy(g_pServerList[svId][chid], inet_ntoa(addr));

	return TRUE;
}

void ShowError()
{
	DWORD dwError = WSAGetLastError();
	if (dwError != 0) {
		if (dwError == WSAHOST_NOT_FOUND) {
			printf("Host not found\n");
		}
		else if (dwError == WSANO_DATA) {
			printf("No data record found\n");
		}
		else {
			printf("Function failed with error: %ld\n", dwError);
		}
	}
}

int main()
{
	if (!Initialize())
		ShowError();

	SetChannelUrl(1, "http://openwyd.com.br/online/serverlist.php?sv=1");
	if (!SetChannelHost(1, 1, "test-server.openwyd.com.br"))
		ShowError();

	CreateServerList();

	ShellExecute(NULL, L"open", L"WYD.exe", NULL, NULL, SW_SHOWDEFAULT);

    return 0;
}
