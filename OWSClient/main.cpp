#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "pe_hook.h"

void Log(const char* format, ...)
{
	va_list ap;
	va_start(ap, format);

	FILE* fLog = fopen("OWSClient.Log", "at");

	if (fLog)
	{
		// Timestamp
		time_t rtime;
		time(&rtime);
		char *timestamp = ctime(&rtime);
		timestamp[strlen(timestamp) - 1] = 0;

		fprintf(fLog, "[%s]", timestamp);
		fprintf(fLog, "\n|-----------------------------------------------------------------|\n");
		vfprintf(fLog, format, ap);
		fprintf(fLog, "\n|-----------------------------------------------------------------|\n");

		fclose(fLog);
	}

	va_end(ap);
}

SOCKET __stdcall HKD_connect(int _this, const char* address, u_short port, int localPort, u_int wMsg)
{
	// Applies the new data format to the channel address in serverlist.bin
	char* channelAddress = _strdup(address);
	u_short channelport = 0;

	char* token = strchr(channelAddress, ':');
	if (token)
	{
		*token++ = '\0';
		if (*token)
			channelport = atoi(token);
	}

	// If port is not defined, then is using old data format.
	// Fix to support old format.
	if (channelport == 0)
		channelport = port;

	Log("Connect: (%s:%d) %s:%d", address, port, channelAddress, channelport);
	
	// Call native functionality.
	SOCKET result = -1;
	__asm
	{
		PUSH 0x464
		PUSH 0
		PUSH DWORD PTR SS : [channelport]
		MOV EAX, DWORD PTR DS : [channelAddress]
		PUSH EAX
		MOV ECX, _this
		MOV EDX, 0x00424844
		CALL EDX

		MOV result, EAX
	}

	free(channelAddress);

	return result;
}

static INT32 reg_aux;
__declspec(naked) void NKD_Connect()
{
	__asm
	{
		POP reg_aux

		PUSH ECX

		PUSH reg_aux

		JMP HKD_connect
	}
}

int __stdcall DllMain(HINSTANCE hInstDLL, DWORD catchReason, LPVOID lpResrv)
{
	if (catchReason == DLL_PROCESS_ATTACH)
	{
		CALL_NEAR(0x00486439, NKD_Connect);
		CALL_NEAR(0x004B381E, NKD_Connect);
	}
	else if (catchReason == DLL_PROCESS_DETACH)
	{
		FreeLibrary(hInstDLL);
	}

	return TRUE;
}