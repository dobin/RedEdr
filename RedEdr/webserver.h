#pragma once

#include <Windows.h>
#include <vector>

DWORD WINAPI WebserverThread(LPVOID param);
int InitializeWebServer(std::vector<HANDLE>& threads, int port);
void StopWebServer();
