#pragma once

#include <stdio.h>
#include <Windows.h>

void SendEmitterPipe(wchar_t* buffer);
BOOL ConnectEmitterPipe();
void DisconnectEmitterPipe();
