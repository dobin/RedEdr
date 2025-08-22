#pragma once

#include <Windows.h>

void SendEmitterPipe(char* buffer);
BOOL ConnectEmitterPipe();
void DisconnectEmitterPipe();
