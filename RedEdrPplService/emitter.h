#pragma once

#include <stdio.h>
#include <Windows.h>

void SendEmitterPipe(char* buffer);
BOOL ConnectEmitterPipe();
void DisconnectEmitterPipe();
