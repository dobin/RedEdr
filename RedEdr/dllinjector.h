#pragma once

#include <stdio.h>
#include <windows.h>

#define MESSAGE_SIZE 2048
#define MAX_PATH 260

BOOL remote_inject(DWORD target_pid);