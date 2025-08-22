#pragma once

#include <windows.h>

#define MESSAGE_SIZE 1024
#define MAX_PATH 260

BOOL remote_inject(DWORD target_pid);