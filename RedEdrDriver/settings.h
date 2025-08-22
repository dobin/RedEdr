#pragma once

#include <ntddk.h>

#include "../Shared/common.h"

typedef struct _Settings{
	int init_processnotify;
	int init_threadnotify;
	int init_imagenotify;
	int init_obnotify;

	int enable_kapc_injection;
	int enable_logging;

	HANDLE trace_pid;
	int trace_children;
	WCHAR target[TARGET_WSTR_LEN];  // zero length means disabled
} Settings;


// Declare a global configuration instance
extern Settings g_Settings;

void init_settings();
void print_settings();