#pragma once
#include <ntddk.h>
#include <string.h>
#include <stdio.h>

#include "../Shared/common.h"

typedef struct _config {
	int init_processnotify;
	int init_threadnotify;
	int init_imagenotify;
	int init_obnotify;

	int enable_kapc_injection;
	int enable_logging;

	HANDLE trace_pid;
	int trace_children;
	WCHAR target[TARGET_WSTR_LEN];  // zero length means disabled
} Config;


// Declare a global configuration instance
extern Config g_Config;

void init_config();
void print_config();