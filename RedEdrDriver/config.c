
#include "config.h"
#include <ntddk.h>
#include <string.h>
#include <stdio.h>

Config g_Config;


void init_config() {
	g_Config.init_processnotify = 1;
	g_Config.init_threadnotify = 1;
	g_Config.init_imagenotify = 1;
	g_Config.init_obnotify = 0; // too much data, no parser

	g_Config.enable_kapc_injection = 0;
	g_Config.enable_logging = 0;

	g_Config.trace_pid = 0;
	g_Config.trace_children = 0;

	wcscpy_s(g_Config.target, TARGET_WSTR_LEN, L""); // disable
}


void print_config() {

}