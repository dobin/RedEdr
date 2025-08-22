
#include "settings.h"


Settings g_Settings;


void init_settings() {
	g_Settings.init_processnotify = 1;
	g_Settings.init_threadnotify = 1;
	g_Settings.init_imagenotify = 1;
	g_Settings.init_obnotify = 0; // too much data, no parser

	g_Settings.enable_kapc_injection = 0;
	g_Settings.enable_logging = 0;

	g_Settings.trace_pid = 0;
	g_Settings.trace_children = 0;

	wcscpy_s(g_Settings.target, TARGET_WSTR_LEN, L""); // disable
}


void print_settings() {

}
