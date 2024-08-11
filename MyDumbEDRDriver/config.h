#pragma once

typedef struct _config {
	int enable_processnotify;
	int enable_threadnotify;
	int enable_imagenotify;
	int enable_obnotify;
} Config;


// Declare a global configuration instance
extern Config g_config;

void init_config();
void print_config();