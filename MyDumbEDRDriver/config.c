
#include "config.h"
#include <ntddk.h>
#include <string.h>
#include <stdio.h>

Config g_config;


void init_config() {
	g_config.enable_processnotify = 1;
	g_config.enable_threadnotify = 1;
	g_config.enable_imagenotify = 1;
	g_config.enable_obnotify = 1;

	//HANDLE pid = 0;
}


void print_config() {

}