#pragma once

#include <Ntifs.h>
#include <ntddk.h>
#include <wdf.h>
#include <string.h>
#include <stdio.h>
#include <fltkernel.h>

int log_event(wchar_t*);
void close_pipe();
int open_pipe();