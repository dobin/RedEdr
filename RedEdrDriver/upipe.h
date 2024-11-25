#pragma once

#include <Ntifs.h>
#include <ntddk.h>
#include <wdf.h>
#include <string.h>
#include <stdio.h>
#include <fltkernel.h>

int LogEvent(wchar_t*);
int IsUserspacePipeConnected();
void DisconnectUserspacePipe();
int ConnectUserspacePipe();