#pragma once

#include <Ntifs.h>
#include <ntddk.h>
#include <wdf.h>
#include <string.h>
#include <fltkernel.h>

// Function declarations
void InitializePipe();
void CleanupPipe();
int LogEvent(char*);
int IsUserspacePipeConnected();
void DisconnectUserspacePipe();
int ConnectUserspacePipe();