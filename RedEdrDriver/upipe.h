#pragma once

// Function declarations
void InitializePipe();
void CleanupPipe();
int LogEvent(char*);
int IsUserspacePipeConnected();
void DisconnectUserspacePipe();
int ConnectUserspacePipe();