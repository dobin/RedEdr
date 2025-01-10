#include <stdio.h>
#include <Windows.h>

#include "../Shared/common.h"
#include "piping.h"
#include "logging.h"


// The pipe to RedEdr.exe
// Read first message as config,
// then send all the data
PipeClient pipeClient;


BOOL ConnectEmitterPipe() {
    LOG_W(LOG_INFO, L"Emitter: Connect pipe %s to RedEdr", DLL_PIPE_NAME);
    if (!pipeClient.Connect(DLL_PIPE_NAME)) {
        LOG_W(LOG_ERROR, L"Emitter not connect to RedEdr.exe at %s because %ld", 
            DLL_PIPE_NAME, GetLastError());
        return FALSE;
    }

    // Retrieve config (first packet)
    // this is the only read for this pipe
    char buffer[PPL_CONFIG_LEN];
    if (pipeClient.Receive(buffer, PPL_CONFIG_LEN)) {
        // Ignore config atm
    }

    return TRUE;
}


void SendEmitterPipe(char* buffer) {
    pipeClient.Send(buffer);
}


void DisconnectEmitterPipe() {
    LOG_W(LOG_INFO, L"Emitter: Disconnect pipe %s to RedEdr", DLL_PIPE_NAME);
    pipeClient.Disconnect();
}
