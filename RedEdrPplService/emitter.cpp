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
    wchar_t buffer[WCHAR_BUFFER_SIZE];
    if (pipeClient.Receive(buffer, WCHAR_BUFFER_SIZE)) {
        // Ignore config atm
    }

    return TRUE;
}


void SendEmitterPipe(wchar_t* buffer) {
    pipeClient.Send(buffer);
}


void DisconnectEmitterPipe() {
    LOG_W(LOG_INFO, L"Emitter: Disconnect pipe %s to RedEdr", DLL_PIPE_NAME);
    pipeClient.Disconnect();
}
