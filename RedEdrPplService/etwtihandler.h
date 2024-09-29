#pragma once

#include <windows.h>
#include <evntrace.h>
#include <tdh.h>

void enable_consumer(BOOL e);
void WINAPI EventRecordCallbackTi(PEVENT_RECORD eventRecord);
void WINAPI EventRecordCallbackKernelProcess(PEVENT_RECORD eventRecord);
