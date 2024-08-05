
#pragma once



void WINAPI EventRecordCallbackSecurityAuditing(PEVENT_RECORD pEventRecord);
void WINAPI EventRecordCallbackKernelProcess(PEVENT_RECORD eventRecord);
void WINAPI EventRecordCallbackAntimalwareEngine(PEVENT_RECORD eventRecord);
void WINAPI EventRecordCallbackAntimalwareRtp(PEVENT_RECORD eventRecord);
void WINAPI EventRecordCallbackPrintAll(PEVENT_RECORD eventRecord);

void PrintProperties(std::wstring eventName, PEVENT_RECORD eventRecord);
