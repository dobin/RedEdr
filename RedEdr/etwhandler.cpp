
#include <windows.h>
#include <evntrace.h>
#include <tdh.h>
#include <iostream>
#include <vector>
#include <string>
#include <iomanip>
#include <sstream>

#include "output.h"
#include "etwhandler.h"
#include "config.h"
#include "cache.h"


void WINAPI EventRecordCallbackSecurityAuditing(PEVENT_RECORD eventRecord)
{
    // Display the event ID and its name
    //std::wcout << L"SecurityEvent " << pEventRecord->EventHeader.EventDescriptor.Id << L" received." << std::endl;

    PrintProperties(L"SecurityEvents", eventRecord);


    // 4688: new process
    // 4689: exit process
}


void WINAPI EventRecordCallbackKernelProcess(PEVENT_RECORD eventRecord) {
    std::wstring eventName;

    if (eventRecord == nullptr) {
        return;
    }

    // Do we want to track this process?
    DWORD processId = eventRecord->EventHeader.ProcessId;
    if (!g_cache.observe(processId)) {
        return;
    }

    switch (eventRecord->EventHeader.EventDescriptor.Id) {
    case 1:  // Process Start
        eventName = L"StartProcess";
        break;
    case 3:  // Thread Start
        eventName = L"StartThread";
        break;
    case 5:  // Image Load
        eventName = L"LoadImage";
        break;
    default:
        if (g_config.log_unload) {
            switch (eventRecord->EventHeader.EventDescriptor.Id) {
            case 2:  // Process Stop
                eventName = L"StopProcess";
                break;
            case 4:  // Thread Stop
                eventName = L"StopThread";
                break;
                break;
            case 6:  // Image Unload
                eventName = L"UnloadImage";
                break;
            default:
                // Ignore other events
                return;
            }
        }
        else {
            return;
        }
    }

    PrintProperties(eventName, eventRecord);
}


void WINAPI EventRecordCallbackAntimalwareEngine(PEVENT_RECORD eventRecord) {
    std::wstring eventName = L"engine";

    if (eventRecord == nullptr) {
        return;
    }
    switch (eventRecord->EventHeader.EventDescriptor.Id) {
    case 60:
        // test:60;ProviderName:Microsoft-Antimalware-Engine;PID:187076;Channel:ThreatIntel;EventId:19;
        return;
    }

    // Rest
    PrintProperties(eventName, eventRecord);
}


void WINAPI EventRecordCallbackAntimalwareRtp(PEVENT_RECORD eventRecord) {
    std::wstring eventName = L"rtp";

    if (eventRecord == nullptr) {
        return;
    }
    switch (eventRecord->EventHeader.EventDescriptor.Id) {
    case 22:
        // test:22;ProviderName:Microsoft-Antimalware-RTP;Description:AsyncWorkerUpdate;PreviousValue:8;IntendedValueOrHResult:0;LatestValue:8;
        // test:22;ProviderName:Microsoft-Antimalware-RTP;Description:RevertPriorityOK;PreviousValue:8;IntendedValueOrHResult:14;LatestValue:14;
        return;
    }

    // Rest
    PrintProperties(eventName, eventRecord);
}


void WINAPI EventRecordCallbackPrintAll(PEVENT_RECORD eventRecord) {
    std::wstring eventName = L"test";

    if (eventRecord == nullptr) {
        return;
    }

    // All
    PrintProperties(eventName, eventRecord);
}


void PrintProperties(std::wstring eventName, PEVENT_RECORD eventRecord) {
    DWORD bufferSize = 0;
    PTRACE_EVENT_INFO eventInfo = NULL;
    TDHSTATUS status = TdhGetEventInformation(eventRecord, 0, NULL, eventInfo, &bufferSize);
    if (status == ERROR_INSUFFICIENT_BUFFER) {
        eventInfo = (PTRACE_EVENT_INFO)malloc(bufferSize);
        status = TdhGetEventInformation(eventRecord, 0, NULL, eventInfo, &bufferSize);
    }
    if (ERROR_SUCCESS != status) {
        if (eventInfo) {
            free(eventInfo);
        }
        return;
    }

    // String stream to accumulate output
    std::wstringstream output;
    output << L"type:etw;time:" << static_cast<__int64>(eventRecord->EventHeader.TimeStamp.QuadPart) << L";";
    output << L"pid:" << eventRecord->EventHeader.ProcessId << L";";
    output << L"thread_id:" << eventRecord->EventHeader.ThreadId << L";";
    output << L"event:" << eventName << L";";

    //output << L"EventID:" << eventRecord->EventHeader.EventDescriptor.Id << L";";
    output << L"provider_name:" << (eventInfo->ProviderNameOffset ? (PCWSTR)((PBYTE)eventInfo + eventInfo->ProviderNameOffset) : L"Unknown") << L";";

    for (DWORD i = 0; i < eventInfo->TopLevelPropertyCount; i++) {
        PROPERTY_DATA_DESCRIPTOR dataDescriptor;
        dataDescriptor.PropertyName = (ULONGLONG)((PBYTE)eventInfo + eventInfo->EventPropertyInfoArray[i].NameOffset);
        dataDescriptor.ArrayIndex = ULONG_MAX;

        bufferSize = 0;
        status = TdhGetPropertySize(eventRecord, 0, NULL, 1, &dataDescriptor, &bufferSize);
        if (status != ERROR_SUCCESS) {
            continue;
        }

        std::vector<BYTE> propertyBuffer(bufferSize);
        status = TdhGetProperty(eventRecord, 0, NULL, 1, &dataDescriptor, bufferSize, propertyBuffer.data());
        if (status != ERROR_SUCCESS) {
            continue;
        }

        output << reinterpret_cast<PCWSTR>((PBYTE)eventInfo + eventInfo->EventPropertyInfoArray[i].NameOffset) << L":";

        switch (eventInfo->EventPropertyInfoArray[i].nonStructType.InType) {
        case TDH_INTYPE_UINT32:
            output << *reinterpret_cast<PULONG>(propertyBuffer.data()) << L";";
            break;
        case TDH_INTYPE_UINT64:
            output << *reinterpret_cast<PULONG64>(propertyBuffer.data()) << L";";
            break;
        case TDH_INTYPE_UNICODESTRING:
            output << reinterpret_cast<PCWSTR>(propertyBuffer.data()) << L";";
            break;
        case TDH_INTYPE_ANSISTRING:
            output << reinterpret_cast<PCSTR>(propertyBuffer.data()) << L";";
            break;
        case TDH_INTYPE_POINTER:  // hex
            output << L"0x" << reinterpret_cast<PVOID>(propertyBuffer.data()) << L";";
            break;
        case TDH_INTYPE_FILETIME:
        {
            FILETIME fileTime = *reinterpret_cast<PFILETIME>(propertyBuffer.data());
            SYSTEMTIME stUTC, stLocal;
            FileTimeToSystemTime(&fileTime, &stUTC);
            SystemTimeToTzSpecificLocalTime(NULL, &stUTC, &stLocal);
            output << stLocal.wYear << L"/" << stLocal.wMonth << L"/" << stLocal.wDay << L" "
                << stLocal.wHour << L":" << stLocal.wMinute << L":" << stLocal.wSecond << L";";
            break;
        }
        default:
            output << L"(Unknown type);";
            break;
        }
    }

    // Free the event information structure
    if (eventInfo) {
        free(eventInfo);
    }
    do_output(output.str());
    // Print the accumulated string
    //std::wcout << output.str() << L"\n";
    //fflush(stdout);
}