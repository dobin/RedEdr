
#include <windows.h>
#include <evntrace.h>
#include <tdh.h>
#include <iostream>
#include <vector>
#include <string>
#include <iomanip>
#include <sstream>

#include "loguru.hpp"
#include "output.h"
#include "etwhandler.h"
#include "config.h"
#include "cache.h"


void WINAPI EventRecordCallbackSecurityAuditing(PEVENT_RECORD eventRecord)
{
    // Do we want to track this process?
    DWORD processId = eventRecord->EventHeader.ProcessId;
    if (!g_cache.observe(processId)) {
        return;
    }

    /* https://docs.google.com/spreadsheets/d/1d7hPRktxzYWmYtfLFaU_vMBKX2z98bci0fssTYyofdo/edit?gid=0#gid=0
    4624	An account was successfully logged on.
    4625	An account failed to log on.
    4627	Group membership information.
    4634	An account was logged off
    4647	User initiated logoff.
    4648	A logon was attempted using explicit credentials.
    4656	A handle to an object was requested.
    4657	A registry value was modified.
    4660	An object was deleted.
    4661	A handle to an object was requested.
    4662	An operation was performed on an object.
    4663	An attempt was made to access an object.
    4664	An attempt was made to create a hard link.
    4672	Special privileges assigned to new logon.
    4673	A privileged service was called.
    4674	An operation was attempted on a privileged object.
   x 4688	A new process has been created.
   x 4689	A process has exited.
    4690	An attempt was made to duplicate a handle to an object.
    4696	A primary token was assigned to process.
    4697	A service was installed in the system.
    4698	A scheduled task was created.
    4699	A scheduled task was deleted.
    4700	A scheduled task was enabled.
    4701	A scheduled task was disabled.
    4702	A scheduled task was updated.
    4703	A user right was adjusted.
    4741	A computer account was created.
    4742	A computer account was changed.
    4743	A computer account was deleted.
    4768	A Kerberos authentication ticket (TGT) was requested.
    4769	A Kerberos service ticket was requested.
    4770	A Kerberos service ticket was renewed.
    4771	Kerberos pre-authentication failed.
    4798	A user's local group membership was enumerated.
    5145	A network share object was checked to see whether client can be granted desired access.
    5379	Credential Manager credentials were read.
    */
    std::wstring event_name = L"";
    switch (eventRecord->EventHeader.EventDescriptor.Id) {
    case 4624:	
        event_name = L"AccountLogonSuccess";
        break;
    case 4625:	
        event_name = L"AccountLogonFail";
        break;
    case  4627:	
        event_name = L"GroupMembershipInformation.";
        break;
    case 4634:	
        event_name = L"AccountLogoff";
        break;
    case 4647:	
        event_name = L"UserLogoff";
        break;
    case 4648:	
        event_name = L"ExplicitLogon";
        break;
    case 4656:	
        event_name = L"ObjectHandleRequest";
        break;
    case 4657:	
        event_name = L"RegistryValueModified";
        break;
    case 4660:	
        event_name = L"ObjectDelete";
        break;
    case 4661:	
        event_name = L"ObjectHandleRequest";
        break;
    case 4662:	
        event_name = L"ObjectOperation";
        break;
    case 4663:	
        event_name = L"ObjectAccess";
        break;
    case 4664:	
        event_name = L"CreateHardLink";
        break;
    case 4672:	
        event_name = L"LogonSpecialPrivileges";
        break;
    case 4673:	
        event_name = L"PrivilegedServiceInstalled";
        break;
    case 4674:	
        event_name = L"PrivilegedObjectOperation";
        break;
    case 4688:	
        event_name = L"ProcessCreate";
        break;
    case 4689:	
        event_name = L"ProcessExit";
        break;
    case 4690:	
        event_name = L"ObjectHandleDuplicate";
        break;
    case 4696:	
        event_name = L"ProcessPrimaryTokenAssign";
        break;
    case 4697:	
        event_name = L"ServiceInstalled";
        break;
    case 4698:	
        event_name = L"ScheduledTaskCreate";
        break;
    case 4699:	
        event_name = L"ScheduledTaskDelete";
        break;
    case 4700:	
        event_name = L"ScheduledTaskEnable";
        break;
    case 4701:	
        event_name = L"ScheduledTaskDisable";
        break;
    case 4702:	
        event_name = L"ScheduledTaskUpdated";
        break;
    case 4703:	
        event_name = L"UserRightsAdjusted";
        break;
    case 4741:	
        event_name = L"ComputerAccountCreated";
        break;
    case 4742:	
        event_name = L"ComputerAccountChanged";
        break;
    case 4743:	
        event_name = L"ComputerAccountDeleted";
        break;
    case 4768:	
        event_name = L"KerberosTgtRequest";
        break;
    case 4769:	
        event_name = L"KerberosServiceTicketRequest";
        break;
    case 4770:	
        event_name = L"KerberosServiceTicketRenew";
        break;
    case 4771:	
        event_name = L"KerberosPreAuthFail";
        break;
    case 4798:	
        event_name = L"LocalGroupEnum";
        break;
    case 5145:	
        event_name = L"NetworkShareCheck";
        break;
    case 5379:	
        event_name = L"CredentialManagerRead";
        break;
    default:
        event_name = L"<unknown>";
        return;
    }

    PrintProperties(event_name, eventRecord);
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

    /* Available tasks:
     <task name="ProcessStart" message="$(string.task_ProcessStart)" value="1"/>
     <task name="ProcessStop" message="$(string.task_ProcessStop)" value="2"/>
     <task name="ThreadStart" message="$(string.task_ThreadStart)" value="3"/>
     <task name="ThreadStop" message="$(string.task_ThreadStop)" value="4"/>
     <task name="ImageLoad" message="$(string.task_ImageLoad)" value="5"/>
     <task name="ImageUnload" message="$(string.task_ImageUnload)" value="6"/>
     <task name="CpuBasePriorityChange" message="$(string.task_CpuBasePriorityChange)" value="7"/>
     <task name="CpuPriorityChange" message="$(string.task_CpuPriorityChange)" value="8"/>
     <task name="PagePriorityChange" message="$(string.task_PagePriorityChange)" value="9"/>
     <task name="IoPriorityChange" message="$(string.task_IoPriorityChange)" value="10"/>
    */

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
        LOG_F(ERROR, "TdhGetEventInformation");
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