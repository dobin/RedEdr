
#include <windows.h>
#include <evntrace.h>
#include <tdh.h>
#include <iostream>
#include <vector>
#include <string>
#include <iomanip>
#include <sstream>

#include "logging.h"
#include "etwhandler.h"
#include "config.h"
#include "processcache.h"
#include "etwconsumer.h"
#include "eventproducer.h"


// EtwHandler: ETW Event Handlers


void WINAPI EventRecordCallbackSecurityAuditing(PEVENT_RECORD eventRecord)
{
    // Do we want to track this process?
    DWORD processId = eventRecord->EventHeader.ProcessId;
    if (!g_ProcessCache.observe(processId)) {
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
    std::wstring eventName = L"";
    switch (eventRecord->EventHeader.EventDescriptor.Id) {
    case 4624:	
        eventName = L"AccountLogonSuccess";
        break;
    case 4625:	
        eventName = L"AccountLogonFail";
        break;
    case  4627:	
        eventName = L"GroupMembershipInformation.";
        break;
    case 4634:	
        eventName = L"AccountLogoff";
        break;
    case 4647:	
        eventName = L"UserLogoff";
        break;
    case 4648:	
        eventName = L"ExplicitLogon";
        break;
    case 4656:	
        eventName = L"ObjectHandleRequest";
        break;
    case 4657:	
        eventName = L"RegistryValueModified";
        break;
    case 4660:	
        eventName = L"ObjectDelete";
        break;
    case 4661:	
        eventName = L"ObjectHandleRequest";
        break;
    case 4662:	
        eventName = L"ObjectOperation";
        break;
    case 4663:	
        eventName = L"ObjectAccess";
        break;
    case 4664:	
        eventName = L"CreateHardLink";
        break;
    case 4672:	
        eventName = L"LogonSpecialPrivileges";
        break;
    case 4673:	
        eventName = L"PrivilegedServiceInstalled";
        break;
    case 4674:	
        eventName = L"PrivilegedObjectOperation";
        break;
    case 4688:	
        eventName = L"ProcessCreate";
        break;
    case 4689:	
        eventName = L"ProcessExit";
        break;
    case 4690:	
        eventName = L"ObjectHandleDuplicate";
        break;
    case 4696:	
        eventName = L"ProcessPrimaryTokenAssign";
        break;
    case 4697:	
        eventName = L"ServiceInstalled";
        break;
    case 4698:	
        eventName = L"ScheduledTaskCreate";
        break;
    case 4699:	
        eventName = L"ScheduledTaskDelete";
        break;
    case 4700:	
        eventName = L"ScheduledTaskEnable";
        break;
    case 4701:	
        eventName = L"ScheduledTaskDisable";
        break;
    case 4702:	
        eventName = L"ScheduledTaskUpdated";
        break;
    case 4703:	
        eventName = L"UserRightsAdjusted";
        break;
    case 4741:	
        eventName = L"ComputerAccountCreated";
        break;
    case 4742:	
        eventName = L"ComputerAccountChanged";
        break;
    case 4743:	
        eventName = L"ComputerAccountDeleted";
        break;
    case 4768:	
        eventName = L"KerberosTgtRequest";
        break;
    case 4769:	
        eventName = L"KerberosServiceTicketRequest";
        break;
    case 4770:	
        eventName = L"KerberosServiceTicketRenew";
        break;
    case 4771:	
        eventName = L"KerberosPreAuthFail";
        break;
    case 4798:	
        eventName = L"LocalGroupEnum";
        break;
    case 5145:	
        eventName = L"NetworkShareCheck";
        break;
    case 5379:	
        eventName = L"CredentialManagerRead";
        break;
    default:
        eventName = L"<unknown>";
        return;
    }

    std::wstring eventStr = EtwEventToStr(eventName, eventRecord);
    g_EventProducer.do_output(eventStr);
}


void WINAPI EventRecordCallbackKernelProcess(PEVENT_RECORD eventRecord) {
    std::wstring eventName;

    if (eventRecord == nullptr) {
        return;
    }

    // Do we want to track this process?
    DWORD processId = eventRecord->EventHeader.ProcessId;
    if (!g_ProcessCache.observe(processId)) {
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

    std::wstring eventStr = EtwEventToStr(eventName, eventRecord);
    g_EventProducer.do_output(eventStr);
}


void WINAPI EventRecordCallbackApiCalls(PEVENT_RECORD eventRecord) {
    std::wstring eventName;

    if (eventRecord == nullptr) {
        return;
    }

    // Do we want to track this process?
    DWORD processId = eventRecord->EventHeader.ProcessId;
    if (!g_ProcessCache.observe(processId)) {
        return;
    }

    /* https://www.elastic.co/security-labs/kernel-etw-best-etw
    Id	EVENT_DESCRIPTOR Symbol	                        Function
    1	KERNEL_AUDIT_API_PSSETLOADIMAGENOTIFYROUTINE	PsSetLoadImageNotifyRoutineEx
    2	KERNEL_AUDIT_API_TERMINATEPROCESS	            NtTerminateProcess
    3	KERNEL_AUDIT_API_CREATESYMBOLICLINKOBJECT	    ObCreateSymbolicLink
    4	KERNEL_AUDIT_API_SETCONTEXTTHREAD	            NtSetContextThread
    5	KERNEL_AUDIT_API_OPENPROCESS	                PsOpenProcess
    6	KERNEL_AUDIT_API_OPENTHREAD	                    PsOpenThread
    7	KERNEL_AUDIT_API_IOREGISTERLASTCHANCESHUTDOWNNOTIFICATION	IoRegisterLastChanceShutdownNotification
    8	KERNEL_AUDIT_API_IOREGISTERSHUTDOWNNOTIFICATION IoRegisterShutdownNotification
    */

    switch (eventRecord->EventHeader.EventDescriptor.Id) {
    case 1:
        eventName = L"KERNEL_AUDIT_API_PSSETLOADIMAGENOTIFYROUTINE";
        break;
    case 2:
        eventName = L"KERNEL_AUDIT_API_TERMINATEPROCESS";
        break;
    case 3:
        eventName = L"KERNEL_AUDIT_API_CREATESYMBOLICLINKOBJECT";
        break;
    case 4:
        eventName = L"KERNEL_AUDIT_API_SETCONTEXTTHREAD";
        break;
    case 5:
        eventName = L"KERNEL_AUDIT_API_OPENPROCESS";
        break;
    case 6:
        eventName = L"KERNEL_AUDIT_API_OPENTHREAD";
        break;
    case 7:
        eventName = L"KERNEL_AUDIT_API_IOREGISTERLASTCHANCESHUTDOWNNOTIFICATION";
        break;
    case 8:
        eventName = L"KERNEL_AUDIT_API_IOREGISTERSHUTDOWNNOTIFICATION";
        break;
    }

    std::wstring eventStr = EtwEventToStr(eventName, eventRecord);
    g_EventProducer.do_output(eventStr);
}


void WINAPI EventRecordCallbackWin32(PEVENT_RECORD eventRecord) {
    /*
          <task name="task_0" message="$(string.task_task_0)" value="0" />
          <task name="WindowUpdate" message="$(string.task_WindowUpdate)" value="1" />
          <task name="FocusChange" message="$(string.task_FocusChange)" value="2" />
          <task name="UIPIMsgError" message="$(string.task_UIPIMsgError)" value="3" />
          <task name="UIPIHookError" message="$(string.task_UIPIHookError)" value="4" />
          <task name="UIPIEventHookError" message="$(string.task_UIPIEventHookError)" value="5" />
          <task name="UIPIHandleValError" message="$(string.task_UIPIHandleValError)" value="6" />
          <task name="UIPIInputError" message="$(string.task_UIPIInputError)" value="7" />
          <task name="UIPIClipboardError" message="$(string.task_UIPIClipboardError)" value="8" />
          <task name="UIPISystemError" message="$(string.task_UIPISystemError)" value="9" />
          <task name="PowerDisplayChange" message="$(string.task_PowerDisplayChange)" value="10" />
          <task name="IdleActionExpiration" message="$(string.task_IdleActionExpiration)" value="11" />
          <task name="DisplayReqChange" message="$(string.task_DisplayReqChange)" value="12" />
          <task name="DisplayTimeoutReset" message="$(string.task_DisplayTimeoutReset)" value="13" />
          <task name="LockAcquireExclusive" message="$(string.task_LockAcquireExclusive)" value="14" />
          <task name="LockAcquireShared" message="$(string.task_LockAcquireShared)" value="15" />
          <task name="LockAcquireSharedStarveExclusive" message="$(string.task_LockAcquireSharedStarveExclusive)" value="16" />
          <task name="LockRelease" message="$(string.task_LockRelease)" value="17" />
          <task name="SwapChainBind" message="$(string.task_SwapChainBind)" value="18" />
          <task name="SwapChainSetStats" message="$(string.task_SwapChainSetStats)" value="19" />
          <task name="SwapChainUnBind" message="$(string.task_SwapChainUnBind)" value="20" />
          <task name="IdleStatusTracing" message="$(string.task_IdleStatusTracing)" value="21" />
          <task name="ScreenSaverProcess" message="$(string.task_ScreenSaverProcess)" value="22" />
          <task name="WinlogonSleepStart" message="$(string.task_WinlogonSleepStart)" value="23" />
          <task name="WinlogonSleepEnd" message="$(string.task_WinlogonSleepEnd)" value="24" />
          <task name="UserActive" message="$(string.task_UserActive)" value="25" />
          <task name="FocusedProcessChange" message="$(string.task_FocusedProcessChange)" value="26" />
          <task name="DwmSpriteCreate" message="$(string.task_DwmSpriteCreate)" value="27" />
          <task name="DwmSpriteDestroy" message="$(string.task_DwmSpriteDestroy)" value="28" />
          <task name="LogicalSurfCreate" message="$(string.task_LogicalSurfCreate)" value="29" />
          <task name="LogicalSurfDestroy" message="$(string.task_LogicalSurfDestroy)" value="30" />
          <task name="LogicalSurfPhysSurfBind" message="$(string.task_LogicalSurfPhysSurfBind)" value="31" />
          <task name="LogicalSurfPhysSurfUnbind" message="$(string.task_LogicalSurfPhysSurfUnbind)" value="32" />
          <task name="GdiSysMemToken" message="$(string.task_GdiSysMemToken)" value="33" />
          <task name="WaitCursor" message="$(string.task_WaitCursor)" value="35" />
          <task name="ThreadInfoRundown" message="$(string.task_ThreadInfoRundown)" value="36" />
          <task name="InputProcessDelay" message="$(string.task_InputProcessDelay)" value="37" />
          <task name="MessageCheckDelay" message="$(string.task_MessageCheckDelay)" value="38" />
          <task name="Rendering" message="$(string.task_Rendering)" value="39">
    */

    std::wstring eventName = L"<unknown>";
    if (eventRecord == nullptr) {
        return;
    }

    // Do we want to track this process?
    DWORD processId = eventRecord->EventHeader.ProcessId;
    if (!g_ProcessCache.observe(processId)) {
        return;
    }

    std::wstring eventStr = EtwEventToStr(eventName, eventRecord);
    g_EventProducer.do_output(eventStr);
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

    std::wstring eventStr = EtwEventToStr(eventName, eventRecord);
    g_EventProducer.do_output(eventStr);
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

    std::wstring eventStr = EtwEventToStr(eventName, eventRecord);
    g_EventProducer.do_output(eventStr);
}


void WINAPI EventRecordCallbackPrintAll(PEVENT_RECORD eventRecord) {
    std::wstring eventName = L"test";

    if (eventRecord == nullptr) {
        return;
    }

    std::wstring eventStr = EtwEventToStr(eventName, eventRecord);
    g_EventProducer.do_output(eventStr);
}
