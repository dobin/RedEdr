#include <windows.h>
#include <evntrace.h>
#include <tdh.h>
#include <iostream>
#include <vector>
#include <string>
#include <iomanip>
#include <sstream>

#include "logging.h"
#include "etwconsumer.h"
#include "etwtihandler.h"
#include "objcache.h"
#include "emitter.h"


BOOL seen_etwti_event = FALSE;
BOOL enabled_consumer = FALSE;


void enable_consumer(BOOL e) {
    LOG_W(LOG_INFO, L"Consumer: Enable: %d", e);
    enabled_consumer = e;
}


void WINAPI EventRecordCallbackTi(PEVENT_RECORD eventRecord) {
    if (eventRecord == NULL || !enabled_consumer) {
        return;
    }
    DWORD processId = eventRecord->EventHeader.ProcessId;
    struct my_hashmap* obj = get_obj(processId);
    if (!obj->value) {
        return;
    }

    wchar_t id[128];
    //swprintf_s(buffer, sizeof(buffer) / sizeof(buffer[0]), L"<%d>", eventRecord->EventHeader.EventDescriptor.Id);

    switch (eventRecord->EventHeader.EventDescriptor.Id) {
    case 1:
        wcsncpy_s(id, 128, L"ALLOCVM_REMOTE", _TRUNCATE);
        break;
    case 2:
        wcsncpy_s(id, 128, L"PROTECTVM_REMOTE", _TRUNCATE);
        break;
    case 3:
        wcsncpy_s(id, 128, L"MAPVIEW_REMOTE", _TRUNCATE);
        break;
    case 4:
        wcsncpy_s(id, 128, L"QUEUEUSERAPC_REMOTE", _TRUNCATE);
        break;
    case 5:
        wcsncpy_s(id, 128, L"SETTHREADCONTEXT_REMOTE", _TRUNCATE);
        break;
    case 6:
        wcsncpy_s(id, 128, L"ALLOCVM_LOCAL", _TRUNCATE);
        break;
    case 7:
        wcsncpy_s(id, 128, L"PROTECTVM_LOCAL", _TRUNCATE);
        break;
    case 8:
        wcsncpy_s(id, 128, L"MAPVIEW_LOCAL", _TRUNCATE);
        break;
    case 9:
        wcsncpy_s(id, 128, L"???", _TRUNCATE);
        break;
    case 10:
        wcsncpy_s(id, 128, L"???", _TRUNCATE);
        break;
    case 11:
        wcsncpy_s(id, 128, L"READVM_LOCAL", _TRUNCATE);
        break;
    case 12:
        wcsncpy_s(id, 128, L"WRITEVM_LOCAL", _TRUNCATE);
        break;
    case 13:
        wcsncpy_s(id, 128, L"READVM_REMOTE", _TRUNCATE);
        break;
    case 14:
        wcsncpy_s(id, 128, L"WRITEVM_REMOTE", _TRUNCATE);
        break;
    case 15:
        wcsncpy_s(id, 128, L"SUSPEND_THREAD", _TRUNCATE);
        break;
    case 16:
        wcsncpy_s(id, 128, L"RESUME_THREAD", _TRUNCATE);
        break;
    case 17:
        wcsncpy_s(id, 128, L"SUSPEND_PROCESS", _TRUNCATE);
        break;
    case 18:
        wcsncpy_s(id, 128, L"RESUME_PROCESS", _TRUNCATE);
        break;
    case 19:
        wcsncpy_s(id, 128, L"FREEZE_PROCESS", _TRUNCATE);
        break;
    case 20:
        wcsncpy_s(id, 128, L"THAW_PROCESS", _TRUNCATE);
        break;
    case 21:
        wcsncpy_s(id, 128, L"ALLOCVM_REMOTE_KERNEL_CALLER", _TRUNCATE);
        break;
    case 22:
        wcsncpy_s(id, 128, L"PROTECTVM_REMOTE_KERNEL_CALLER", _TRUNCATE);
        break;
    case 23:
        wcsncpy_s(id, 128, L"MAPVIEW_REMOTE_KERNEL_CALLER", _TRUNCATE);
        break;
    case 24:
        wcsncpy_s(id, 128, L"QUEUEUSERAPC_REMOTE_KERNEL_CALLER", _TRUNCATE);
        break;
    case 25:
        wcsncpy_s(id, 128, L"SETTHREADCONTEXT_REMOTE_KERNEL_CALLER", _TRUNCATE);
        break;
    case 26:
        wcsncpy_s(id, 128, L"ALLOCVM_LOCAL_KERNEL_CALLER", _TRUNCATE);
        break;
    case 27:
        wcsncpy_s(id, 128, L"PROTECTVM_LOCAL_KERNEL_CALLER", _TRUNCATE);
        break;
    case 28:
        wcsncpy_s(id, 128, L"MAPVIEW_LOCAL_KERNEL_CALLER", _TRUNCATE);
        break;
    case 29:
        wcsncpy_s(id, 128, L"DRIVER_OBJECT_LOAD", _TRUNCATE);
        break;
    case 30:
        wcsncpy_s(id, 128, L"DRIVER_OBJECT_UNLOAD", _TRUNCATE);
        break;
    case 31:
        wcsncpy_s(id, 128, L"DEVICE_OBJECT_LOAD", _TRUNCATE);
        break;
    case 32:
        wcsncpy_s(id, 128, L"DEVICE_OBJECT_UNLOAD", _TRUNCATE);
        break;
    default:
        wcsncpy_s(id, 128, L"???", _TRUNCATE);
        break;
    }

    //PrintProperties(id, eventRecord);
    std::wstring s = EtwEventToStr(id, eventRecord);
    SendEmitterPipe((wchar_t*)s.c_str());
}


// Only for testing
void WINAPI EventRecordCallbackKernelProcess(PEVENT_RECORD eventRecord) {
    if (eventRecord == NULL || !enabled_consumer) {
        return;
    }
    if (!seen_etwti_event) {
        seen_etwti_event = TRUE;
        LOG_W(LOG_INFO, L"Consumer: Got a ETW-TI message, all is working");
    }
    DWORD processId = eventRecord->EventHeader.ProcessId;
    struct my_hashmap* obj = get_obj(processId);
    if (!obj->value) {
        return;
    }

    wchar_t id[32];

    switch (eventRecord->EventHeader.EventDescriptor.Id) {
    case 1:
        wcsncpy_s(id, 32, L"StartProcess", _TRUNCATE);
        break;
    case 3:
        wcsncpy_s(id, 32, L"StartThread", _TRUNCATE);
        break;
        //case 5:
        //    wcsncpy_s(id, 32, L"LoadImage", _TRUNCATE);
        //    break;
    default:
        return;
    }

    std::wstring s = EtwEventToStr(id, eventRecord);
    SendEmitterPipe((wchar_t*)s.c_str());
    //PrintProperties(id, eventRecord);
}
