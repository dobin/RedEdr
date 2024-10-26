#pragma once

typedef void (WINAPI* EventRecordCallbackFuncPtr)(PEVENT_RECORD);


class EtwConsumer {
public:
	EtwConsumer();
	BOOL SetupEtw(int id, const wchar_t* guid, EventRecordCallbackFuncPtr func, const wchar_t* info, const wchar_t* sessionName);
	BOOL SetupEtwSecurityAuditing(int id, EventRecordCallbackFuncPtr func, const wchar_t* sessionName);
	BOOL StartEtw();
	void StopEtw();
	int getId();


private:
	int id;
	wchar_t* SessionName;
	TRACEHANDLE SessionHandle;
	TRACEHANDLE TraceHandle;
};


std::wstring EtwEventToStr(std::wstring eventName, PEVENT_RECORD eventRecord);
