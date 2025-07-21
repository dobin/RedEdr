#include <windows.h>
#include <winevt.h>
#include <iostream>
#include <string>
#include <iomanip>
#include <sstream>
#pragma comment(lib, "wevtapi.lib")

#include "edr_reader.h"
#include "utils.h"

EdrReader g_EdrReader;

/* EDR Reader
 * 
 * Reads the Windows Defender event logs using the Windows Event Log API.
 * Include messages between Start() and Stop() calls (via Get()). 
 */


bool EdrReader::Start() {
	start_time = GetISO8601Timestamp();
	defender_eventlogs = ""; // Clear previous logs
    return true;
}

bool EdrReader::Stop() {
	defender_eventlogs = GetDefenderEventsSince(start_time);
    return true;
}


std::string EdrReader::Get() {
    std::string allEventsUtf8 = defender_eventlogs;
	return allEventsUtf8;
}


std::wstring EdrReader::GetISO8601Timestamp()
{
    SYSTEMTIME st;
    GetSystemTime(&st); // UTC time

    std::wstringstream ss;
    ss << std::setfill(L'0')
        << std::setw(4) << st.wYear << L'-'
        << std::setw(2) << st.wMonth << L'-'
        << std::setw(2) << st.wDay << L'T'
        << std::setw(2) << st.wHour << L':'
        << std::setw(2) << st.wMinute << L':'
        << std::setw(2) << st.wSecond << L".000Z";

    return ss.str();
}

std::string EdrReader::GetDefenderEventsSince(const std::wstring& isoTime)
{
    std::wstring query = L"*[System[TimeCreated[@SystemTime>='" + isoTime + L"']]]";

    EVT_HANDLE hResults = EvtQuery(
        nullptr,
        L"Microsoft-Windows-Windows Defender/Operational",
        query.c_str(),
        EvtQueryForwardDirection | EvtQueryTolerateQueryErrors
    );

    if (!hResults) {
        std::wcerr << L"EvtQuery failed: " << GetLastError() << std::endl;
        return "";
    }

    std::string allEvents = "<Events>\n";
    EVT_HANDLE hEvents[10];
    DWORD returned = 0;

    while (EvtNext(hResults, 10, hEvents, INFINITE, 0, &returned)) {
        for (DWORD i = 0; i < returned; ++i) {
            DWORD bufferUsed = 0;
            DWORD propertyCount = 0;
            EvtRender(nullptr, hEvents[i], EvtRenderEventXml, 0, nullptr, &bufferUsed, &propertyCount);

            if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
                std::wstring buffer(bufferUsed / sizeof(WCHAR), 0);
                if (EvtRender(nullptr, hEvents[i], EvtRenderEventXml,
                    bufferUsed, &buffer[0], &bufferUsed, &propertyCount)) {

					std::string bufferUtf8 = wstring2string(buffer);
                    allEvents += bufferUtf8 + "\n";
                }
                else {
                    std::wcerr << L"EvtRender failed: " << GetLastError() << std::endl;
                }
            }

            EvtClose(hEvents[i]);
        }
    }

    if (GetLastError() != ERROR_NO_MORE_ITEMS) {
        std::wcerr << L"EvtNext failed: " << GetLastError() << std::endl;
    }
    EvtClose(hResults);

    allEvents += "</Events>";
    return allEvents;
}

