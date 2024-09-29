#pragma once

#include <Windows.h>
#include <vector>
#include <string>

#include "../Shared/common.h"


class PipeServer {
public:
	PipeServer(const wchar_t* pipe_name);
	BOOL StartAndWaitForClient(const wchar_t* pipeName, BOOL allow_all);

	BOOL Send(wchar_t* buffer);
	BOOL Receive(wchar_t* buffer, size_t buffer_len);
	std::vector<std::wstring> ReceiveBatch();
	void Shutdown();
	
private:
	HANDLE hPipe;
	const wchar_t* name;

	// state for ReceiveBatch
	char buffer[DATA_BUFFER_SIZE] = { 0 };
	char* buf_ptr = buffer; // buf_ptr and rest_len are synchronized
	int rest_len = 0;
	
};



class PipeClient {
public:
	PipeClient();
	BOOL Connect(const wchar_t* pipeName);
	void Disconnect();

	BOOL Send(wchar_t* buffer);
	BOOL Receive(wchar_t* buffer, size_t buffer_len);

private:
	HANDLE hPipe;
};

