#pragma once

#include <Windows.h>
#include <vector>
#include <string>

#include "../Shared/common.h"


class PipeServer {
public:
	PipeServer(std::string pipeName, wchar_t* pipePath);
	BOOL StartAndWaitForClient(BOOL allow_all);
	BOOL WaitForClient();
	BOOL Start(BOOL allow_all);

	BOOL Send(char* buffer);
	BOOL Receive(char* buffer, size_t buffer_len);
	std::vector<std::string> ReceiveBatch();
	void Shutdown();
	BOOL IsConnected();
	
private:
	HANDLE hPipe;
	wchar_t* pipe_path;
	std::string pipe_name;

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

	BOOL Send(char* buffer);
	BOOL Receive(char* buffer, size_t buffer_len);

private:
	HANDLE hPipe;
};

