#pragma once

#include <Windows.h>
#include <vector>
#include <string>
#include <mutex>

#include "../Shared/common.h"


class PipeServer {
public:
	PipeServer(std::string pipeName, wchar_t* pipePath);
	~PipeServer(); // Add destructor for proper cleanup
	
	// Disable copy constructor and assignment operator to prevent resource issues
	PipeServer(const PipeServer&) = delete;
	PipeServer& operator=(const PipeServer&) = delete;
	
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
	std::mutex pipe_mutex; // Add mutex for thread safety

	char buffer[DATA_BUFFER_SIZE] = { 0 };
};


class PipeClient {
public:
	PipeClient(std::string pipeName);
	~PipeClient(); // Add destructor for proper cleanup
	
	// Disable copy constructor and assignment operator to prevent resource issues
	PipeClient(const PipeClient&) = delete;
	PipeClient& operator=(const PipeClient&) = delete;
	
	BOOL Connect(const wchar_t* pipeName);
	void Disconnect();

	BOOL Send(char* buffer);
	BOOL Receive(char* buffer, size_t buffer_len);

private:
	HANDLE hPipe;
	std::mutex pipe_mutex; // Add mutex for thread safety
	std::string pipe_name;
};

