
#include <thread>
#include <atomic>

class Executor {
public:
	bool WriteMalware(std::string filepath, std::string filedata);
	bool Start(std::string filepath);
	bool StartAsSystem(const wchar_t* commandLine);
	bool StartAsUser(const wchar_t* commandLine);
	bool Stop();
	std::string GetOutput();
	bool Capture();
	void StartReaderThread();
	void StopReaderThread();


	DWORD getLastPid();
	bool KillLastExec();

private:
	bool IsDllFile(const std::string& filepath);
	std::wstring CreateCommandLine(const std::string& filepath);
	HANDLE hStdOutRead = nullptr;
	HANDLE pihProcess = nullptr;
	std::string capturedOutput;
	std::thread readerThread;
	std::atomic<bool> stopReading{ false };
	std::string malwareFilePath;
};


extern Executor g_Executor;
