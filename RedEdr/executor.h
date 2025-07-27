
#include <thread>
#include <atomic>

class Executor {
public:
	bool WriteMalware(std::string filepath, std::string filedata);
	bool Start(std::string filepath);

	bool Start(std::string filepath);
	bool StartAsSystem(const wchar_t* programPath);
	bool StartAsUser(const wchar_t* programPath);
	bool Stop();
	std::string GetOutput();
	bool Capture();
	void StartReaderThread();
	void StopReaderThread();


	DWORD getLastPid();
	bool KillLastExec();

private:
	HANDLE hStdOutRead = nullptr;
	HANDLE pihProcess = nullptr;
	std::string capturedOutput;
	std::thread readerThread;
	std::atomic<bool> stopReading{ false };
	std::string malwareFilePath;
};


extern Executor g_Executor;
