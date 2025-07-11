
class Executor {
public:
	bool Start(const wchar_t* programPath);
	bool StartAsSystem(const wchar_t* programPath);
	bool StartAsUser(const wchar_t* programPath);
	bool Stop();
	std::string GetOutput();
	bool Capture();
	void StartReaderThread();

private:
	HANDLE hStdOutRead = nullptr;
	HANDLE pihProcess = nullptr;
	std::string capturedOutput;
};


extern Executor g_Executor;
