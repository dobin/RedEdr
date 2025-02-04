

class Executor {
public:
	bool Start(const wchar_t* programPath);
	bool Stop();
	std::string GetOutput();

private:
	HANDLE hStdOutRead = nullptr;
	HANDLE pihProcess = nullptr;
};
