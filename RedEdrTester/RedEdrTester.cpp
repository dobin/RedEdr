#include <stdio.h>
#include <windows.h>
#include <cwchar>  // For wcstol
#include <cstdlib> // For exit()

#include "logreader.h"
#include "config.h"
#include "procinfo.h"


int wmain(int argc, wchar_t* argv[]) {
    if (argc != 2) {
        printf("Usage: rededrtester.exe <pid>");
        return 1;
    }

    wchar_t* end;
    DWORD pid = wcstol(argv[1], &end, 10);

    printf("RedTester\n");
    Process* process = MakeProcess(pid);
    process->display();

    if (process->image_path.find(g_config.targetExeName) != std::wstring::npos) {
        wprintf(L"Observe CMD: %d %ls\n", pid, process->image_path.c_str());
    }

    //tail_testlog();
    tail_mplog();
}
