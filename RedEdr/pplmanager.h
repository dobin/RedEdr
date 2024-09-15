#pragma once

#include <stdio.h>
#include <Windows.h>

DWORD InstallElamCertPpl();
DWORD InstallPplService();
DWORD remove_ppl_service();
BOOL EnablePplService(BOOL e, wchar_t* target_name);
BOOL ShutdownPplService();
