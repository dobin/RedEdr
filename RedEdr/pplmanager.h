#pragma once

#include <stdio.h>
#include <Windows.h>

BOOL InstallElamCertPpl();
BOOL InstallPplService();
BOOL remove_ppl_service();
BOOL EnablePplService(BOOL e, wchar_t* target_name);
BOOL ShutdownPplService();
