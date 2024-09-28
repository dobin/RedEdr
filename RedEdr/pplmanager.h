#pragma once

#include <stdio.h>
#include <Windows.h>

BOOL InstallElamCertPpl();
BOOL InstallPplService();
BOOL EnablePplService(BOOL e, wchar_t* target_name);
BOOL ShutdownPplService();

BOOL remove_ppl_service();
