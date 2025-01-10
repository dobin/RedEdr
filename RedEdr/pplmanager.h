#pragma once

#include <stdio.h>
#include <Windows.h>

BOOL InstallElamCertPpl();
BOOL InstallPplService();
BOOL EnablePplProducer(BOOL e, std::string target_name);
BOOL InitPplService();
BOOL ShutdownPplService();

BOOL remove_ppl_service();
