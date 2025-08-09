#pragma once

#include <Windows.h>
#include <string>

BOOL ConnectPplService();
BOOL InstallElamCertPpl();
BOOL InstallPplService();
BOOL EnablePplProducer(BOOL e, std::string target_name);
BOOL InitPplService();
BOOL ShutdownPplService();
BOOL DisablePplProducer();
BOOL remove_ppl_service();
