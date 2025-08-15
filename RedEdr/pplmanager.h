#pragma once

#include <Windows.h>
#include <string>
#include <vector>

BOOL ConnectPplService();
BOOL InstallElamCertPpl();
BOOL InstallPplService();
BOOL EnablePplProducer(BOOL e, std::vector<std::string> targetNames);
BOOL InitPplService();
BOOL ShutdownPplService();
BOOL DisablePplProducer();
BOOL remove_ppl_service();
