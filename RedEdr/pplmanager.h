#pragma once

#include <stdio.h>
#include <Windows.h>

DWORD install_elam_cert();
DWORD install_ppl_service();
DWORD remove_ppl_service();
BOOL ppl_service_enable(BOOL e, wchar_t* target_name);
BOOL ppl_service_shutdown();
