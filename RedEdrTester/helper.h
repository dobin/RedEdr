#pragma once

#include <stdio.h>
#include <windows.h>
#include <cstdlib>
#include <string>

DWORD FindProcessIdByName(const std::wstring& processName);
