#pragma once
#include <windows.h>
#include <iostream>
#include <vector>
#include <string>
#include <iomanip>
#include <sstream>


bool DllReaderInit(std::vector<HANDLE>& threads);
void DllReaderShutdown();
