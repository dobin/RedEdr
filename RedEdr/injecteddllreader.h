#pragma once
#include <windows.h>
#include <iostream>
#include <vector>
#include <string>
#include <iomanip>
#include <sstream>


void InitializeInjectedDllReader(std::vector<HANDLE>& threads);
void InjectedDllReaderStopAll();