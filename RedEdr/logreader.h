#pragma once

#include <iostream>
#include <fstream>
#include <string>
#include <windows.h>

void tail_f(const std::wstring& filename);
std::wstring findFiles(const std::wstring& directory, const std::wstring& pattern);
void chomp(std::wstring& str);
BOOL tail_mplog();
