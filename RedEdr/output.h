#pragma once

void do_output(std::wstring str);
void print_all_output();
std::string output_as_json();
int InitializeWebServer(std::vector<HANDLE>& threads);
void StopWebServer();