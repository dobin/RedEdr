
#include "event_producer.h"
#include "config.h"
#include "logging.h"
#include "utils.h"
#include "json.hpp"

DWORD WINAPI WebserverThread(LPVOID param);
int InitializeWebServer(std::vector<HANDLE>& threads);
void StopWebServer();
