#pragma once

#pragma once

#include <windows.h>
#include <vector>
#include <string>
#include <iostream>
#include <sstream>
#include <mutex>

#include "ranges.h"
#include "json.hpp"
#include "process.h"

BOOL AugmentProcess(DWORD pid, Process* process);
BOOL InitProcessInfo();
