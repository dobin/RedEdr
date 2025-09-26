#pragma once

#include "json.hpp"
#include "myprocess.h"


void AugmentEvent(nlohmann::json& j, Process *process);
void AugmentEventWithMemAddrInfo(nlohmann::json& j, Process *process);
