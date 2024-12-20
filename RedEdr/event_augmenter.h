#pragma once

#include "json.hpp"


void AugmentEvent(nlohmann::json& j);
void AugmentEventWithMemAddrInfo(nlohmann::json& j);