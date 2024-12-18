#pragma once

#include <string>

// Criticality 

enum class Criticality {
    LOW,
    MEDIUM,
    HIGH
};
std::string CriticalityToString(Criticality c);


class CriticalityManager {
private:
    Criticality currentCriticality;

public:
    CriticalityManager() : currentCriticality(Criticality::LOW) {}

    void set(Criticality newCriticality) {
        if (newCriticality > currentCriticality) {
            currentCriticality = newCriticality;
        }
    }

    Criticality get() const {
        return currentCriticality;
    }
};

void ScanForMemoryChanges(nlohmann::json& j);
void ScanForDetections(nlohmann::json& j);
std::string CriticalityToString(Criticality c);
std::string GetAllDetectionsAsJson();
size_t GetDetectionsCount();
TargetInfo* GetTargetMemoryChanges();