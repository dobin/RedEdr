#pragma once

#include <string>
#include "mem_static.h"


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


// Detection

class EventDetector {
public:
    void AnalyzerNewDetection(nlohmann::json& j, Criticality c, std::string s);
    void ScanEventForMemoryChanges(nlohmann::json& j);
    void ScanEventForDetections(nlohmann::json& j);
    void ResetData();

    std::string GetAllDetectionsAsJson();
    size_t GetDetectionsCount();
    MemStatic* GetTargetMemoryChanges();


private:
    std::vector<std::string> detections;
    MemStatic targetMemoryChanges;
};

extern EventDetector g_EventDetector;


std::string CriticalityToString(Criticality c);
