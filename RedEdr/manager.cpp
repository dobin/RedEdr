#include <windows.h>
#include <iostream>

#include "config.h"
#include "etwreader.h"
#include "kernelreader.h"
#include "webserver.h"
#include "dllreader.h"
#include "pplreader.h"
#include "kernelinterface.h"
#include "pplmanager.h"
#include "logging.h"
#include "event_processor.h"
#include "event_aggregator.h"
#include "process_resolver.h"


/* manager.cpp: Knows and manages all subsystems (Input's)
 *   start, stop, restart components
 *   start, stop, restart components logging
 *   set new configuration (process trace etc.)
 */


// Unused atm
void ResetEverything() {
    g_EventAggregator.ResetData();
    g_EventProcessor.ResetData();
    g_ProcessResolver.ResetData();
    //g_MemStatic.ResetData();
    //g_MemDynamic.ResetData();
}


BOOL ManagerApplyNewTargets() {
    // DLL
    // -> Automatic upon connect of DLL (initiated by Kernel)

    // ETW
    if (g_Config.do_etw) {
        // Re-evaluate all cached processes with the new target names
        g_ProcessResolver.SetTargetNames(g_Config.targetProcessNames);
        g_ProcessResolver.RefreshTargetMatching();
    }
    
    // Kernel
    if (g_Config.do_hook) {
        // Kernel driver only supports one target at a time, use the first one
        if (!g_Config.targetProcessNames.empty()) {
            LOG_A(LOG_INFO, "Manager: Tell Kernel about new target: %s", g_Config.targetProcessNames[0].c_str());
            if (!EnableKernelDriver(true, g_Config.targetProcessNames[0])) {
                LOG_A(LOG_ERROR, "Manager: Could not communicate with kernel driver, aborting.");
                return FALSE;
            }
        } else {
            LOG_A(LOG_WARNING, "Manager: No target names configured, skip kernel driver");
        }
    }

    // PPL
    if (g_Config.do_etwti) {
        LOG_A(LOG_INFO, "Manager: Tell ETW-TI about new targets: %zu names", g_Config.targetProcessNames.size());
        if (!EnablePplProducer(true, g_Config.targetProcessNames)) {
            LOG_A(LOG_ERROR, "Manager: Failed to enable PPL producer");
            return FALSE;
        }
    }

    return TRUE;
}


BOOL ManagerStart(std::vector<HANDLE>& threads) {
    try {
        // Hook
        if (g_Config.do_hook) {
            // Kernel: Driver load
            if (! IsServiceRunning(g_Config.driverName)) {
                LOG_A(LOG_INFO, "Manager: Kernel Driver load");
                if (!LoadKernelDriver()) {
                    LOG_A(LOG_ERROR, "Manager: Kernel driver could not be loaded");
                    return FALSE;
                }
            }

            // Kernel: Start Reader Thread
            LOG_A(LOG_INFO, "Manager: Kernel reader thread start");
            if (!KernelReaderInit(threads)) {
                LOG_A(LOG_ERROR, "Manager: Failed to initialize kernel reader");
                return FALSE;
            }
        }
        if (g_Config.do_hook || g_Config.debug_dllreader) {
            // Hook: Start DLL Reader Thread
            LOG_A(LOG_INFO, "Manager: InjectedDll reader thread start");
            if (!DllReaderInit(threads)) {
                LOG_A(LOG_ERROR, "Manager: Failed to initialize DLL reader");
                return FALSE;
            }
        }

        // Load: ETW-TI
        if (g_Config.do_etwti) {
            // Start PPL service first (if not already)
            if (!StartThePplService()) {
                LOG_A(LOG_ERROR, "Manager: Failed to initialize PPL service");
                return FALSE;
            }

            // Start PPL Reader Thread for dedicated data pipe
            // will wait for client connection
            LOG_A(LOG_INFO, "Manager: PPL reader thread start");
            if (!PplReaderInit(threads)) {
                LOG_A(LOG_ERROR, "Manager: Failed to initialize PPL reader");
                return FALSE;
            }


			// Connect to PPL service pipe
            // it will connect back to the pipe created above when we connect
            if (!ConnectPplService()) {
                LOG_A(LOG_ERROR, "ETW-TI: Failed to connect to PPL service pipe");
                return FALSE;
            }

            // notify service about initial target
            LOG_A(LOG_INFO, "Manager: Tell ETW-TI about new targets: %zu names", g_Config.targetProcessNames.size());
            if (!EnablePplProducer(true, g_Config.targetProcessNames)) {
                LOG_A(LOG_ERROR, "Manager: Failed to enable PPL producer");
                return FALSE;
            }
        }

        // ETW
        if (g_Config.do_etw) {
            g_ProcessResolver.SetTargetNames(g_Config.targetProcessNames);
            if (!InitializeEtwReader(threads)) {
                LOG_A(LOG_ERROR, "Manager: Failed to initialize ETW reader");
                return FALSE;
            }
        }

        // Kernel: Enable
        if (g_Config.do_hook) {
            LOG_A(LOG_INFO, "Manager: Kernel module enable collection");
            if (!g_Config.targetProcessNames.empty()) {
                if (!EnableKernelDriver(1, g_Config.targetProcessNames[0])) {
                    LOG_A(LOG_ERROR, "Manager: Kernel module failed");
                    return FALSE;
                }
            } else {
                LOG_A(LOG_WARNING, "Manager: No target names configured for kernel driver");
            }
        }

        // Necessary? (wait for kernel and ETW-TI to connect)
        //Sleep(1000);

        // Populate process cache with all currently running processes
        LOG_A(LOG_INFO, "Manager: Populating process cache with all running processes");
        if (!g_ProcessResolver.PopulateAllProcesses()) {
            LOG_A(LOG_WARNING, "Manager: Failed to populate process cache, continuing anyway");
            // Don't return FALSE here as this is not critical for core functionality
        } else {
            // Log cache statistics after successful population
            g_ProcessResolver.LogCacheStatistics();
        }

        return TRUE;
        }
    catch (const std::exception& e) {
        LOG_A(LOG_ERROR, "Manager: Exception in ManagerStart: %s", e.what());
        return FALSE;
    }
    catch (...) {
        LOG_A(LOG_ERROR, "Manager: Unknown exception in ManagerStart");
        return FALSE;
    }
}


void ManagerShutdown() {
    // ETW-TI
    if (g_Config.do_etwti) {
        PplReaderShutdown(); // needs to be first
        DisablePplProducer();
    }

    // ETW
    if (g_Config.do_etw) {
        LOG_A(LOG_INFO, "Manager: Stop ETW readers");
        EtwReaderStopAll();
    }

    // Hook
    if (g_Config.do_hook) {
        LOG_A(LOG_INFO, "Manager: Disable kernel driver");
        EnableKernelDriver(0, "");

        LOG_A(LOG_INFO, "Manager: Stop kernel reader");
        KernelReaderShutdown();

        LOG_A(LOG_INFO, "Manager: Stop DLL reader");
        DllReaderShutdown();
    }
    // Debug: DLL Reader
    if (g_Config.debug_dllreader) {
        LOG_A(LOG_INFO, "Manager: Stop DLL reader");
        DllReaderShutdown();
    }

    // Web server
    if (g_Config.web_output) {
        LOG_A(LOG_INFO, "Manager: Stop web server");
        StopWebServer();
    }

    // Analyzer
    LOG_A(LOG_INFO, "Manager: Stop EventProcessor");
    StopEventProcessor();
}
