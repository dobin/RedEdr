#include <windows.h>
#include <iostream>
#include <string>

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
#include "logreader.h"


/* manager.cpp: Knows and manages all subsystems (Input's)
 *   start, stop, restart components
 *   start, stop, restart components logging
 *   set new configuration (process trace etc.)
 */


BOOL ManagerApplyNewTargets(std::vector<std::string> traceNames) {
    LOG_A(LOG_INFO, "Trace targets: %zu targets", traceNames.size());
    for (const auto& target : traceNames) {
        LOG_A(LOG_INFO, "  - %s", target.c_str());
    }
    g_Config.targetProcessNames = traceNames;

    // DLL
    // -> Automatic upon connect of DLL (initiated by Kernel)

    // ETW
    if (g_Config.do_etw) {
        // Re-evaluate all cached processes with the new target names
        g_ProcessResolver.SetTargetNames(g_Config.targetProcessNames);
        g_ProcessResolver.RefreshTargetMatching();
    }
    
    // Kernel Config
    if (g_Config.do_kernel) {
        // Kernel driver only supports one target at a time, use the first one
        LOG_A(LOG_INFO, "Manager: Configure kernel module");
        if (!ConfigureKernelDriver(true)) {
            LOG_A(LOG_ERROR, "Manager: Could not communicate with kernel driver, aborting.");
            return FALSE;
        }
    }

    // PPL
    if (g_Config.do_etwti) {
        LOG_A(LOG_INFO, "Manager: Tell ETW-TI about new targets: %zu names", g_Config.targetProcessNames.size());
        if (!EnablePplProducer(true, g_Config.targetProcessNames, g_Config.do_defendertrace)) {
            LOG_A(LOG_ERROR, "Manager: Failed to enable PPL producer");
            return FALSE;
        }
    }

    return TRUE;
}


BOOL ManagerStart(std::vector<HANDLE>& threads) {
	LOG_A(LOG_INFO, "Manager: Starting all subsystems...");
    try {
        // Kernel: Load module, and reader
        if (g_Config.do_kernel) {
            // Kernel: Driver load
            if (!IsServiceRunning(g_Config.driverName)) {
                LOG_A(LOG_INFO, "Manager: Kernel Driver load");
                if (!LoadKernelDriver()) {
                    LOG_A(LOG_ERROR, "Manager: Kernel driver could not be loaded");
                    return FALSE;
                }
            }

            // Kernel: Start Reader Thread
            LOG_A(LOG_INFO, "Manager: Kernel Reader init");
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
            LOG_A(LOG_INFO, "Manager: Start ETW-TI PPL service");
            if (!StartThePplService()) {
                LOG_A(LOG_ERROR, "Manager: Failed to initialize PPL service");
                return FALSE;
            }

            // Start PPL Reader Thread for dedicated data pipe
            // will wait for client connection
            LOG_A(LOG_INFO, "Manager: PPL Reader init");
            if (!PplReaderInit(threads)) {
                LOG_A(LOG_ERROR, "Manager: Failed to initialize PPL reader");
                return FALSE;
            }


            // Connect to PPL service pipe
            // it will connect back to the pipe created above when we connect
            LOG_A(LOG_INFO, "Manager: Connect to ETW-TI PPL service pipe");
            if (!ConnectPplService()) {
                LOG_A(LOG_ERROR, "ETW-TI: Failed to connect to PPL service pipe");
                return FALSE;
            }

            // notify service about initial target
            LOG_A(LOG_INFO, "Manager: Configure ETW-TI PPL");
            if (!EnablePplProducer(true, g_Config.targetProcessNames, g_Config.do_defendertrace)) {
                LOG_A(LOG_ERROR, "Manager: Failed to enable PPL producer");
                return FALSE;
            }
        }

        // ETW
        if (g_Config.do_etw) {
            g_ProcessResolver.SetTargetNames(g_Config.targetProcessNames);
            LOG_A(LOG_INFO, "Manager: ETW Reader init");
            if (!InitializeEtwReader(threads)) {
                LOG_A(LOG_ERROR, "Manager: Failed to initialize ETW reader");
                return FALSE;
            }
        }

        // Kernel: Configuration (target process name etc.)
        if (g_Config.do_kernel) {
            LOG_A(LOG_INFO, "Manager: Kernel module configuration");
            if (!ConfigureKernelDriver(1)) {
                LOG_A(LOG_ERROR, "Manager: Kernel module failed");
                return FALSE;
            }
        }

        // Necessary? (wait for kernel and ETW-TI to connect)
        //Sleep(1000);

        // Populate process cache with all currently running processes
        //LOG_A(LOG_INFO, "Manager: Populating process cache with all running processes");
        if (!g_ProcessResolver.PopulateAllProcesses()) {
            LOG_A(LOG_WARNING, "Manager: Failed to populate process cache, continuing anyway");
            // Don't return FALSE here as this is not critical for core functionality
        }
        else {
            // Log cache statistics after successful population
            g_ProcessResolver.LogCacheStatistics();

            // Start cleanup thread to remove stale processes every 30 minutes
            g_ProcessResolver.StartCleanupThread(std::chrono::minutes(30));
        }

		LOG_A(LOG_INFO, "Manager: All subsystems started");

        return TRUE;
    } catch (const std::exception& e) {
        LOG_A(LOG_ERROR, "Manager: Exception in ManagerStart: %s", e.what());
        return FALSE;
    }
    catch (...) {
        LOG_A(LOG_ERROR, "Manager: FATAL unknown exception in ManagerStart (possible SEH/access violation)");
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

    // Hook / DLL injection
    if (g_Config.do_hook || g_Config.debug_dllreader) {
        LOG_A(LOG_INFO, "Manager: Stop DLL reader");
        DllReaderShutdown();
    }

    // Kernel
    if (g_Config.do_kernel) {
        // Tell the driver to stop and disconnect its pipe end.
        // This unblocks any ReadFile in the kernel reader thread before we join it.
        LOG_A(LOG_INFO, "Manager: Disable kernel driver collection");
        ConfigureKernelDriver(0);

        LOG_A(LOG_INFO, "Manager: Stop kernel reader");
        KernelReaderShutdown();
    }

    // Web server
    if (g_Config.web_output) {
        LOG_A(LOG_INFO, "Manager: Stop web server");
        StopWebServer();
    }

    // Analyzer
    LOG_A(LOG_INFO, "Manager: Stop EventProcessor");
    StopEventProcessor();

    // LogReader (stop flag only; thread polls every 1s)
    LogReaderStopAll();
}
