#include <stdio.h>
#include <windows.h>
#include <dbghelp.h>
#include <iostream>
#include <string.h>

#include "config.h"
#include "dllinjector.h"
#include "etwreader.h"
#include "logreader.h"
#include "kernelreader.h"
#include "webserver.h"
#include "dllreader.h"
#include "kernelinterface.h"
#include "pplmanager.h"
#include "logging.h"
#include "event_processor.h"
#include "event_aggregator.h"
#include "process_resolver.h"
#include "mem_static.h"
#include "mem_dynamic.h"


/* manager.cpp: Knows and manages all subsystems (Input's)
 *   start, stop, restart components
 *   start, stop, restart components logging
 *   set new configuration (process trace etc.)
 */


void ResetEverything() {
    g_EventAggregator.ResetData();
    g_EventProcessor.ResetData();
    g_ProcessResolver.ResetData();
    //g_MemStatic.ResetData();
    //g_MemDynamic.ResetData();
}


BOOL ManagerReload() {
    try {
        // DLL
        // -> Automatic upon connect of DLL (initiated by Kernel)

        // ETW
        // -> Automatic in ProcessCache
        
        // Kernel
        if (g_Config.do_kernelcallback || g_Config.do_dllinjection) {
            LOG_A(LOG_INFO, "Manager: Tell Kernel about new target: %s", g_Config.targetExeName.c_str());
            if (!EnableKernelDriver(g_Config.enabled, g_Config.targetExeName)) {
                LOG_A(LOG_ERROR, "Manager: Could not communicate with kernel driver, aborting.");
                return FALSE;
            }
        }

        // PPL
        if (g_Config.do_etwti) {
            LOG_A(LOG_INFO, "Manager: Tell ETW-TI about new target: %s", g_Config.targetExeName.c_str());
            if (!EnablePplProducer(g_Config.enabled, g_Config.targetExeName)) {
                LOG_A(LOG_ERROR, "Manager: Failed to enable PPL producer");
                return FALSE;
            }
        }

        return TRUE;
    }
    catch (const std::exception& e) {
        LOG_A(LOG_ERROR, "Manager: Exception in ManagerReload: %s", e.what());
        return FALSE;
    }
    catch (...) {
        LOG_A(LOG_ERROR, "Manager: Unknown exception in ManagerReload");
        return FALSE;
    }
}


BOOL ManagerStart(std::vector<HANDLE>& threads) {
    try {
        // Load: Kernel dependencies
        if (g_Config.do_kernelcallback || g_Config.do_dllinjection) {
            // Kernel: Module load
            if (! IsServiceRunning(g_Config.driverName)) {
                LOG_A(LOG_INFO, "Manager: Kernel Driver load");
                if (!LoadKernelDriver()) {
                    LOG_A(LOG_ERROR, "Manager: Kernel driver could not be loaded");
                    return FALSE;
                }
            }

            // Kernel: Reader Threads start
            LOG_A(LOG_INFO, "Manager: Kernel reader thread start");
            if (!KernelReaderInit(threads)) {
                LOG_A(LOG_ERROR, "Manager: Failed to initialize kernel reader");
                return FALSE;
            }
        }

    // Load: DLL reader
    //   its important for DLL AND ETW-TI to be up
    if (g_Config.do_dllinjection || g_Config.debug_dllreader || g_Config.do_etwti) {
        // DLL: Reader start (also for ETW-TI)
        LOG_A(LOG_INFO, "Manager: InjectedDll reader thread start");
        if (!DllReaderInit(threads)) {
            LOG_A(LOG_ERROR, "Manager: Failed to initialize DLL reader");
            return FALSE;
        }
    }

    // Load: ETW-TI
    if (g_Config.do_etwti) {
        if (!InitPplService()) {
            LOG_A(LOG_ERROR, "Manager: Failed to initialize PPL service");
            return FALSE;
        }
        // No reader, uses DLL-pipe
    }

    // ETW
    //   if --all, this will spend some time, making the previous shit ready
    if (g_Config.do_etw) {
        if (!InitializeEtwReader(threads)) {
            LOG_A(LOG_ERROR, "Manager: Failed to initialize ETW reader");
            return FALSE;
        }
    }

    Sleep(1000); // For good measure

    // ETW-TI: Enable
    if (g_Config.do_etwti) {
        if (!EnablePplProducer(TRUE, g_Config.targetExeName)) {
            LOG_A(LOG_ERROR, "Manager: Failed to enable ETW-TI");
            return FALSE;  // Make this a hard failure for consistency
        }
    }
    // Kernel: Enable
    if (g_Config.do_kernelcallback || g_Config.do_dllinjection) {
        // Enable it
        LOG_A(LOG_INFO, "Manager: Kernel module enable collection");
        // Even with all the other code carefully making sure that all the shit is started, it still seems to need this sleep
        if (!EnableKernelDriver(1, g_Config.targetExeName)) {
            LOG_A(LOG_ERROR, "Manager: Kernel module failed");
            return FALSE;
        }
    }

    // Necessary? (wait for kernel and ETW-TI to connect)
    Sleep(1000);

    // Not really used
    if (g_Config.do_mplog) {
        LOG_A(LOG_INFO, "Manager: MPLOG Start Reader");
        if (!InitializeLogReader(threads)) {
            LOG_A(LOG_ERROR, "Manager: Failed to initialize MPLOG reader");
            return FALSE;
        }
    }

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
    g_EventAggregator.StopRecorder();

    if (g_Config.do_mplog) {
        LOG_A(LOG_INFO, "Manager: Stop log reader");
        LogReaderStopAll();
    }

    // Lets shut down ETW stuff first, its more important
    // ETW-TI
    if (g_Config.do_etwti) {
        LOG_A(LOG_INFO, "Manager: Stop ETWTI reader");
        EnablePplProducer(FALSE, "");  // Use empty string instead of NULL
    }
    // ETWTracing processes with name: Shellcode
    if (g_Config.do_etw) {
        LOG_A(LOG_INFO, "Manager: Stop ETW readers");
        EtwReaderStopAll();
    }

    // Make kernel module stop emitting events
    //    Disconnects KernelPipe client
    if (g_Config.do_kernelcallback || g_Config.do_dllinjection) {
        LOG_A(LOG_INFO, "Manager: Disable kernel driver");
        EnableKernelDriver(0, "");
    }

    // The following may crash?
    // Shutdown kernel reader
    if (g_Config.do_kernelcallback) {
        LOG_A(LOG_INFO, "Manager: Stop kernel reader");
        KernelReaderShutdown();
    }
    // Shutdown dll reader
    if (g_Config.do_dllinjection || g_Config.do_etwti) {
        LOG_A(LOG_INFO, "Manager: Stop DLL reader");
        DllReaderShutdown();
    }

    // Special case
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
