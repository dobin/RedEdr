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
#include "event_detector.h"
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
    g_EventDetector.ResetData();
    g_ProcessResolver.ResetData();
    //g_MemStatic.ResetData();
    //g_MemDynamic.ResetData();
}


BOOL ManagerReload() {
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


BOOL ManagerStart(std::vector<HANDLE>& threads) {
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
        KernelReaderInit(threads);
    }

    // Load: DLL reader
    //   its important for DLL AND ETW-TI to be up
    if (g_Config.do_dllinjection || g_Config.debug_dllreader || g_Config.do_etwti) {
        // DLL: Reader start (also for ETW-TI)
        LOG_A(LOG_INFO, "Manager: InjectedDll reader thread start");
        DllReaderInit(threads);
    }

    // Load: ETW-TI
    if (g_Config.do_etwti) {
        InitPplService();
        // No reader, uses DLL-pipe
    }

    // ETW
    //   if --all, this will spend some time, making the previous shit ready
    if (g_Config.do_etw) {
        LOG_A(LOG_INFO, "Manager: ETW reader thread start");
        InitializeEtwReader(threads);
    }

    Sleep(1000); // For good measure

    // ETW-TI: Enable
    if (g_Config.do_etwti) {
        if (!EnablePplProducer(TRUE, g_Config.targetExeName)) {
            LOG_A(LOG_ERROR, "Manager: Failed to enable ETW-TI");
            // Don't return FALSE here, continue with other components
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
        InitializeLogReader(threads);
    }

    return TRUE;
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
        EnablePplProducer(FALSE, NULL);
    }
    // ETW
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
    StopEventProcessor();
}
