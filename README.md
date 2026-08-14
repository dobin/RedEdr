# RedEdr

**RedEdr is a Windows telemetry recorder for malware developers and red teamers.**

It captures the same events an ETW-based EDR would see when your tool runs, so
you can inspect and assess your detection surface before it hits a real EDR.

Point RedEdr at a process name, run your malware, and browse the resulting
telemetry (ETW, ETW-TI, kernel callbacks, `ntdll.dll` hooks, callstacks) in a
local web UI or as JSON.

RedEdr is also the recording engine behind [detonator.r00ted.ch](https://detonator.r00ted.ch).

**Who this is for:** malware developers, red teamers, and anyone reverse-engineering
Windows EDRs and telemetry.


## Screenshots

Recording a small shellcode loader:

```c
PVOID shellcodeAddr = VirtualAlloc(NULL, payloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
memcpy(shellcodeAddr, payload, payloadSize);
VirtualProtect(shellcodeAddr, payloadSize, PAGE_EXECUTE_READWRITE, &dwOldProtection);
HANDLE hThread = CreateThread(NULL, 0, shellcodeAddr, shellcodeAddr, 0, &threadId);
```

`ntdll.dll` hooks (`VirtualAlloc`, `VirtualProtect`, `CreateThread` calls with callstacks):

![RedEdr Screenshot ntdll.dll hooking](https://raw.github.com/dobin/RedEdr/master/Doc/screenshot-web-rwx-dll.png)

ETW events (kernel process/thread/image, audit API calls):

![RedEdr Screenshot ETW](https://raw.github.com/dobin/RedEdr/master/Doc/screenshot-web-rwx-etw.png)


## What RedEdr captures

| Source | Provider / mechanism |
|---|---|
| **ETW** | `Microsoft-Windows-Kernel-Process`, `Microsoft-Windows-Kernel-Audit-API-Calls`, `Microsoft-Windows-Security-Auditing` |
| **ETW (Defender)** | `Microsoft-Antimalware-Engine`, `-RTP`, `-AMFilter`, `-Scan-Interface`, `-Protection` |
| **ETW-TI** | `Microsoft-Windows-Threat-Intelligence` (via a PPL service loaded through an ELAM driver) |
| **Kernel callbacks** | `PsSetCreateProcessNotifyRoutine`, `PsSetCreateThreadNotifyRoutine`, `PsSetLoadImageNotifyRoutine` |
| **User-mode hooks** | `ntdll.dll` hooking via KAPC DLL injection (what many older EDRs used to rely on) |
| **Callstacks** | Captured on hook invocation and on selected ETW events |
| **Process context** | PEB, loaded DLLs and their section layout |

Example captured events live in [`Data/`](https://github.com/dobin/RedEdr/tree/master/Data).


## How it works

RedEdr is not one process - it is a small system of cooperating components that
talk over named pipes (`\\.\pipe\RedEdr*`):

| Component | Role |
|---|---|
| `RedEdr.exe` | Orchestrator + web UI. Consumes user-mode ETW, aggregates events from all other components, serves the HTTP API. |
| `RedEdrDriver.sys` | Kernel driver. Captures kernel callbacks and performs KAPC DLL injection into the target. Requires test-signing. |
| `RedEdrDll.dll` | Injected into the target process for `ntdll.dll` hooking (via Detours / MinHook). |
| `RedEdrPplService.exe` | PPL service. The only place from which ETW-TI can be consumed. Loaded via an ELAM driver. |
| `elam_driver.sys` | Empty, signed ELAM driver used solely to allow `RedEdrPplService` to start as PPL. |

You only need the components required by the modes you enable - see the
[Feature matrix](#feature-matrix) below.

A build deploys everything into `C:\RedEdr\`.


## Feature matrix

Pick a row based on what you want to see. Rows are additive - flags can be combined.

| I want to see… | Flags | Kernel driver? | Test-signing? | PPL service installed? |
|---|---|---|---|---|
| ETW events (user-mode) | `--etw` | No | No | No |
| ETW + `ntdll.dll` hooks | `--etw --hook` | **Yes** | **Yes** | No |
| ETW + ETW-TI | `--etw --etwti` | **Yes** | **Yes** | **Yes** |
| Everything | `--etw --etwti --hook` | **Yes** | **Yes** | **Yes** |
| Defender's Antimalware-Engine ETW | add `--with-antimalwareengine` | No | No | No |
| `MsMpEng.exe` ETW view | add `--with-defendertrace` | Better | Better | Better |

**Trace matching is a substring match on the process image path.** `--trace otepad`
matches both `notepad.exe` (Windows 10) and `Notepad.exe` (Windows 11).


## Warnings

Before you run anything:

- ⚠️ **Use a dedicated, snapshotted VM.** For disabled secure boot, enabled
  test-signing, and installed kernel driver.
- ⚠️ **Installing the PPL service (`--etwti`) is not reversible.** There is
  currently no working uninstall path. Snapshot the VM *before* the first
  `--etwti` run.
- ⚠️ **Only `C:\RedEdr\` is supported.** Paths are hardcoded in the driver and
  PPL service. Don't install anywhere else.
- ⚠️ **RedEdr looks like malware to AV.** Whitelist `C:\RedEdr\` in Defender
  (or whatever AV/EDR you have) before extracting.


## Prerequisites

- Windows 11, x64
- Local administrator (some ETW providers additionally require SYSTEM - see
  [ETW-TI mode](#etw-ti-mode-etwti))
- For `--hook` or `--etwti`: test-signing enabled and secure boot disabled
  (see [Enabling kernel-driver modes](#enabling-kernel-driver-modes))
- For building from source: Visual Studio 2022 + matching Windows SDK + WDK
  (see [Building from source](#building-from-source))


## Installation

0. Add `C:\RedEdr\` to your AV exclusions.
1. Download `release.zip` from the
   [GitHub Releases page](https://github.com/dobin/RedEdr/releases).
2. Extract to **`C:\RedEdr\`** (no other path works - paths are hardcoded).
3. Open a terminal **as Administrator** and `cd C:\RedEdr`.
4. Verify it starts:

   ```powershell
   PS C:\RedEdr> .\RedEdr.exe --help
   ```

For anything beyond plain ETW, continue with
[Enabling kernel-driver modes](#enabling-kernel-driver-modes).


## Quick Start (ETW only, no kernel driver)

The simplest mode. No reboot, no driver, no PPL.

```powershell
PS C:\RedEdr> .\RedEdr.exe --etw --trace notepad.exe
```

Then in another window, start `notepad.exe`. Open
<http://localhost:8081> in your browser - events stream in live.

Stop RedEdr with `Ctrl+C`.


## Enabling kernel-driver modes

`--hook` and `--etwti` load a self-signed kernel driver. Windows will refuse to
load it unless test-signing is enabled and secure boot is off.

**Snapshot your VM first.** Then, in an **Administrator cmd.exe** (not PowerShell -
`bcdedit` behaves better there):

```cmd
bcdedit /set testsigning on

:: Required for Win11 on Proxmox even with secure boot disabled in BIOS
bcdedit /set {bootmgr} testsigning on
bcdedit /set {current} testsigning on
bcdedit /set hypervisorlaunchtype off

bcdedit -debug on
shutdown /r /t 0
```

**Disable Secure Boot in your hypervisor as well:**

- **Hyper-V:** VM settings → Security → uncheck *Enable Secure Boot*.
- **Proxmox:** Reboot VM, mash `ESC` to enter the BIOS menu →
  *Device Manager* → *Secure Boot Configuration* → uncheck *Attempt Secure Boot*.

After the reboot, Windows will show a "Test Mode" watermark on the desktop.
Then you ready.


## Usage modes

### ETW-TI mode (`--etwti`)

Adds `Microsoft-Windows-Threat-Intelligence` events. Requires the PPL service,
which is installed permanently on first run through the ELAM driver.

```powershell
PS C:\RedEdr> .\RedEdr.exe --etw --etwti --trace notepad.exe
```

For `Microsoft-Windows-Security-Auditing` events, run RedEdr as SYSTEM
(`psexec -i -s cmd.exe`). Configure which audit categories are recorded via:

`gpedit.msc` → *Computer Configuration* → *Windows Settings* → *Security
Settings* → *Advanced Audit Policy Configuration* → *System Audit Policies –
Local Group Policy Object*.

### `ntdll.dll` hook mode (`--hook`)

KAPC-based DLL injection into the target. Records every hooked `Nt*` call with
its callstack - the classic view an older user-mode-hooking EDR would have.

```powershell
PS C:\RedEdr> .\RedEdr.exe --hook --trace notepad.exe
```

### EDR introspection (Defender)

These flags don't watch *your* process - they watch what **Defender** does in
response to your process. Great for verifying that anti-EDR techniques actually
land. See Levi's [My Hacker Blog](https://blog.levi.wiki/) and the
[EDR-Introspection](https://github.com/cailllev/EDR-Introspection) project for
context.

**`--with-antimalwareengine`** - capture `Microsoft-Antimalware-Engine` events
related to the target. Overview: [Defender Telemetry](https://blog.deeb.ch/posts/defender-telemetry/).

```powershell
PS C:\RedEdr> .\RedEdr.exe --etw --trace putty --with-antimalwareengine
```

Example event ("Defender is about to start behavior-monitoring us"):

```
Behavior Monitoring BmProcessContextStart etw etw_pid:0x1524 etw_process:MsMpEng.exe
  etw_provider_name:Microsoft-Antimalware-Engine
  imagepath:\Device\HarddiskVolume6\toolz\putty.exe pid:0x11F48
```

**`--with-defendertrace`** - capture *all* ETW events emitted by `MsMpEng.exe`
that reference our target. Overview: [Windows Telemetry](https://blog.deeb.ch/posts/windows-telemetry/).

```powershell
PS C:\RedEdr> .\RedEdr.exe --etw --etwti --trace putty --with-defendertrace
```

Example event (Defender opening a handle to our process):

```
Info etw etw_pid:0x1524 etw_process:MsMpEng.exe
  etw_provider_name:Microsoft-Windows-Kernel-Audit-API-Calls
  desiredaccess:0x1FFFFF returncode:0x0 targetprocessid:0x1524
```


## Command-line reference

```
RedEdr [OPTION...]

Input (what to record):
  --trace <name>            Substring-match on process image name (default: malware)
  --etw                     Enable ETW consumers
  --etwti                   Enable ETW-TI (requires PPL service, permanent)
  --kernel                  Enable kernel-callback consumer
  --hook                    Enable ntdll.dll hooking via KAPC injection

Input options:
  --with-defendertrace      Also record ETW events emitted by MsMpEng.exe
  --with-antimalwareengine  Also record Microsoft-Antimalware-Engine events

Output:
  --web                     Enable web UI (default: on)
  --port <n>                Web server port (default: 8081)
  --show                    Also print events to stdout

Debug / maintenance:
  --dllreader               Run only the DLL reader (for manual injection tests)
  --krnload / --krnunload   Load / unload the kernel driver
  --pplstart / --pplstop    Install / stop the PPL service
  -d, --debug               Verbose debug output
  -h, --help                Show help
```

The HTTP API is documented separately in [`Doc/api.md`](Doc/api.md).


## Verifying it works

After starting RedEdr with `--etw`:

1. Open <http://localhost:8081> - you should see the SemiDataSieve UI.
2. Run your target process (e.g. `notepad.exe`).
3. Events appear in the log pane within a second.
4. Sidebar counters (`ETW`, `ETW-TI`, `kernel`, `DLL`) should match the sources
   you enabled.

If nothing appears, see [Troubleshooting](#troubleshooting).


## Troubleshooting

| Symptom | Likely cause / fix |
|---|---|
| `--hook` or `--etwti`: driver fails to load | Test-signing not active or Secure Boot still on. Re-check the `bcdedit` output; verify the "Test Mode" watermark; confirm hypervisor settings. |
| No events at all | `--trace` substring doesn't match. Try `--trace notepad` (no `.exe`) or run with `--debug --show`. |
| `RedEdr.exe` is deleted on extraction | Defender ate it. Add `C:\RedEdr\` to exclusions **before** extracting. |
| Port 8081 already in use | `--port 8082` (or any free port). |
| ETW-TI events missing but `--etwti` set | PPL service failed to start. Check the Windows Event Viewer for `RedEdrPplService`. |
| `Microsoft-Windows-Security-Auditing` empty | Run as SYSTEM via `psexec -i -s cmd.exe` and configure audit policy in `gpedit.msc`. |


## Uninstall

- **ETW-only install:** delete `C:\RedEdr\`. That's it.
- **`--hook` install:** stop RedEdr, then `.\RedEdr.exe --krnunload`, then delete
  `C:\RedEdr\`.
- **`--etwti` install:** the PPL service currently **cannot be cleanly removed**.
  Restore your VM snapshot. This is a known limitation.


## Building from source

Requirements:

- Visual Studio 2022 ([download](https://aka.ms/vs/17/release/vs_community.exe))
  with the *Desktop development with C++* workload.
- Windows SDK **and** WDK - matching versions (e.g. both `10.0.26100`).
  Follow Microsoft's [Download the WDK](https://learn.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk)
  guide *exactly* - the WDK installer must run after the matching SDK.

Build (Debug is currently the supported configuration; artefacts deploy to
`C:\RedEdr\`):

```powershell
# Everything
msbuild RedEdr.sln /p:Configuration=Debug /p:Platform=x64

# Just the main exe
msbuild RedEdr.sln /p:Configuration=Debug /p:Platform=x64 /t:RedEdr
```

Use the *x64 Native Tools Command Prompt for VS 2022* if `msbuild` isn't on
your PATH.

The kernel driver is the fragile part. If the SDK/WDK versions don't match
exactly, driver builds silently produce broken binaries or fail cryptically.
When in doubt, uninstall both and reinstall in the order the WDK page
prescribes.


## Further reading

- [blog.deeb.ch - AI Assisted EDR Introspection](https://blog.deeb.ch/posts/defender-ai-introspection/)
- blog.deeb.ch - Defender Reversing [Opus](https://blog.deeb.ch/posts/reversing-defender-opus/) / [Qwen](https://blog.deeb.ch/posts/reversing-defender-qwen/) / [Deepseek](https://blog.deeb.ch/posts/reversing-defender-deepseek/)
- [blog.deeb.ch - Defender Introspection](https://blog.deeb.ch/posts/defender-introspection/)
- [blog.deeb.ch - Defender Telemetry](https://blog.deeb.ch/posts/defender-telemetry/)
- [blog.deeb.ch - Windows Telemetry](https://blog.deeb.ch/posts/windows-telemetry/)
- [My Hacker Blog](https://blog.levi.wiki/) (Levi)
- [EDR-Introspection](https://github.com/evilele/EDR-Introspection) (Levi)


## Credits

RedEdr is licensed under **GPLv3** (see [`LICENSE.txt`](LICENSE.txt)).

Built on top of:

- [MyDumbEdr](https://github.com/sensepost/mydumbedr) (GPLv3) -
  ["From Windows Drivers to an (almost) Fully Working EDR"](https://sensepost.com/blog/2024/sensecon-23-from-windows-drivers-to-an-almost-fully-working-edr/),
  itself based on [SylantStrike](https://github.com/CCob/SylantStrike/tree/master/SylantStrike).
  Patched fork: [dobin/mydumbedr](https://github.com/dobin/mydumbedr).
- KAPC injection from [RootkitDiaries](https://github.com/0xOvid/RootkitDiaries/) (no license).
- PPL loading from [PPLRunner](https://github.com/pathtofile/PPLRunner/) (no license).

Vendored libraries:

- [cxxopts](https://github.com/jarro2783/cxxopts) - MIT
- [cpp-httplib](https://github.com/yhirose/cpp-httplib) - MIT
- [nlohmann/json](https://github.com/nlohmann/json) - MIT
- [Microsoft Detours](https://github.com/microsoft/Detours) - MIT
- [MinHook](https://github.com/TsudaKageyu/minhook) - BSD-2-Clause
