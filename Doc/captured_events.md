# Captured Events 

Examples of captured events of a meterpreter load, beautified. 


##  Process Info Events

```
type:peb time:133770294491342048
  id:5296 parent_pid:6904 is_debugged:0 is_protected_process:0 is_protected_process_light:0 
  image_base:0x00007FF6ECCE0000
  image_path:C:\\RedEdr\\msf\\loader.exe
  commandline:loader.exe meterpreter-revhttp-nonstaged-autoload.bin
  working_dir:C:\\RedEdr\\msf\\
```


## Kernel Events

```
process_create type:kernel time:133770294491342048 krn_pid:6904 pid:5296 ppid:6904 observe:1
  name:\\Device\\HarddiskVolume2\\RedEdr\\msf\\loader.exe
  parent_name:\\Device\\HarddiskVolume2\\Windows\\System32\\cmd.exe

image_load type:kernel time:133770294491342048 krn_pid:5296 pid:5296
  image:\\Device\\HarddiskVolume2\\RedEdr\\msf\\loader.exe

image_load type:kernel time:133770294491342048 krn_pid:5296 pid:5296
  image:\\Device\\HarddiskVolume2\\Windows\\System32\\ntdll.dll

image_load type:kernel time:133770294491342048 krn_pid:5296 pid:5296
  image:\\Device\\HarddiskVolume2\\Windows\\System32\\kernel32.dll

thread_create type:kernel time:133770294491967024 krn_pid:4 pid:5296
  threadid:6008 create:1
```


## DLL Hook events

```
ProtectVirtualMemory type:dll time:133770294497279534 pid:5296 tid:2944
  handle:0xffffffffffffffff 
  addr:0x1e7f46a8000 
  size:413696 
  protect:RWX 
  return:0
  callstack:
    [{idx:0, addr:0x7ffa2d499491, size:131072, state:0x2d4bd698, protect:R-X, type:IMAGE},
     {idx:1, addr:0x7ffa2d49f809, size:106496, state:0x2d4bd698, protect:R-X, type:IMAGE},
     {idx:2, addr:0x7ffa3623c6f6, size:843776, state:0x2d4bd698, protect:R-X, type:IMAGE},
     {idx:3, addr:0x1e7f2e1638e, size:118784, state:0x2d4bd698, protect:R-X, type:PRIVATE},
     {idx:4, addr:0x65000, size:2146938880, state:0x2d4bd670, protect:NOACCESS, type:Unknown},
     {idx:5, addr:0x1e7f46a8000, size:413696, state:0x2d4bd698, protect:RWX, type:PRIVATE}]

AllocateVirtualMemory type:dll time:133770294497279534 pid:5296 tid:2944
  handle:0xffffffffffffffff 
  addr:0x1e7f31a0000 
  zero:0 
  size:438272 
  size_req:438272 
  alloc_type:0x3000 
  protect:RW- 
  return:0

NtCreateSection type:dll time:133770294497279534 pid:5296 tid:2944
  section_handle:0x0x2f0 
  access_mask:0xd 
  max_size:0x0x0 
  page_protection:0x10 
  alloc_attributes:0x1000000 
  file_handle:0x0x308
  callstack:
    [{idx:0, addr:0x7ffa2d499491, size:131072, state:0x2d4bd698, protect:R-X, type:IMAGE}, 
     {idx:1, addr:0x7ffa2d49c590, size:118784, state:0x2d4bd698, protect:R-X, type:IMAGE}, 
     {idx:2, addr:0x7ffa385111ee, size:770048, state:0x2d4bd698, protect:R-X, type:IMAGE}, 
     {idx:3, addr:0x7ffa38510ca0, size:774144, state:0x2d4bd698, protect:R-X, type:IMAGE}, 
     {idx:4, addr:0x7ffa38510160, size:774144, state:0x2d4bd698, protect:R-X, type:IMAGE}, 
     {idx:5, addr:0x7ffa384cfb53, size:1040384, state:0x2d4bd698, protect:R-X, type:IMAGE}]
```


## ETW Events

Kernel-Process:
```
StartThread type:etw time:133770294494966600 pid:5296 thread_id:5976 provider_name:Microsoft-Windows-Kernel-Process
  ProcessID:5296 
  ThreadID:3300 
  StackBase:0x0000024A2306C360 StackLimit:0x0000024A2306B820 UserStackBase:0x0000024A2306BD70 UserStackLimit:0x0000024A2306C180 
  StartAddr:0x0000024A2306BC80 Win32StartAddr:0x0000024A2306BC80
  TebBase:0x0000024A2306B820 SubProcessTag:0

LoadImage type:etw time:133770294495038884 pid:5296 thread_id:3300 provider_name:Microsoft-Windows-Kernel-Process
  ImageBase:0x0000024A2306BD70 
  ImageSize:0x0000024A2306BFF0 
  ProcessID:5296 
  ImageCheckSum:136545 
  TimeDateStamp:3662695069 
  DefaultBase:0x0000024A2306CF40 
  ImageName:\\Device\\HarddiskVolume2\\Windows\\System32\\cryptsp.dll
```


## ETW-TI Events

```
ALLOCVM_LOCAL type:etw time:133770294491496070 pid:5296 thread_id:5976 provider_name:Microsoft-Windows-Threat-Intelligence
  BaseAddress:0x000001C79B58DA90 
  RegionSize:0x000001C79B58D770 
  AllocationType:12288 
  ProtectionMask:rwx

PROTECTVM_LOCAL type:etw time:133770294491496374 pid:5296 thread_id:5976 provider_name:Microsoft-Windows-Threat-Intelligence
  BaseAddress:0x000001C79B58D630 
  RegionSize:0x000001C79B58D720 
  ProtectionMask:rwx 
  LastProtectionMask:r-x
  stack_trace:
  [
     {idx:0, addr:0x7ffa2d499491, type:IMAGE}, 
     {idx:1, addr:0x7ffa2d49c590, type:IMAGE}, 
     {idx:2, addr:0x7ffa385111ee, type:IMAGE}, 
     {idx:3, addr:0x7ffa38510ca0, type:IMAGE}, 
     {idx:4, addr:0x7ffa38510160, type:IMAGE}, 
     {idx:5, addr:0x7ffa384cfb53, type:IMAGE}
  ]
```
