# Data Format

RedEdrDriver pipe: 
* Lots of data received in UNICODE_STRING
* All data should be stored in WCHAR (converted from UNICODE_STRING)
* Will send WCHAR to the pipe, 2-byte null terminated

RedEdrDll pipe:
* Uses mostly char?
* Will send WCHAR to pipe, 2-byte null terminated


RedEdrDriver IOCTL: 
* Receive struct with char
* Send char status back



## JSON result

{
  "time": xxx,
  "source": ""  // dll, krn, etw, inf
  "data": {}
}
