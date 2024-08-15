# Data Format

RedEdrDriver: 
* Lots of data received in UNICODE_STRING
* All data should be stored in WCHAR (converted from UNICODE_STRING)
* Will send WCHAR to the pipe, 2-byte null terminated

RedEdrDll:
* Uses mostly char?
* Will send WCHAR to pipe, 2-byte null terminated


## JSON result

{
  "time": xxx,
  "source": ""  // dll, krn, etw, inf
  "data": {}
}
