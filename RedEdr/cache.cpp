#include <stdio.h>
#include <windows.h>
#include <dbghelp.h>
#include <wintrust.h>
#include <Softpub.h>
#include <wincrypt.h>
#include <iostream>
#include <unordered_map>
#include <memory>
#include <tchar.h>

#include "procinfo.h"
#include "cache.h"


Cache g_cache;


void test() {
    //Cache cache;

    // Try to retrieve an object (which will be created if not found)
    Process* obj = g_cache.getObject(9592); // admin, c:\temp
    if (obj) {
        obj->display();
    }

    /*obj = cache.getObject(2460);
    if (obj) {
        obj->display();
    }*/
}
