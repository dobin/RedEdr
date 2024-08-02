#include <stdio.h>
#include <windows.h>
#include <dbghelp.h>
#include <wintrust.h>
#include <Softpub.h>
#include <wincrypt.h>

#include "etwreader.h"
#include "kernelcom.h"


int main() {
    int a = 1;

    if (a == 1) {
        etwreader();
    }
    else {
        kernelcom();
    }
    return 0;
}