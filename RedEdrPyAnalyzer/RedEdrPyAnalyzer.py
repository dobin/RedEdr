import json

file1 = "meterpreter-revhttp-nonstaged-autoload.json"
file2 = "meterpreter-revhttp-nonstaged-noautoload.json"
file3 = "meterpreter-revhttp-staged.json"
file4 = "notepad.json"
srcfile = file4


def checkRwx(event, eventStr):
    if "RWX" in eventStr or "\"0x80\"" in eventStr or "\"0x40\"" in eventStr:
        print("RWX: " + eventStr)
        return True
    return False



def checkCallstack(event, eventStr):
    if not "callstack" in event:
        return False
    
    callstackStr = str(event["callstack"])
    if "\'type\': \'0x0\'" in callstackStr:
        print("Callstack: " + eventStr)
        return True

    return False



def main(filename):
    print("Hello, World!")
    data = "[]"
    with open(filename) as f:
        data = f.read()
    data = json.loads(data)
    
    rwx = 0
    callstack = 0
    for event in data:
        #print(event)
        if (checkRwx(event, str(event))):
            rwx += 1
        if (checkCallstack(event, str(event))):
            callstack += 1
    print("RWX count: ", rwx)
    print("callstack count: ", callstack)

# main
if __name__ == '__main__':
    main("..\\Data\\" + srcfile)
