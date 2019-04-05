# Example 5
# @author: Danny (z3r0s)
# @category: Search.Sinks

sinks = [
        "strcpy",
        "memcpy",
        "gets",
        "memmove",
        "scanf",
        "strcpyA",
        "strcpyW",
        "wcscpy",
        "_tcscpy",
        "_mbscpy",
        "StrCpy",
        "StrCpyA",
        "lstrcpyA",
        "lstrcpy"
        #...
        ]


duplicate = []
fm = currentProgram.getFunctionManager()
ext_fm = fm.getExternalFunctions()

while ext_fm.hasNext():
    ext_func = ext_fm.next()
    target_func = ext_func.getName()
    if target_func in sinks and target_func not in duplicate:
        duplicate.append(target_func)
        loc = ext_func.getExternalLocation()
        
        sink_func_addr = loc.getAddress()
        
        if sink_func_addr is None:
            sink_func_addr = ext_func.getEntryPoint()

        if sink_func_addr is not None:
            references = getReferencesTo(sink_func_addr)
            for ref in references:
                call_addr = ref.getFromAddress()
                ins = listing.getInstructionAt(call_addr)
                mnemonic = ins.getMnemonicString()
                if mnemonic == "CALL":
                    print (target_func,sink_func_addr,call_addr)
