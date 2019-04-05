# Example 4
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
        "lstrcpy", 
        #...
	]

duplicate = []
listing = currentProgram.getListing()
func = getFirstFunction()

while func is not None:

    func_name = func.getName()

    if func_name in sinks and func_name not in duplicate:

        duplicate.append(func_name)
        entry_point = func.getEntryPoint()
        references = getReferencesTo(entry_point)

        for ref in references:

            sink_func_addr = ref.getToAddress()
            call_addr = ref.getFromAddress()
            ins = listing.getInstructionAt(call_addr)

            if ins is not None:
                mnemonic = ins.getMnemonicString()

                if mnemonic == "CALL":
                    print (func_name,sink_func_addr,call_addr)

    func = getFunctionAfter(func)
