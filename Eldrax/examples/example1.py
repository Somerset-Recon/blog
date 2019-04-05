# Example 1
# @author: Danny (z3r0s)
# @category: Search.Sinks
# Linear search example (expected failure)

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
ins_list = listing.getInstructions(1)

#iterate through each instruction
while ins_list.hasNext():
    ins = ins_list.next()
    ops = ins.getOpObjects(0)
    mnemonic = ins.getMnemonicString()

    #check to see if the instruction is a call instruction
    if mnemonic == "CALL":
        try:
            target_addr = ops[0]
            sink_func = listing.getFunctionAt(target_addr)
            sink_func_name = sink_func.getName()
            #check to see if function being called is in the sinks list
            if sink_func_name in sinks and sink_func_name not in duplicate:
                duplicate.append(sink_func_name)
                print (sink_func_name,target_addr)
        except:
	        pass
