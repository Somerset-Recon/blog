# Example 2
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

program_sinks = {}
listing = currentProgram.getListing()
ins_list = listing.getInstructions(1)

fm = currentProgram.getFunctionManager()
ext_fm = fm.getExternalFunctions()

#iterate through each of the external functions to build a dictionary
#of external functions and their addresses
while ext_fm.hasNext():
    ext_func = ext_fm.next()
    target_func = ext_func.getName()
   
    #if the function is a sink then add it's address to a dictionary
    if target_func in sinks: 
        loc = ext_func.getExternalLocation()
        sink_addr = loc.getAddress()
        sink_func_name = loc.getLabel()
        program_sinks[sink_addr] = sink_func_name

#iterate through each instruction 
while ins_list.hasNext():
    ins = ins_list.next()
    ops = ins.getOpObjects(0)
    mnemonic = ins.getMnemonicString()

    #check to see if the instruction is a call instruction
    if mnemonic == "CALL":
        try:
            #get address of operand
            target_addr = ops[0]   
            #check to see if address exists in generated sink dictionary
            if program.sinks.get(target_addr):
                print (program_sinks[target_addr],target_addr,ins.getAddress()) 
        except:
            pass
