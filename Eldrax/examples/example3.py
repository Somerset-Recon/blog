# Example 3
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
func = getFirstFunction()

while func is not None:
    func_name = func.getName()
    #check if function name is in sinks list
    if func_name in sinks and func_name not in duplicate:
        duplicate.append(func_name)
        entry_point = func.getEntryPoint()
        references = getReferencesTo(entry_point)
	#print cross-references    
        print(references)

    func = getFunctionAfter(func)
