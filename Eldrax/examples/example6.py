# Example 6   
# @author: Danny (z3r0s)
# @category: Search.Sinks

from ghidra.program.model.address import Address
from ghidra.program.model.listing.CodeUnit import *
from ghidra.program.model.listing.Listing import *

import sys
import os

#get ghidra root directory
ghidra_default_dir = os.getcwd()

#get ghidra jython directory
jython_dir = os.path.join(ghidra_default_dir, "Ghidra", "Features", "Python", "lib", "Lib", "site-packages")

#insert jython directory into system path 
sys.path.insert(0,jython_dir)

from beautifultable import BeautifulTable
from graphviz import Digraph


sinks = [
    "strcpy",
    "memcpy",
    "gets",
    "memmove",
    "scanf",
    "lstrcpyA"
    "strcpyA", 
    "strcpyW", 
    "wcscpy", 
    "_tcscpy", 
    "_mbscpy", 
    "StrCpy", 
    "StrCpyA", 
    "StrCpyW", 
    "lstrcpy", 
    "lstrcpyA", 
    "lstrcpyW", 
    "_tccpy", 
    "_mbccpy",
    "_ftcscpy", 
    "strncpy", 
    "wcsncpy", 
    "_tcsncpy", 
    "_mbsncpy", 
    "_mbsnbcpy", 
    "StrCpyN", 
    "StrCpyNA", 
    "StrCpyNW", 
    "StrNCpy", 
    "strcpynA", 
    "StrNCpyA", 
    "StrNCpyW", 
    "lstrcpyn", 
    "lstrcpynA", 
    "lstrcpynW"
]

sink_dic = {}
duplicate = []
listing = currentProgram.getListing()
ins_list = listing.getInstructions(1)

#iterate over each instruction
while ins_list.hasNext():
    ins = ins_list.next()
    mnemonic = ins.getMnemonicString()
    ops = ins.getOpObjects(0)
    if mnemonic == "CALL":	
        try:
            target_addr = ops[0]
            func_name = None 
            
            if isinstance(target_addr,Address):
                code_unit = listing.getCodeUnitAt(target_addr)
                if code_unit is not None:
                    ref = code_unit.getExternalReference(0)	
                    if ref is not None:
                        func_name = ref.getLabel()
                    else:
                        func = listing.getFunctionAt(target_addr)
                        func_name = func.getName()

            #check if function name is in our sinks list
            if func_name in sinks and func_name not in duplicate:
                duplicate.append(func_name)
                references = getReferencesTo(target_addr)
                for ref in references:
                    call_addr = ref.getFromAddress()
                    sink_addr = ops[0]
                    parent_func_name = getFunctionBefore(call_addr).getName()

                    #check sink dictionary for parent function name
                    if sink_dic.get(parent_func_name):
                        if sink_dic[parent_func_name].get(func_name):
                            if call_addr not in sink_dic[parent_func_name][func_name]['call_address']:
                                sink_dic[parent_func_name][func_name]['call_address'].append(call_addr)
                            else:
                                sink_dic[parent_func_name] = {func_name:{"address":sink_addr,"call_address":[call_addr]}}
                    else:	
                        sink_dic[parent_func_name] = {func_name:{"address":sink_addr,"call_address":[call_addr]}}				
        except:
            pass

#instantiate graphiz
graph = Digraph("ReferenceTree")
graph.graph_attr['rankdir'] = 'LR'
duplicate = 0

#Add sinks and parent functions to a graph	
for parent_func_name,sink_func_list in sink_dic.items():
    #parent functions will be blue
    graph.node(parent_func_name,parent_func_name,style="filled",color="blue",fontcolor="white")
    for sink_name,sink_list in sink_func_list.items():
        #sinks will be colored red
        graph.node(sink_name,sink_name,style="filled",color="red",fontcolor="white")
        for call_addr in sink_list['call_address']:
	    if duplicate != call_addr:					
                graph.edge(parent_func_name,sink_name,label=call_addr.toString())
                duplicate = call_addr	

ghidra_default_path = os.getcwd()
graph_output_file = os.path.join(ghidra_default_path, "sink_and_caller.gv")

#create the graph and view it using graphiz
graph.render(graph_output_file,view=True)



