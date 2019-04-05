# Attempt to identify the sinks and thier calling functions
# @author: Danny (z3r0s)
# @category: Search.Sinks
# @keybindings ctrl alt shift e

from ghidra.program.model.address.Address import *
from ghidra.program.model.listing.CodeUnit import *
from ghidra.program.model.listing.Listing import *

import time
import sys
import os

ghidra_default_dir = os.getcwd()

jython_dir = os.path.join(ghidra_default_dir, "Ghidra", "Features", "Python", "lib", "Lib", "site-packages")

#insert path
sys.path.insert(0,jython_dir)

from beautifultable import BeautifulTable
from graphviz import Graph


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


execute_func_list = [

					"system",
					"execve",
					"execvp",
					"execlp",
					"execle",
					"execvpe"


					]



sink_dic = {}
exec_dic = {}

duplicate = []

listing = currentProgram.getListing()
ins_list = listing.getInstructions(1)

while ins_list.hasNext():

	ins = ins_list.next()

	mnemonic = ins.getMnemonicString()
	ops = ins.getOpObjects(0)


	if mnemonic == "CALL":

		try:
			target_addr = ops[0]

			code_unit = listing.getCodeUnitAt(target_addr)
			ref = code_unit.getExternalReference(0)
			func_name = ref.getLabel()

			if func_name in sinks and func_name not in duplicate:
				duplicate.append(func_name)
				references = getReferencesTo(target_addr)

				for ref in references:
					call_addr = ref.getFromAddress()
					sink_addr = ops[0]

					parent_func_name = getFunctionBefore(call_addr).getName()

					if sink_dic.get(parent_func_name,None) is not None:
						if sink_dic[parent_func_name].get(func_name,None) is not None:
							if call_addr not in sink_dic[parent_func_name][func_name]['call_address']:
								sink_dic[parent_func_name][func_name]['call_address'].append(call_addr)
						else:
							sink_dic[parent_func_name] = {func_name:{"address":sink_addr,"call_address":[call_addr]}}

					else:
						sink_dic[parent_func_name] = {func_name:{"address":sink_addr,"call_address":[call_addr]}}

		except:
			pass



user_choice = askChoice("Format Settings","Options",["Text","Json","Graph"],["Text","Json","Graph"])

if user_choice == "Text":


	sink_table = BeautifulTable(max_width=200,default_alignment=BeautifulTable.ALIGN_CENTER)
	exec_table = BeautifulTable(max_width=200,default_alignment=BeautifulTable.ALIGN_CENTER)

	sink_table.column_headers = ["Parent Function","Sink Name","Sink Address","Call Address"]


	sink_table.left_padding_widths['Parent Function'] = 5
	sink_table.right_padding_widths['Parent Function'] = 5


	sink_table.left_padding_widths['Call Address'] = 10
	sink_table.right_padding_widths['Call Address'] = 10


	exec_table.column_headers = ["Parent Function","Exec Function Name","Exec Function Address","Call Address"]

	exec_table.left_padding_widths['Parent Function'] = 5
	exec_table.right_padding_widths['Parent Function'] = 5


	exec_table.left_padding_widths['Call Address'] = 10
	exec_table.right_padding_widths['Call Address'] = 10

	func_flag = 0

	for parent_func_name,sink_func_list in sink_dic.items():
		for sink_name,sink_list in sink_func_list.items():
			if not func_flag:

				sink_table.append_row([parent_func_name,sink_name,sink_list["address"],", ".join(["%s" % (ref) for ref in sink_list["call_address"]])])

				func_flag = 1

			else:

				sink_table.append_row(["",sink_name,sink_list["address"],", ".join(["%s" % (ref) for ref in sink_list["call_address"]])])

		func_flag = 0


	print (sink_table)


	exec_flag = 0

	for parent_func_name,exec_func_list in exec_dic.items():
		for exec_func_name,exec_list in exec_func_list.items():
			if not func_flag:
				exec_table.append_row([parent_func_name,exec_func_name,exec_list["address"],", ".join(["%s" % (ref) for ref in exec_list["call_address"]])])
				exec_flag = 1
			else:
				exec_table.append_row(["",exec_func_name,exec_list["address"],", ".join(["%s" % (ref) for ref in exec_list["call_address"]])])

		exec_flag = 0

	print (exec_table)

elif user_choice == "Json":

	fmt = lambda x : x*40

	print (fmt("="))
	print ("Sinks")
	print (fmt("="))
	print (sink_dic)

	print (fmt("="))
	print ("Exec Functions")
	print (fmt("="))
	print (exec_dic)


else:

	graph = Graph("ReferenceTree")
	graph.graph_attr['rankdir'] = 'LR'

	duplicate = 0

	for parent_func_name,sink_func_list in sink_dic.items():
		graph.node(parent_func_name,parent_func_name,style="filled",color="blue",fontcolor="white")
		for sink_name,sink_list in sink_func_list.items():
			graph.node(sink_name,sink_name,style="filled",color="red",fontcolor="white")
			for call_addr in sink_list['call_address']:
				if duplicate != call_addr:
					graph.edge(parent_func_name,sink_name,label=call_addr.toString())
					duplicate = call_addr

	file_output = os.path.join(ghidra_default_dir,"sink_and_caller.gv")
	graph.render(file_output,view=True)





monitor.initialize(3)
for i in range(3):
	monitor.checkCanceled()
	time.sleep(1)
	monitor.incrementProgress(1)
	monitor.setMessage("Running...."+str(i))