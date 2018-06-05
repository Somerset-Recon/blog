#!/usr/bin/env python
#---------------------------------------------------------------------
# Introduction to IDAPython for Vulnerabiliity Hunting
# 
# Author: Zach Miller, Somerset Recon
#
#---------------------------------------------------------------------

# A function to determine if an operand of an instruction is located on the stack. This is used for finding stack buffers 
# that have the potential to be overflowed
#
# @param addr - the address of the instruction with the operand that we are checking 
# @param idx  - the index of the operand that we are checking whether it is on the stack
#
# Returns a True if the specified operand is on the stack
#
def is_stack_buffer(addr, idx):
    inst = DecodeInstruction(addr)
    return get_stkvar(inst[idx], inst[idx].addr) != None

# A function that finds a specified argument to a function call 
#
# @param addr - the address of the function call
# @param arg_num - the index of the parameter that we are interested 
#
# Returns the operand that corresponds to the specified argument
#
def find_arg(addr, arg_num):
    function_head = GetFunctionAttr(addr, idc.FUNCATTR_START)    # Get the start address of the function that we are in
    steps = 0
    arg_count = 0
    while steps < 100:    # It is unlikely the arguments are 100 instructions away, include this as a safety check
        steps = steps + 1
        addr = idc.PrevHead(addr)    # Get the previous instruction        
        op = GetMnem(addr).lower() # Get the name of the previous instruction

        # Check to ensure that we havent reached anything that breaks sequential code flow
        if op in ("ret", "retn", "jmp", "b") or addr < function_head: 
            return
        if op == "push":
            arg_count = arg_count + 1
            if arg_count == arg_num:
                return GetOpnd(addr, 0) # Return the operand that was pushed to the stack

for functionAddr in Functions():
    if "strcpy" in GetFunctionName(functionAddr): # Check each function to look for strcpy
        xrefs = CodeRefsTo(functionAddr, False) 
        for xref in xrefs:                                    # Iterate over each cross-reference
            if GetMnem(xref).lower() == "call":  # Check to see if this cross-reference is a function call
                opnd = find_arg(xref, 1) # Since the dest is the first argument of strcpy
                function_head = GetFunctionAttr(xref, idc.FUNCATTR_START)
                addr = xref
                _addr = xref

                while True:
                    _addr = idc.PrevHead(_addr)
                    _op = GetMnem(_addr).lower()

                    if _op in ("ret", "retn", "jmp", "b") or _addr < function_head:
                        break
                    elif _op == "lea" and GetOpnd(_addr, 0) == opnd:
                        # We found the destination buffer, check to see if it is in the stack
                        if is_stack_buffer(_addr, 1):
                            print "STACK BUFFER STRCOPY FOUND at 0x%X" % addr 
                            break
                    # If we detect that the register that we are trying to locate comes from some other register 
                    # then we update our loop to begin looking for the source of the data in that other register
                    elif _op == "mov" and GetOpnd(_addr, 0) == opnd:
                        op_type = GetOpType(_addr, 1)
                        if op_type == o_reg:
                            opnd = GetOpnd(_addr, 1)
                            addr = _addr
                        else:
                            break
