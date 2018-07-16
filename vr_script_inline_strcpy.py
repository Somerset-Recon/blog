#!/usr/bin/env python
#---------------------------------------------------------------------
# Introduction to IDAPython for Vulnerabiliity Hunting (Part 2)
#      Searching for Inline strcpy() functions
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

info = idaapi.get_inf_structure()
ea = 0

def twos_compl(val, bits=32):
    """compute the 2's complement of int value val"""
    if (val & (1 << (bits - 1))) != 0: # if sign bit is set e.g., 8bit: 128-255
        val = val - (1 << bits)        # compute negative value
    return val                         # return positive value as is
    
def is_stack_buffer(addr, idx):
    inst = DecodeInstruction(addr)

    # IDA < 7.0
    try:
        ret = get_stkvar(inst[idx], inst[idx].addr) != None
    # IDA >= 7.0
    except:
        from ida_frame import *
        v = inst[idx].addr
        if sys.maxint < v:
            v = twos_compl(v)
        ret = get_stkvar(inst, inst[idx], v)
    return ret

while ea != BADADDR:
    addr = FindText(ea+2,SEARCH_DOWN|SEARCH_NEXT, 0, 0, "rep movsd");
    ea = addr
    _addr = ea
    if "movsb" in GetDisasm(addr+7):
        opnd = "edi" # Make variable based on architecture
        if info.is_64bit():
            opnd = "rdi"
        
        val = None
        function_head = GetFunctionAttr(_addr, idc.FUNCATTR_START)
        while True:
            _addr = idc.PrevHead(_addr)
            _op = GetMnem(_addr).lower()

            if _op in ("ret", "retn", "jmp", "b") or _addr < function_head:
                break
            elif _op == "lea" and GetOpnd(_addr, 0) == opnd:
                # We found the origin of the destination, check to see if it is in the stack
                if is_stack_buffer(_addr, 1):
                    print "0x%X"%ea
                    break
                else: break
            elif _op == "mov" and GetOpnd(_addr, 0) == opnd:
                op_type = GetOpType(_addr, 1)
                if op_type == o_reg:
                    opnd = GetOpnd(_addr, 1)
                    addr = _addr
                else:
                    break
