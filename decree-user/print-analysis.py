#!/usr/bin/env python
import struct
import sys
import analysis

def handle_calltrace_call(wall_time, binary_id, insn_count, contents):
	prefix = "[%.6f %d:%.8x]" % (wall_time, binary_id, insn_count)
	from_eip, to_eip, esp = struct.unpack("<III", contents)
	print "%s Call to 0x%x from 0x%x, esp=0x%x" % (prefix, to_eip, from_eip, esp)

def handle_calltrace_return(wall_time, binary_id, insn_count, contents):
	prefix = "[%.6f %d:%.8x]" % (wall_time, binary_id, insn_count)
	from_eip, to_eip, esp = struct.unpack("<III", contents)
	print "%s Return to 0x%x from 0x%x, esp=0x%x" % (prefix, to_eip, from_eip, esp)

def handle_branch(wall_time, binary_id, insn_count, contents):
	prefix = "[%.6f %d:%.8x]" % (wall_time, binary_id, insn_count)
	branch_type, from_eip, to_eip = struct.unpack("<III", contents)
	if branch_type > 4:
		return
	type_name = ["Call", "Return", "Jump", "Conditional (not taken)", "Conditional (taken)"][branch_type]
	print "%s %s from 0x%x to 0x%x" % (prefix, type_name, from_eip, to_eip)

def handle_instruction(wall_time, binary_id, insn_count, contents):
	prefix = "[%.6f %d:%.8x]" % (wall_time, binary_id, insn_count)
	eip = struct.unpack("<I", contents[0:4])[0]
	bytestr = contents[4:].encode("hex")
	print "%s 0x%x  %s" % (prefix, eip, bytestr)

def handle_instruction_disasm(wall_time, binary_id, insn_count, contents):
	prefix = "[%.6f %d:%.8x]" % (wall_time, binary_id, insn_count)
	eip = struct.unpack("<I", contents[0:4])[0]
	print "%s 0x%x  %s" % (prefix, eip, contents[4:])

def handle_instruction_regs(wall_time, binary_id, insn_count, contents):
	prefix = "[%.6f %d:%.8x]" % (wall_time, binary_id, insn_count)
	eip, eax, ecx, edx, ebx, esp, ebp, esi, edi = struct.unpack("<IIIIIIIII", contents[0:36])
	bytestr = contents[36:].encode("hex")
	print "%s eax=%.8x ecx=%.8x edx=%.8x ebx=%.8x" % (prefix, eax, ecx, edx, ebx)
	print "%s esp=%.8x ebp=%.8x esi=%.8x edi=%.8x" % (" " * len(prefix), esp, ebp, esi, edi)
	print "%s 0x%x  %s" % (" " * len(prefix), eip, bytestr)

def handle_instruction_regs_disasm(wall_time, binary_id, insn_count, contents):
	prefix = "[%.6f %d:%.8x]" % (wall_time, binary_id, insn_count)
	eip, eax, ecx, edx, ebx, esp, ebp, esi, edi = struct.unpack("<IIIIIIIII", contents[0:36])
	print "%s eax=%.8x ecx=%.8x edx=%.8x ebx=%.8x" % (prefix, eax, ecx, edx, ebx)
	print "%s esp=%.8x ebp=%.8x esi=%.8x edi=%.8x" % (" " * len(prefix), esp, ebp, esi, edi)
	print "%s 0x%x  %s" % (" " * len(prefix), eip, contents[36:])

def handle_perf(wall_time, binary_id, insn_count, contents):
	prefix = "[%.6f %d:%.8x]" % (wall_time, binary_id, insn_count)
	mem_pages = struct.unpack("<I", contents[0:4])[0]
	print "%s Mem usage %d pages, CPU usage %d instructions" % (prefix, mem_pages, insn_count)

event_handler = {}
event_handler["calltrace_call"] = handle_calltrace_call
event_handler["calltrace_return"] = handle_calltrace_return
event_handler["branch"] = handle_branch
event_handler["instruction"] = handle_instruction
event_handler["instruction_regs"] = handle_instruction_regs
event_handler["instruction_disasm"] = handle_instruction_disasm
event_handler["instruction_regs_disasm"] = handle_instruction_regs_disasm
event_handler["perf"] = handle_perf

if len(sys.argv) < 2:
	print "Usage: %s <filename>" % sys.argv[0]
	exit(1)

analysis.read_analysis(sys.argv[1:], event_handler)

