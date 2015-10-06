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

def handle_mem_read(wall_time, binary_id, insn_count, contents):
	prefix = "[%.6f %d:%.8x]" % (wall_time, binary_id, insn_count)
	addr = struct.unpack("<I", contents[0:4])[0]
	value = contents[4:]
	print "%s Read address %.8x, value %s" % (prefix, addr, value[::-1].encode("hex"))

def handle_mem_write(wall_time, binary_id, insn_count, contents):
	prefix = "[%.6f %d:%.8x]" % (wall_time, binary_id, insn_count)
	addr = struct.unpack("<I", contents[0:4])[0]
	value = contents[4:]
	print "%s Write address %.8x, value %s" % (prefix, addr, value[::-1].encode("hex"))

def handle_perf(wall_time, binary_id, insn_count, contents):
	prefix = "[%.6f %d:%.8x]" % (wall_time, binary_id, insn_count)
	mem_pages = struct.unpack("<I", contents[0:4])[0]
	print "%s Mem usage %d pages, CPU usage %d instructions" % (prefix, mem_pages, insn_count)

def handle_log(wall_time, binary_id, insn_count, contents):
	prefix = "[%.6f %d:%.8x]" % (wall_time, binary_id, insn_count)
	name_len = struct.unpack("<I", contents[0:4])[0]
	name = contents[4:4+name_len]
	desc = contents[4+name_len:]
	print "%s %s: %s" % (prefix, name, desc)

def handle_invalid_instr_from_input(wall_time, binary_id, insn_count, contents):
	prefix = "[%.6f %d:%.8x]" % (wall_time, binary_id, insn_count)
	computed = struct.unpack("<B", contents[0])[0] != 0
	offset_valid = struct.unpack("<B", contents[1])[0] != 0
	offset = struct.unpack("<I", contents[4:8])[0]
	if computed:
		print "%s Invalid eip computed from input" % prefix
	elif offset_valid:
		print "%s Invalid eip copied from input offset 0x%x" % (prefix, offset)
	else:
		print "%s Invalid eip copied from input"

def handle_invalid_mem_from_input(wall_time, binary_id, insn_count, contents):
	prefix = "[%.6f %d:%.8x]" % (wall_time, binary_id, insn_count)
	computed = struct.unpack("<B", contents[0])[0] != 0
	offset_valid = struct.unpack("<B", contents[1])[0] != 0
	offset = struct.unpack("<I", contents[4:8])[0]
	if computed:
		print "%s Invalid address computed from input" % prefix
	elif offset_valid:
		print "%s Invalid address copied from input offset 0x%x" % (prefix, offset)
	else:
		print "%s Invalid address copied from input"

event_handler = {}
event_handler["calltrace_call"] = handle_calltrace_call
event_handler["calltrace_return"] = handle_calltrace_return
event_handler["branch"] = handle_branch
event_handler["instruction"] = handle_instruction
event_handler["instruction_regs"] = handle_instruction_regs
event_handler["instruction_disasm"] = handle_instruction_disasm
event_handler["instruction_regs_disasm"] = handle_instruction_regs_disasm
event_handler["mem_read"] = handle_mem_read
event_handler["mem_write"] = handle_mem_write
event_handler["perf"] = handle_perf
event_handler["log"] = handle_log
event_handler["invalid_instr_from_input"] = handle_invalid_instr_from_input
event_handler["invalid_mem_from_input"] = handle_invalid_mem_from_input

def print_analysis(files):
	global event_handler
	analysis.read_analysis(files, event_handler)

if __name__ == "__main__":
	if len(sys.argv) < 2:
		print "Usage: %s <filename>" % sys.argv[0]
		exit(1)

	analysis.read_analysis(sys.argv[1:], event_handler)
