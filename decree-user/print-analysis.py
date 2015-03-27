#!/usr/bin/env python
import struct
import sys

def handle_calltrace_call(prefix, contents):
    eip, esp = struct.unpack("<II", contents)
    print "%s Call to 0x%x, esp=0x%x" % (prefix, eip, esp)

def handle_calltrace_return(prefix, contents):
    eip, esp = struct.unpack("<II", contents)
    print "%s Return to 0x%x, esp=0x%x" % (prefix, eip, esp)

ANALYSIS_OUTPUT_MAGIC = 0xbed3a629
ANALYSIS_OUTPUT_VERSION = 1
ANALYSIS_DEFINE_EVENT = 0

analysis_events = {}

event_handler = {}
event_handler["calltrace_call"] = handle_calltrace_call
event_handler["calltrace_return"] = handle_calltrace_return

if len(sys.argv) < 2:
    print "Usage: %s <filename>" % sys.argv[0]
    exit(1)

f = open(sys.argv[1], "rb")

magic, version, binary_id, flags = struct.unpack("<IIHH", f.read(12))

if magic != ANALYSIS_OUTPUT_MAGIC:
    print "Invalid analysis output file"
    exit(1)
if version != ANALYSIS_OUTPUT_VERSION:
    print "Version mismatch, file is %d but current is %d" % (version, ANALYSIS_OUTPUT_VERSION)
    exit(1)

while True:
    data = f.read(24)
    if len(data) < 24:
        break

    event_id, length, wall_time, insn_count = struct.unpack("<IIdQ", data)

    contents = f.read(length)
    if len(contents) != length:
        print "Truncated event"
        exit(1)

    if event_id == ANALYSIS_DEFINE_EVENT:
        new_id = struct.unpack("<I", contents[0:4])[0]
        name = contents[4:]
        analysis_events[new_id] = name
        continue

    if event_id not in analysis_events:
        print "Invalid event ID"
        exit(1)

    name = analysis_events[event_id]
    if name not in event_handler:
        continue

    prefix = "[%.6f %d:%.8x]" % (wall_time, binary_id, insn_count)
    event_handler[name](prefix, contents)
