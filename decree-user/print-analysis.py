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

# Open all files given
files = []
events = []
binary_ids = []
for name in sys.argv[1:]:
    f = open(name, "rb")

    # Check header
    magic, version, binary_id, flags = struct.unpack("<IIHH", f.read(12))

    if magic != ANALYSIS_OUTPUT_MAGIC:
        print "Invalid analysis output file"
        exit(1)
    if version != ANALYSIS_OUTPUT_VERSION:
        print "Version mismatch, file is %d but current is %d" % (version, ANALYSIS_OUTPUT_VERSION)
        exit(1)

    # Add file to file list and set its event to None so that it will be read in immediately
    files.append(f)
    events.append(None)
    binary_ids.append(binary_id)

while True:
    # Gather the next event for all files
    i = 0
    while i < len(events):
        if events[i] is not None:
            # Event already populated for this file
            i += 1
            continue

        if files[i] is None:
            # File is completed
            i += 1
            continue

        # Grab header of event
        data = files[i].read(24)
        if len(data) < 24:
            # No more data in this file
            files[i] = None
            i += 1
            continue

        # Parse event header
        event_id, length, wall_time, insn_count = struct.unpack("<IIdQ", data)

        # Grab event data contents
        contents = files[i].read(length)
        if len(contents) != length:
            print "Truncated event"
            exit(1)

        # Check for name definition events
        if event_id == ANALYSIS_DEFINE_EVENT:
            new_id = struct.unpack("<I", contents[0:4])[0]
            name = contents[4:]
            analysis_events[new_id] = name
            continue

        # Get the name for this event
        if event_id not in analysis_events:
            print "Invalid event ID"
            exit(1)

        name = analysis_events[event_id]

        # Record the event as the next event to be processed for this file
        events[i] = (name, contents, wall_time, binary_ids[i], insn_count)

    # Find the next event in all files, use wall time for the comparison
    best = None
    best_index = None
    best_time = None
    for i in xrange(0, len(events)):
        if events[i] is None:
            continue
        if (best is None) or (events[i][2] < best_time):
            best = events[i]
            best_index = i
            best_time = best[2]

    if best is None:
        # No more events in any file
        break

    # Consume this event so that a new one will be read in from the file
    events[best_index] = None
    name, contents, wall_time, binary_id, insn_count = best

    if name not in event_handler:
        # Skip events that we don't have handlers for
        continue

    # Handler for this event found, print it out
    prefix = "[%.6f %d:%.8x]" % (wall_time, binary_id, insn_count)
    event_handler[name](prefix, contents)
