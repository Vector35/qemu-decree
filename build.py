#!/usr/bin/env python
import os
import sys
import subprocess
import zipfile
import glob
import shutil

if len(sys.argv) < 3:
	print "Usage: build.py <os> <build_number>"
	sys.exit(1)

def linux_build():
	# Clean existing files
	for f in glob.glob("*.zip"):
		os.unlink(f)
	if os.path.exists("i386-decree-user"):
		shutil.rmtree("i386-decree-user")

	# Build the project with a clean build
	ok = subprocess.call("./configure --target-list=i386-decree-user --disable-system && make clean && make -j5", shell = True) == 0
	if not ok:
		print "Build failed, aborting"
		return False

	# Create archive of executables
	name = "qemu_decree_linux_%s.zip" % sys.argv[2]
	print "Creating " + name
	if os.path.exists(name):
		os.unlink(name)
	with zipfile.ZipFile(name, 'w') as z:
		z.write("i386-decree-user/qemu-decree", "qemu-decree/qemu-decree")
		z.write("i386-decree-user/qemu-cb-test", "qemu-decree/qemu-cb-test")
		z.write("i386-decree-user/qemu_cb_replay.py", "qemu-decree/qemu_cb_replay.py")
	return True

def mac_build():
	# Clean existing files
	for f in glob.glob("*.zip"):
		os.unlink(f)
	if os.path.exists("i386-decree-user"):
		shutil.rmtree("i386-decree-user")

	# Build the project with a clean build
	ok = subprocess.call("./configure --target-list=i386-decree-user --disable-system --enable-pie && make clean && make -j5", shell = True) == 0
	if not ok:
		print "Build failed, aborting"
		return False

	# Create archive of executables
	name = "qemu_decree_macosx_%s.zip" % sys.argv[2]
	print "Creating " + name
	if os.path.exists(name):
		os.unlink(name)
	with zipfile.ZipFile(name, 'w') as z:
		z.write("i386-decree-user/qemu-decree", "qemu-decree/qemu-decree")
		z.write("i386-decree-user/qemu-cb-test", "qemu-decree/qemu-cb-test")
		z.write("i386-decree-user/qemu_cb_replay.py", "qemu-decree/qemu_cb_replay.py")
	return True

if sys.argv[1] == "linux":
	ok = linux_build()
elif sys.argv[1] == "macosx":
	ok = mac_build()
else:
	print "Unknown platform %s" % sys.argv[1]
	ok = False

if not ok:
	sys.exit(1)
sys.exit(0)
