#!/usr/bin/env python
import os
import sys
import subprocess
import zipfile
import glob
import shutil
import time
import signal

if len(sys.argv) < 3:
	print "Usage: build.py <os> <build_number>"
	sys.exit(1)

def get_cbs(name, patched):
	cb_paths = []
	cb_names = []
	for f in glob.glob("%s/bin/*" % name):
		if "patched" in f:
			if patched:
				os.chmod(f, 0755)
				cb_paths.append(f)
				cb_names.append(os.path.basename(f))
		else:
			if not patched:
				os.chmod(f, 0755)
				cb_paths.append(f)
				cb_names.append(os.path.basename(f))
	return cb_paths, cb_names

def run_cb_test(name, patched, options, desc):
	begin = time.time()
	cb_paths, cb_names = get_cbs(name, patched)
	p = subprocess.Popen(["i386-decree-user/qemu-cb-test", "--record", "tmp/replay", "--optimize_failure", "--cb"] +
			cb_paths + options, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
	out, error = p.communicate()
	t = time.time() - begin
	if p.returncode != 0:
		print "%s: FAILED" % desc
		print out
		print "***** POLLS FAILED *****"
		return False, t
	return True, t

def compute_replay_size(name, patched, poll_names):
	replay_size = 0
	cb_paths, cb_names = get_cbs(name, patched)
	for f in poll_names:
		for b in cb_names:
			replay_name = "tmp/replay-%s-%s.replay" % (f, b)
			if not os.path.exists(replay_name):
				print "Replay file %s missing" % replay_name
				print "***** REPLAY FAILED *****"
				return False, 0
			replay_size += os.stat(replay_name).st_size
	return True, replay_size

def test_replays(name, patched, poll_names, desc, should_core):
	cb_paths, cb_names = get_cbs(name, patched)
	begin = time.time()

	for f in poll_names:
		replay_options = []
		for b in cb_names:
			replay_name = "tmp/replay-%s-%s.replay" % (f, b)
			replay_options += ["-replay", replay_name]

		p = subprocess.Popen(["i386-decree-user/qemu-decree"] + replay_options + cb_paths,
				stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
		out, error = p.communicate()
		if ((should_core and (p.returncode != -signal.SIGSEGV) and (p.returncode != -signal.SIGILL) and
				(p.returncode != -signal.SIGBUS)) or
			((not should_core) and (p.returncode < 0))):
			print "%s: REPLAY FAILED" % desc
			print "Failed while replaying %s" % f
			print out
			print "***** REPLAY FAILED *****"
			t = time.time() - begin
			return False, t

	t = time.time() - begin
	return True, t

def test_tci_replays(name, patched, poll_names, desc, should_core):
	cb_paths, cb_names = get_cbs(name, patched)
	begin = time.time()

	for f in poll_names:
		replay_options = []
		for b in cb_names:
			replay_name = "tmp/replay-%s-%s.replay" % (f, b)
			replay_options += ["-replay", replay_name]

		p = subprocess.Popen(["i386-decree-user-tci/qemu-decree"] + replay_options + cb_paths,
				stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
		out, error = p.communicate()
		if ((should_core and (p.returncode != -signal.SIGSEGV) and (p.returncode != -signal.SIGILL) and
				(p.returncode != -signal.SIGBUS)) or
			((not should_core) and (p.returncode < 0))):
			print "%s: REPLAY FAILED" % desc
			print "Failed while replaying %s" % f
			print out
			print "***** REPLAY FAILED *****"
			t = time.time() - begin
			return False, t

	t = time.time() - begin
	return True, t

def run_poller(name, config, ids = None):
	polls = glob.glob("%s/poller/for-%s/*.xml" % (name, config))
	count = len(polls)
	if count == 0:
		return True

	poll_names = []
	for f in polls:
		poll_names.append(os.path.splitext(os.path.basename(f))[0])

	# Clean up from any previous runs
	if os.path.exists("tmp"):
		shutil.rmtree("tmp")
	os.mkdir("tmp")

	# Get the list of challenge binaries
	cb_paths, cb_names = get_cbs(name, False)

	# Run the polls and record replays
	opt_name = ""
	opt = []
	if ids is not None:
		opt_name = " with IDS"
		opt = ["--ids", ids]
	ok, t = run_cb_test(name, False, ["--xml_dir", "%s/poller/for-%s" % (name, config)] + opt,
		"%d poll(s) for %s%s" % (count, config, opt_name))
	if not ok:
		return False
	ok, replay_size = compute_replay_size(name, False, poll_names)
	if not ok:
		return False

	print "%d poll(s) for %s%s complete in %.2f seconds with %.2fMB of replays" % (count, config, opt_name, t, replay_size / 1048576.0)

	# Test the replays
	ok, t = test_replays(name, False, poll_names, "polls for %s" % config, False)
	if not ok:
		return False
	print "%d poll(s) for %s%s replayed in %.2f seconds" % (count, config, opt_name, t)

	# Test the replays in interpreted mode
	ok, t = test_tci_replays(name, False, poll_names, "polls for %s" % config, False)
	if not ok:
		return False
	print "%d poll(s) for %s%s replayed in %.2f seconds (interpreter)" % (count, config, opt_name, t)

	return True

def run_pov(name, patched):
	polls = glob.glob("%s/pov/*.xml" % name)
	count = len(polls)
	if count == 0:
		return True

	poll_names = []
	for f in polls:
		poll_names.append(os.path.splitext(os.path.basename(f))[0])

	if patched:
		patchstr = "against patched binary"
	else:
		patchstr = "against reference binary"

	# Clean up from any previous runs
	if os.path.exists("tmp"):
		shutil.rmtree("tmp")
	os.mkdir("tmp")

	# Get the list of challenge binaries
	cb_paths, cb_names = get_cbs(name, patched)

	# Run the polls and record replays
	options = ["--xml_dir", "%s/pov" % name, "--failure_ok"]
	if not patched:
		options += ["--should_core"]
	ok, t = run_cb_test(name, patched, options, "%d PoV(s) %s" % (count, patchstr))
	if not ok:
		return False
	ok, replay_size = compute_replay_size(name, patched, poll_names)
	if not ok:
		return False

	print "%d PoV(s) %s complete in %.2f seconds with %.2fMB of replays" % (count, patchstr, t, replay_size / 1048576.0)

	# Test the replays
	ok, t = test_replays(name, patched, poll_names, "PoV(s) %s" % patchstr, not patched)
	if not ok:
		return False
	print "%d PoV(s) %s replayed in %.2f seconds" % (count, patchstr, t)

	# Test the replays in interpreted mode
	ok, t = test_tci_replays(name, patched, poll_names, "PoV(s) %s" % patchstr, not patched)
	if not ok:
		return False
	print "%d PoV(s) %s replayed in %.2f seconds (interpreter)" % (count, patchstr, t)

	return True

def test_cb(name):
	print "=== Testing %s ===" % name

	# First extract the CB so that we can get the binaries, pollers, and PoVs
	with zipfile.ZipFile("cb_tests/%s.zip" % name, 'r') as z:
		z.extractall()

	# Run pollers
	if not run_poller(name, "release"):
		return False
	if not run_poller(name, "testing"):
		return False
	if not run_poller(name, "release", ids="/dev/null"):
		return False
	if not run_poller(name, "testing", ids="/dev/null"):
		return False

	# Run PoVs
	if not run_pov(name, False):
		return False
	if not run_pov(name, True):
		return False

	return True

def do_tests():
	for f in glob.glob("cb_tests/*.zip"):
		name = os.path.splitext(os.path.basename(f))[0]
		ok = False
		try:
			ok = test_cb(name)
		finally:
			if os.path.exists(name):
				shutil.rmtree(name)
			if os.path.exists("tmp"):
				shutil.rmtree("tmp")
		if not ok:
			return ok
	return True

def linux_build():
	# Clean existing files
	for f in glob.glob("*.zip"):
		os.unlink(f)
	if os.path.exists("i386-decree-user"):
		shutil.rmtree("i386-decree-user")
	if os.path.exists("i386-decree-user-tci"):
		shutil.rmtree("i386-decree-user-tci")

	# Build the project with a clean build
	ok = subprocess.call("./configure --target-list=i386-decree-user,i386-decree-user-tci --disable-tools --disable-system && make clean && make -j5", shell = True) == 0
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
		z.write("i386-decree-user-tci/qemu-decree", "qemu-decree/qemu-decree-tci")

	return do_tests()

def mac_build():
	# Needed for glib
	os.environ["PATH"] = "/usr/local/bin:" + os.environ["PATH"]

	# Clean existing files
	for f in glob.glob("*.zip"):
		os.unlink(f)
	if os.path.exists("i386-decree-user"):
		shutil.rmtree("i386-decree-user")
	if os.path.exists("i386-decree-user-tci"):
		shutil.rmtree("i386-decree-user-tci")

	# Build the project with a clean build
	ok = subprocess.call("./configure --target-list=i386-decree-user,i386-decree-user-tci --disable-tools --disable-system --enable-pie && make clean && make -j5", shell = True) == 0
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
		z.write("i386-decree-user-tci/qemu-decree", "qemu-decree/qemu-decree-tci")

	return do_tests()

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
