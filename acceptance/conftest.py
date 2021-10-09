from datetime import datetime, timedelta
import json
from os import path
import pytest
from scapy.data import ETH_P_ALL
from scapy.interfaces import resolve_iface
from scapy.sendrecv import sniff
import select
import subprocess

class LazyBag(dict):
	def __getitem__(self, idx):
		value = {}
		if idx in self:
			 value = super().__getitem__(idx)
			 if not isinstance(value, dict):
				 return value

		return LazyBag(value)

	def __getattr__(self, name):
		return self[name]

class NetworkInterfaceHelper():
	def __init__(self, iface_name, fakenet_subprocess_stdout):
		self.interface = resolve_iface(iface_name)
		# Keep one socket so we don't miss packets between sniff calls.
		self.l2socket = self.interface.l2listen()(type = ETH_P_ALL, iface = iface_name)
		self.fakenet_subprocess_stdout = fakenet_subprocess_stdout
		self.stdout_poll = select.poll()
		self.stdout_poll.register(self.fakenet_subprocess_stdout, select.POLLIN)
		self.last_status = {}
	
	def assert_packets(self, count, lfilter, timeout = 5):
		packets = sniff(count = count, lfilter = lfilter, opened_socket = self.l2socket, timeout = timeout)
		assert(len(packets) == count)

		return packets

	def assert_packet(self, lfilter, timeout = 5):
		return self.assert_packets(1, lfilter, timeout)[0]

	def _read_status_update(self):
		self.status = json.loads(self.fakenet_subprocess_stdout.readline())

	def assert_status(self, pred, timeout = 5):
		deadline = datetime.now() + timedelta(seconds = timeout)

		while self.stdout_poll.poll(0):
			self._read_status_update()

		while not pred(LazyBag(self.status)) and datetime.now() < deadline:
			if self.stdout_poll.poll((deadline-datetime.now()).total_seconds()*1000):
				self._read_status_update()

		assert(pred(LazyBag(self.status)))

@pytest.fixture
def iface(pytestconfig, request):
	base_dir = path.abspath(path.join(path.dirname(__file__), ".."))

	fakenet_subprocess = subprocess.Popen(
		[
			path.join(base_dir, "target", "debug", "fakenet"),
			path.join(base_dir, "examples", "single-node.toml"),
		],
		stdout = subprocess.PIPE,
		stderr = subprocess.STDOUT,
		text = True,
	)

	status = json.loads(fakenet_subprocess.stdout.readline())
	assert("interface" in status and "name" in status["interface"])

	yield NetworkInterfaceHelper(
		status["interface"]["name"],
		fakenet_subprocess.stdout,
	)

	fakenet_subprocess.kill()
	outs = fakenet_subprocess.stdout.read()
	fakenet_subprocess.stdout.close()
	fakenet_subprocess.wait(timeout = 0)

	if fakenet_subprocess.returncode != 0:
		print("fakenet failed: " + outs)
	elif outs:
		print("fakenet output:", outs)
