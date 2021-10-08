import json
from os import path
import pytest
from scapy.data import ETH_P_ALL
from scapy.interfaces import resolve_iface
from scapy.sendrecv import sniff
import select
import subprocess

class NetworkInterfaceHelper():
	def __init__(self, iface_name, fakenet_subprocess_stdout):
		self.interface = resolve_iface(iface_name)
		# Keep one socket so we don't miss packets between sniff calls.
		self.l2socket = self.interface.l2listen()(type = ETH_P_ALL, iface = iface_name)
		self.fakenet_subprocess_stdout = fakenet_subprocess_stdout
		self.stdout_poll = select.poll()
		self.stdout_poll.register(self.fakenet_subprocess_stdout, select.POLLIN)
	
	def assert_packets(self, count, lfilter, timeout = 5):
		packets = sniff(count = count, lfilter = lfilter, opened_socket = self.l2socket, timeout = timeout)
		assert(len(packets) == count)

		return packets

	def assert_packet(self, lfilter, timeout = 5):
		return self.assert_packets(1, lfilter, timeout)[0]

	def assert_status(self, t, timeout = 5):
		events = self.stdout_poll.poll(timeout * 1000)
		assert(events != [])
		
		status_msg = json.loads(self.fakenet_subprocess_stdout.readline())
		assert status_msg['type'] == t
		return status_msg

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

	status_msg = json.loads(fakenet_subprocess.stdout.readline())
	assert(status_msg["type"] == "interface-name")

	yield NetworkInterfaceHelper(
		status_msg["name"],
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
