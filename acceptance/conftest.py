import json
from os import path
import pytest
from scapy.interfaces import resolve_iface
from scapy.sendrecv import sniff
import subprocess

class NetworkInterfaceHelper():
	def __init__(self, iface_name):
		self.interface = resolve_iface(iface_name)
	
	def assert_packets(self, count, lfilter, timeout = 5):
		packets = sniff(count = count, lfilter = lfilter, iface = self.interface, timeout = timeout)
		assert(len(packets) == count)

		return packets

	def assert_packet(self, lfilter, timeout = 5):
		return self.assert_packets(1, lfilter, timeout)[0]

@pytest.fixture(scope="session")
def iface(pytestconfig):
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
	assert("InterfaceName" in status_msg)

	yield NetworkInterfaceHelper(status_msg["InterfaceName"]["name"])

	outs = None
	try:
		outs, _ = fakenet_subprocess.communicate(timeout = 0)

		if fakenet_subprocess.returncode != 0:
			pytest.fail("fakenet failed: " + outs)
	except subprocess.TimeoutExpired:
		fakenet_subprocess.kill()

	if pytestconfig.getoption("verbose") > 0:
		print("fakenet output:", outs)
