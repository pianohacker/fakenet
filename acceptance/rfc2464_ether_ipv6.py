import netaddr

def assert_is_multicast_ether_dest(ether_dest, ipv6_dest):
	ipv6_dest = netaddr.IPAddress(ipv6_dest)

	print(ether_dest, '33:33:' + ':'.join('{:02x}'.format(b) for b in ipv6_dest.packed[-4:]))
	assert(ether_dest == '33:33:' + ':'.join('{:02x}'.format(b) for b in ipv6_dest.packed[-4:]))
