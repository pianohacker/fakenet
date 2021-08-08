import netaddr

SOLICITED_NODES_SPACE = netaddr.IPNetwork('ff02::1:ff00:0/104')

def assert_is_solicited_nodes_for_address(multicast_address, address):
	multicast_address = netaddr.IPNetwork(multicast_address)
	address = netaddr.IPNetwork(address)

	assert(multicast_address in SOLICITED_NODES_SPACE)

	multicast_low_order_bits = multicast_address.value & 0xffffff
	low_order_bits = address.value & 0xffffff

	assert(multicast_low_order_bits == low_order_bits)
