import string


class Network:
    def __init__(self, main_router, other_routers=None, peers=None):
        self.main_router = main_router
        self.other_routers = other_routers
        self.peers = peers

    def get_linked_nodes(self, networks, ip_addr):
        result = []
        for network in networks:
            temp_list = list(map(lambda x: x[1:], network.peers))
            if ip_addr in temp_list:
                result += [peer[1:] for peer in network.peers if peer[1:] != ip_addr]
            if self.main_router in network.other_routers:
                result += [peer[1:] for peer in network.peers if peer.startswith('+')]
        return result


with open('network_topology.txt', 'r+') as f:
    result = []
    temp_counter = 0
    for line in f.readlines():
        if line.endswith(':\n'):
            temp_counter += 1
            if temp_counter != 1:
                result.append(temp)
            temp = Network(main_router=line.strip()[:len(line) - 2])
            continue
        if line.startswith('>'):
            if temp.other_routers is None:
                temp.other_routers = []
                temp.other_routers.append(line[1:].strip())
            else:
                temp.other_routers.append(line[1:].strip())
            continue
        if line.startswith('+') or line.startswith('-'):
            if temp.peers is None:
                temp.peers = []
                temp.peers.append(line.strip())
            else:
                temp.peers.append(line.strip())
            continue
    result.append(temp)

a = temp.get_linked_nodes(result, '192.168.134.1')
print(a)

