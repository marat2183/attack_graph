import numpy
import networkx as nx
import matplotlib.pyplot as plt

with open('vulns.txt', 'r+') as f:
    vulns_dict = {}
    for line in f.readlines():
        v_temp = line.strip().split(': ')
        vulns_dict[v_temp[0]] = int(v_temp[1])


class Network:
    def __init__(self, main_router, other_routers=None, peers=None):
        self.main_router = main_router
        self.other_routers = other_routers
        self.peers = peers

    def formatize(self):
        return list(map(lambda x: x[1:], self.peers))


class Node:
    def __init__(self, ip_addr, vuln):
        self.ip_addr = ip_addr
        self.vuln = vuln
        self.vuln_count = len(self.vuln)
        self.default_gateway = None
        self.linked_nodes = None

    def set_default_gateway(self, networks):
        for network in networks:
            t = network.formatize()
            if self.ip_addr in t:
                self.default_gateway = network.main_router

    def get_max_vuln_priv(self):
        max_priv = 0
        for vuln in self.vuln:
            temp = vulns_dict[vuln]
            if temp > max_priv:
                max_priv = vulns_dict[vuln]
        return max_priv

    def set_linked_nodes(self, networks, nodes):
        result = []
        for network in networks:
            temp_list = network.formatize()
            if self.ip_addr in temp_list:
                result += [peer[1:] for peer in network.peers if peer[1:] != self.ip_addr]
            if self.default_gateway in network.other_routers:
                result += [peer[1:] for peer in network.peers if peer.startswith('+')]
        final_result = [node for node in nodes if node.ip_addr in result]
        self.linked_nodes = final_result



with open('test.txt', 'r+') as f:
    Nodes = []
    for line in f.readlines():
        temp = line.strip().split(':')
        node = Node(ip_addr=temp[0], vuln=temp[1].split(','))
        Nodes.append(node)
    for line in f.readline():
        print(line)


with open('network_topology.txt', 'r+') as f:
    networks = []
    temp_counter = 0
    for line in f.readlines():
        if line.endswith(':\n'):
            temp_counter += 1
            if temp_counter != 1:
                networks.append(temp)
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
    networks.append(temp)



for node in Nodes:
    node.set_default_gateway(networks)
    node.set_linked_nodes(networks, Nodes)

# for node in Nodes:
#     print(node.ip_addr, list(map(lambda x: x.ip_addr, node.linked_nodes)))
    # print(node.ip_addr, node.linked_nodes)


Nodes_dict = {}
t_count = 0
for node in Nodes:
    Nodes_dict[node] = t_count
    t_count += 1

u = len(Nodes)
Nodes_matrix = numpy.zeros((u, u))
# print(Nodes_matrix)
# print(int(Nodes_matrix[0][1]))
# print(Nodes_matrix)
for f_key, f_value in Nodes_dict.items():
    first_node = f_key
    for peer in first_node.linked_nodes:
        s_value = Nodes_dict[peer]
        # print(f_value, s_value)
        if f_value == s_value:
            Nodes_matrix[f_value][s_value] = 0
        else:
            # print(Nodes_matrix[f_value][s_value])
            Nodes_matrix[f_value][s_value] = 1
print(Nodes_matrix)
# nm = numpy.matrix(Nodes_matrix)
# G=nx.from_numpy_matrix(Nodes_matrix)
#
#
# nx.draw(G, with_labels=Nodes_matrix)
# plt.show()
tuple_list = []
for node in Nodes:
    for peer in node.linked_nodes:
        tuple_list.append((node.ip_addr, peer.ip_addr))
print(tuple_list)
G = nx.DiGraph()
G.add_edges_from(tuple_list)
pos = nx.spring_layout(G)
nx.draw_networkx_nodes(G, pos)
nx.draw_networkx_edges(G, pos, edgelist=G.edges(), edge_color='black')
nx.draw_networkx_labels(G, pos)
G.size(weight=10000)
# nx.draw(G, with_labels=True)
plt.show()

# for node in Nodes:
#     print('начало')
#     print(node.ip_addr)
#     print(node.vuln)
#     print(node.default_gateway)
#     print(node.linked_nodes)
#     print(node.get_max_vuln_priv())

