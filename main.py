import numpy
import networkx as nx
import matplotlib.pyplot as plt
import test
import copy
fn_res = []

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

    def format_string(self):
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
            t = network.format_string()
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
            temp_list = network.format_string()
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
        if temp[1] == '':
            node = Node(ip_addr=temp[0], vuln=[])
        else:
            node = Node(ip_addr=temp[0], vuln=temp[1].split(','))
        Nodes.append(node)



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
# Nodes_matrix = numpy.zeros((u, u))
# # print(Nodes_matrix)
# # print(int(Nodes_matrix[0][1]))
# # print(Nodes_matrix)
# for f_key, f_value in Nodes_dict.items():
#     first_node = f_key
#     for peer in first_node.linked_nodes:
#         s_value = Nodes_dict[peer]
#         # print(f_value, s_value)
#         if f_value == s_value:
#             Nodes_matrix[f_value][s_value] = 0
#         else:
#             # print(Nodes_matrix[f_value][s_value])
#             Nodes_matrix[f_value][s_value] = 1
# print(Nodes_matrix)
# nm = numpy.matrix(Nodes_matrix)
# G=nx.from_numpy_matrix(Nodes_matrix)
#
#
# nx.draw(G, with_labels=Nodes_matrix)
# plt.show()
# tuple_list = []
# for node in Nodes:
#     for peer in node.linked_nodes:
#         tuple_list.append((node.ip_addr, peer.ip_addr))
# print('tuple_list')
# print(tuple_list)
# G = nx.DiGraph()
# G.add_edges_from(tuple_list)
# pos = nx.spring_layout(G, weight=5000)
# plt.figure(figsize=(12, 12))
# nx.draw_networkx_nodes(G, pos, node_size=10000)
# nx.draw_networkx_edges(G, pos, edgelist=G.edges(), edge_color='black', node_size=10000)
# nx.draw_networkx_labels(G, pos, font_size=8)
# # plt.show()
# # plt.savefig("Graph.png", format="PNG")
# G.size(weight=10000)
# nx.draw(G, with_labels=True)


# for node in Nodes:
#     print('начало')
#     print(node.ip_addr)
#     print(node.vuln)
#     print(node.default_gateway)
#     print(node.linked_nodes)
#     print(node.get_max_vuln_priv())










test_list = []
for node in Nodes:
    test_list.append(list(map(lambda x: x.ip_addr, node.linked_nodes)))









def dfs(start, end, visited, path=None):
    a = start.ip_addr
    if path is None:
        path = []
    visited[Nodes_dict[start]] = True
    path.append(start.ip_addr)
    if start.ip_addr == end.ip_addr:
        if len(path) > 1:
            print(path)
            global fn_res
            fn_res.append(copy.deepcopy(path))
    else:
        for node in start.linked_nodes:
            b = node.ip_addr
            if (visited[Nodes_dict[node]] == False) and node.vuln_count > 0 and start.get_max_vuln_priv() >= 3:
                dfs(node, end, visited, path)
    path.pop()
    visited[Nodes_dict[start]] = False

user_input = '192.168.135.1'
end_input = '192.168.136.2'
visited = [False] * len(Nodes)
path = []
for k in Nodes_dict.keys():
    if user_input == k.ip_addr:
        start = k
for k in Nodes_dict.keys():
    if end_input == k.ip_addr:
        end = k


def formatize_to_graph(t_list):
    prev_len = len(t_list)
    for l in range(prev_len):
        io = list()
        for t in range(len(t_list[l]) - 1):
            io.append((t_list[l][t], t_list[l][t+1]))
        t_list.append(io)
    for i in range(prev_len):
        del t_list[0]
    return t_list


endless_nodes = [node for node in Nodes if (node.vuln_count > 0 and node.get_max_vuln_priv() < 3)]
print(list(map(lambda x: x.ip_addr, endless_nodes)))
print('dfs_first')
for i in range(len(endless_nodes)):
    t = endless_nodes[i].ip_addr
    dfs(start=start, end=endless_nodes[i], visited=visited)

t_pop = formatize_to_graph(fn_res)
#Топология без атак
tuple_list = []
for node in Nodes:
    for peer in node.linked_nodes:
        tuple_list.append((node.ip_addr, peer.ip_addr))

for i in range(len(t_pop)):
    final_list_for_graph = []
    for m in tuple_list:
        if m not in t_pop[i]:
            final_list_for_graph.append(m)

    G = nx.DiGraph()
    # G.add_nodes_from(list(map(lambda x: x.ip_addr, Nodes)))
    G.add_edges_from(t_pop[i], color='red', weight=1)
    G.add_edges_from(final_list_for_graph, color='black', weight=1)
    pos = nx.planar_layout(G)
    edges = G.edges()
    colors = [G[u][v]['color'] for u,v in edges]
    weights = [G[u][v]['weight'] for u,v in edges]
    plt.figure(figsize=(12, 10))
    pos_higher = {}

    # for k, v in pos.items():
    #     pos_higher[k] = (v[0]-0.02, v[1]-0.03)

    pos = nx.planar_layout(G)
    g_nodes = nx.draw_networkx_nodes(G, pos, node_size=5000, node_color='grey')
    # nx.draw_networkx_nodes(G, pos)
    nx.draw_networkx_edges(G, pos, edgelist=edges, edge_color=colors, node_size=5000, width=weights,
                           connectionstyle='arc3, rad = 0.03')
    # nx.draw_networkx_edges(G, pos, edgelist=edges, edge_color=colors, width=weights)
    g_nodes.set_edgecolor('black')
    nx.draw_networkx_labels(G, pos, font_size=8, font_color='black')
    # plt.show()
    plt.axis("off")
    plt.savefig(f"Graph{i}.png", format="PNG")




def dfs_second(start, visited, path=None, node_c=0):
    a = start.ip_addr
    if path is None:
        path = []
    visited[Nodes_dict[start]] = True
    path.append(start.ip_addr)
    if start.get_max_vuln_priv() < 3:
        if len(path) > 1:
            print(path)
    else:
        for node in start.linked_nodes:
            node_c = 0
            b = node.ip_addr
            if (visited[Nodes_dict[node]] == False) and node.vuln_count > 0 and start.get_max_vuln_priv() >= 3:
                node_c += 1
                dfs_second(node, visited, path, node_c)
    if node_c == 0:
        print(path)
    path.pop()
    visited[Nodes_dict[start]] = False

user_input = '192.168.134.1'
end_input = '192.168.136.2'
visited = [False] * len(Nodes)
path = []
for k in Nodes_dict.keys():
    if user_input == k.ip_addr:
        start = k

print('dfs_second')
dfs_second(start=start, visited=[False] * len(Nodes))