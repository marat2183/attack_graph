import networkx as nx
import matplotlib.pyplot as plt
import copy
import os
from termcolor import colored

ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
RESULT_DIR = ROOT_DIR + '/results'
fn_res = []
def dfs(start, visited, path=None, node_c=0):
    if path is None:
        path = []
    visited[nodes_dict[start]] = True
    path.append(start.ip_addr)
    if start.max_priv < 3:
        if len(path) > 1:
            print(path)
            global fn_res
            fn_res.append(copy.deepcopy(path))
    else:
        for node in start.linked_nodes:
            node_c = 0
            if (visited[nodes_dict[node]] == False) and node.vuln_count > 0 and start.max_priv >= 3:
                node_c += 1
                dfs(node, visited, path, node_c)
    if node_c == 0:
        if len(path) > 1:
            print(path)
            fn_res.append(copy.deepcopy(path))
    path.pop()
    visited[nodes_dict[start]] = False


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
        self.max_priv = 0

    def set_default_gateway(self, networks):
        for network in networks:
            t = network.formatize()
            if self.ip_addr in t:
                self.default_gateway = network.main_router

    def set_max_vuln_priv(self, vulns_dict):
        max_priv = 0
        for vuln in self.vuln:
            try:
                temp = vulns_dict[vuln]
            except KeyError:
                temp = 0
            if temp > max_priv:
                max_priv = vulns_dict[vuln]
        self.max_priv = max_priv

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


class Parser():
    @staticmethod
    def parse_vulnerabilities():
        vulns_dict = {}
        with open('vulns.txt', 'r+') as f:
            for line in f.readlines():
                v_temp = line.strip().split(': ')
                vulns_dict[v_temp[0]] = int(v_temp[1])
        return vulns_dict

    @staticmethod
    def parse_net_topology():
        networks = []
        with open('network_topology.txt', 'r+') as f:
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
        return networks

    @staticmethod
    def parse_nodes():
        with open('nodes.txt', 'r+') as f:
            nodes_dict = {}
            n_count = 0
            for line in f.readlines():
                temp = line.strip().split(':')
                if temp[1] == 'None':
                    nodes_dict[Node(ip_addr=temp[0], vuln=[])] = n_count
                    n_count += 1
                else:
                    nodes_dict[Node(ip_addr=temp[0], vuln=temp[1].split(','))] = n_count
                    n_count += 1
        return nodes_dict


class Handler():
    def __init__(self, user_input):
        self.user_input = user_input
        self.start = None
        self.fn_res = []

    def get_node_by_input(self, nodes_dict):
        for n in nodes_dict.keys():
            t = n.ip_addr
            if self.user_input == n.ip_addr:
                self.start = n

    @staticmethod
    def format_to_graph():
        prev_len = len(fn_res)
        for i in range(prev_len):
            a = list()
            for t in range(len(fn_res[i]) - 1):
                a.append((fn_res[i][t], fn_res[i][t + 1]))
            fn_res.append(a)
        for i in range(prev_len):
            del fn_res[0]
        return fn_res

    @staticmethod
    def get_default_edges(nodes):
        tuple_list = []
        for node in nodes:
            for peer in node.linked_nodes:
                tuple_list.append((node.ip_addr, peer.ip_addr))
        return tuple_list

    @staticmethod
    def get_attack_edges(def_edges, temp_data):
        for i in range(len(temp_data)):
            final_list_for_graph = []
            for m in def_edges:
                if m not in temp_data:
                    final_list_for_graph.append(m)
        return temp_data, final_list_for_graph


class Ilustrator():
    def_edge_color = 'black'
    attack_edge_color = 'red'
    width = 1
    node_edge_color = 'black'
    node_color = 'grey'
    connectionstyle = 'arc3, rad = 0.03'
    node_size = 5000
    font_size = 8
    font_color = 'black'

    def __init__(self, attack_edges, def_edges, figsize):
        self.attack_edges = attack_edges
        self.def_edges = def_edges
        self.figsize = figsize * 2


    def create_default_graph(self):
        G = nx.DiGraph()
        G.add_edges_from(self.def_edges, color=self.def_edge_color, weight=self.width)
        edges = G.edges()
        colors = [G[u][v]['color'] for u, v in edges]
        weights = [G[u][v]['weight'] for u, v in edges]
        plt.figure(figsize=(self.figsize, self.figsize - 2))
        pos = nx.planar_layout(G)
        g_nodes = nx.draw_networkx_nodes(G, pos=pos, node_size=self.node_size, node_color=self.node_color)
        nx.draw_networkx_edges(G, pos=pos, edgelist=edges, edge_color=colors, node_size=self.node_size, width=weights,
                               connectionstyle=self.connectionstyle)
        g_nodes.set_edgecolor(self.node_edge_color)
        nx.draw_networkx_labels(G, pos=pos, font_size=self.font_size, font_color=self.font_color)
        plt.axis("off")
        plt.savefig(f"{RESULT_DIR}/def_graph.png", format="PNG")

    def create_graph_attack_graph(self, i):
        G = nx.DiGraph()
        G.add_edges_from(self.attack_edges, color=self.attack_edge_color, weight=self.width)
        G.add_edges_from(self.def_edges, color=self.def_edge_color, weight=self.width)
        edges = G.edges()
        colors = [G[u][v]['color'] for u, v in edges]
        weights = [G[u][v]['weight'] for u, v in edges]
        plt.figure(figsize=(self.figsize, self.figsize - 2))
        pos = nx.planar_layout(G)
        g_nodes = nx.draw_networkx_nodes(G, pos=pos, node_size=self.node_size, node_color=self.node_color)
        nx.draw_networkx_edges(G, pos=pos, edgelist=edges, edge_color=colors, node_size=self.node_size, width=weights,
                               connectionstyle=self.connectionstyle)
        g_nodes.set_edgecolor(self.node_edge_color)
        nx.draw_networkx_labels(G, pos=pos, font_size=self.font_size, font_color=self.font_color)
        plt.axis("off")
        plt.savefig(f"{RESULT_DIR}/Graph{i}.png", format="PNG")


def main(nodes):
    menu_string = 'Выберите один адрес из доступных:\n'
    ip_addrs = list(map(lambda x: x.ip_addr, nodes))
    for i in ip_addrs:
        menu_string += colored(i, 'green') + '\n'
    print(menu_string)
    u_input = input("Введите ip адрес: ")
    is_correct = False
    while not is_correct:
        if u_input not in ip_addrs:
            print(colored("Некорректные данные", 'red'))
            u_input = input("Введите ip адрес: ")
        else:
            is_correct = True
    temp = Handler(user_input=u_input)
    visited = [False] * len(nodes)
    temp.get_node_by_input(nodes_dict)
    dfs(temp.start, visited=visited)
    attack_edges_list = temp.format_to_graph()
    def_edges = temp.get_default_edges(nodes)
    result = Ilustrator(attack_edges=attack_edges_list, def_edges=def_edges, figsize = len(nodes))
    result.create_default_graph()
    if len(attack_edges_list) > 0:
        for i in range(len(attack_edges_list)):
            temp_tuple = temp.get_attack_edges(def_edges=def_edges, temp_data=attack_edges_list[i])
            temp_res = Ilustrator(def_edges=temp_tuple[1], attack_edges=temp_tuple[0], figsize = len(nodes))
            temp_res.create_graph_attack_graph(i)
        print(colored("Графы атак успешно построены, результаты в папке \"results\"", "green"))
        return
    else:
        print(colored("Граф атаки пуст, так как на указанном узле нет уязвимости с нужным уровнем доступа", "green"))
        return


if __name__ == '__main__':
    for root, dirs, files in os.walk(RESULT_DIR):
        for file in files:
            os.remove(os.path.join(root, file))
    data = Parser()
    vulns_dict = data.parse_vulnerabilities()
    networks = data.parse_net_topology()
    nodes_dict = data.parse_nodes()
    nodes = nodes_dict.keys()
    for node in nodes:
        node.set_default_gateway(networks)
        node.set_linked_nodes(networks, nodes)
        node.set_max_vuln_priv(vulns_dict)
    main(nodes)
    # data = Parser()
    # vulns_dict = data.parse_vulnerabilities()
    # networks = data.parse_net_topology()
    # nodes_dict = data.parse_nodes()
    # nodes = nodes_dict.keys()
    # for node in nodes:
    #     node.set_default_gateway(networks)
    #     node.set_linked_nodes(networks, nodes)
    #     node.set_max_vuln_priv(vulns_dict)
    #
    # temp = Handler(user_input='192.168.134.1')
    # visited = [False] * len(nodes)
    # temp.get_node_by_input(nodes_dict)
    # dfs(temp.start, visited=visited)
    # attack_edges_list = temp.format_to_graph()
    # def_edges = temp.get_default_edges(nodes)
    # result = Ilustrator(attack_edges=attack_edges_list, def_edges=def_edges)
    # result.create_default_graph()
    # if len(attack_edges_list) > 0:
    #     for i in range(len(attack_edges_list)):
    #         temp_tuple = temp.get_attack_edges(def_edges=def_edges, temp_data=attack_edges_list[i])
    #         temp_res = Ilustrator(def_edges=temp_tuple[1], attack_edges=temp_tuple[0])
    #         temp_res.create_graph_attack_graph(i)
    # else:
    #     print('Граф атаки пуст, так как на указанном узле нет уязвимости с нужным уровнем доступа')
