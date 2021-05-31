from main import Node, Network


def parsing_network_topolopy():
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
    return networks


def parsing_vulns_info():
    with open('vulns.txt', 'r+') as f:
        vulns_dict = {}
        for line in f.readlines():
            v_temp = line.strip().split(': ')
            vulns_dict[v_temp[0]] = int(v_temp[1])
    return vulns_dict


def parsing_nodes_info():
    with open('nodes.txt', 'r+') as f:
        Nodes = []
        for line in f.readlines():
            temp = line.strip().split(':')
            node = Node(ip_addr=temp[0], vuln=temp[1].split(','))
            Nodes.append(node)
        for line in f.readline():
            print(line)
    return Nodes