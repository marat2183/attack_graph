def dfs_second(start, visited, path=None, node_c=0):
    a = start.ip_addr
    if path is None:
        path = []
    visited[nodes_dict[start]] = True
    path.append(start.ip_addr)
    if start.get_max_vuln_priv(vulns_dict) < 3:
        if len(path) > 1:
            print(path)
    else:
        for node in start.linked_nodes:
            node_c = 0
            b = node.ip_addr
            if (visited[nodes_dict[node]] == False) and node.vuln_count > 0 and start.get_max_vuln_priv(vulns_dict) >= 3:
                node_c += 1
                dfs_second(node, visited, path, node_c)
    if node_c == 0:
        if len(path) > 1:
            print(path)
    path.pop()
    visited[nodes_dict[start]] = False

user_input = '192.168.135.1'

visited = [False] * len(nodes)
path = []
for n in nodes_dict.keys():
    if user_input == n.ip_addr:
        start = n

print('dfs_second')
dfs_second(start=start, visited=visited)