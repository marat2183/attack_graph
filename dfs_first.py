def dfs(start, end, visited, path=None):
    a = start.ip_addr
    if path is None:
        path = []
    visited[nodes_dict[start]] = True
    path.append(start.ip_addr)
    if start.ip_addr == end.ip_addr:
        if len(path) > 1:
            print(path)
            global fn_res
            fn_res.append(copy.deepcopy(path))
    else:
        for node in start.linked_nodes:
            if (visited[nodes_dict[node]] == False) and node.vuln_count > 0 and start.get_max_vuln_priv(vulns_dict) >= 3:
                dfs(node, end, visited, path)
    path.pop()
    visited[nodes_dict[start]] = False

user_input = '192.168.135.1'
end_input = '192.168.136.2'
visited = [False] * len(nodes)
path = []

for n in nodes_dict.keys():
    if user_input == n.ip_addr:
        start = n



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


endless_nodes = [node for node in nodes if (node.vuln_count > 0 and node.get_max_vuln_priv(vulns_dict) < 3)]
print(list(map(lambda x: x.ip_addr, endless_nodes)))
print('dfs_first')
for i in range(len(endless_nodes)):
    t = endless_nodes[i].ip_addr
    dfs(start=start, end=endless_nodes[i], visited=visited)