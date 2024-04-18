import networkx as nx
from networkx.drawing.nx_pydot import read_dot

# Path to the DOT file containing the graph
path_to_dot_file = 'C:/Repo/cs6747/submission.dot'

# Load the graph from the specified DOT file
graph = read_dot(path_to_dot_file)

# Calculate the immediate post-dominators of the reversed graph
post_dominators = nx.immediate_dominators(graph.reverse(), "0x4019fc")

with open('post_dominators.txt', 'w') as file:
    for node, dominator in post_dominators.items():
        file.write(f"{node} {dominator}\n")

print(post_dominators)
