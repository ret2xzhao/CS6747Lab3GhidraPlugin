import networkx as nx
from networkx.drawing.nx_pydot import read_dot

# Path to the DOT file containing the graph
path_to_dot_file = 'C:/Repo/cs6747/submission.dot'

# Load the graph from the specified DOT file
graph = read_dot(path_to_dot_file)

# Reverse the graph to prepare for finding post-dominators
reversed_graph = graph.reverse()

# Define the start node for post-dominator calculation
start_node = '0x40101c'  # Start node identifier

# Calculate the immediate post-dominators of the graph from the start node
post_dominators = nx.immediate_dominators(reversed_graph, start_node)

# Print the post dominators
print(post_dominators)
