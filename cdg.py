import networkx as nx
from networkx.drawing.nx_pydot import read_dot
import json


def calculate_post_dominators(path_to_dot_file, start_node):
    graph = nx.drawing.nx_pydot.read_dot(path_to_dot_file)
    post_dominators = nx.immediate_dominators(graph.reverse(), start_node)

    # Writing to JSON file
    with open('post_dominators.json', 'w') as json_file:
        json.dump(post_dominators, json_file, indent=4)

    return


def load_ipd_from_json(file_path):
    with open(file_path, 'r') as file:
        ipd = json.load(file)
    return ipd


def load_cfg_from_dot(file_path):
    cfg = []
    parents = {}
    children = {}
    branches = {}
    merges = {}
    duplicates = set()

    try:
        with open(file_path, 'r') as file:
            next(file)  # Skip the header if present
            for line in file:
                if '->' in line:
                    src, dst = line.strip().strip(';').split(' -> ')
                    # Remove quotes from src and dst
                    src = src.strip('"')
                    dst = dst.strip('"')
                    edge = (src, dst)

                    if edge not in cfg:
                        cfg.append(edge)
                    else:
                        duplicates.add(edge)

                    parents.setdefault(src, set()).add(dst)
                    children.setdefault(dst, set()).add(src)

    except FileNotFoundError:
        print(f"Error: The file {file_path} does not exist.")
    except Exception as e:
        print(f"An error occurred: {e}")

    for node, children_nodes in parents.items():
        if len(children_nodes) > 1:
            branches[node] = children_nodes

    for node, parent_nodes in children.items():
        if len(parent_nodes) > 1:
            merges[node] = parent_nodes

    return cfg, parents, children, branches, merges, duplicates


def process_cfg(cfg, branches, merges, ipd):
    control_dependence_stack = []
    control_dependencies = {}

    # Function to get the current control dependency
    def get_current_cd():
        if control_dependence_stack:
            return control_dependence_stack[-1][0]
        return None

    # Convert cfg to a dictionary where each node points to its children
    cfg_dict = {}
    for src, dst in cfg:
        if src not in cfg_dict:
            cfg_dict[src] = set()
        cfg_dict[src].add(dst)

    # Process each node in the cfg
    for node in cfg_dict:
        # Handle merge points first
        if node in merges:
            while control_dependence_stack and ipd[get_current_cd()] == node:
                control_dependence_stack.pop()

        # After handling the merge, get the current control dependency
        current_cd = get_current_cd()

        # If the current node is a branch, push it onto the stack
        if node in branches:
            for branch_node in branches[node]:
                control_dependence_stack.append((node, ipd[branch_node]))
                # Store the control dependency if there is a valid current control dependency
                if current_cd:
                    control_dependencies.setdefault(current_cd, set()).add(node)

    # Ensure that dependencies from the final item on the stack are also recorded
    while control_dependence_stack:
        item, parent = control_dependence_stack.pop()
        if parent in ipd and ipd[parent] in cfg_dict:
            control_dependencies.setdefault(ipd[parent], set()).add(item)

    return control_dependencies


def write_dot_file(control_dependencies, output_file='control_dep.dot'):
    with open(output_file, 'w') as file:
        file.write('digraph control_dep {\n')
        for src, dsts in control_dependencies.items():
            for dst in dsts:
                file.write(f'    "{src}" -> "{dst}";\n')
        file.write('}\n')


def main():
    file_path = 'submission.dot'
    calculate_post_dominators(file_path, 'H')
    cfg, parents, children, branches, merges, duplicates = load_cfg_from_dot(file_path)

    ipd_file_path = 'post_dominators.json'
    ipd = load_ipd_from_json(ipd_file_path)
    #print(ipd)
    print("Total connections:", cfg)
    #print("Parents:", parents)
    #print("Children:", children)
    print("Branches:", branches)
    print("Merges:", merges)
    if duplicates:
        print("Duplicates:", duplicates)
    control_dependencies = process_cfg(cfg, branches, merges, ipd)
    write_dot_file(control_dependencies)


if __name__ == '__main__':
    main()
