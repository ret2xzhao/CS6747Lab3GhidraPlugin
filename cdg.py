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

def generate_control_dependency_graph(cfg, branches, merges):
    control_dependence_stack = []
    control_dependencies = []

    for edge in cfg:
        src, dst = edge

        if src in branches or dst in merges:
            control_dependence_stack.append(dst)
        else:
            if control_dependence_stack:
                dependent_node = control_dependence_stack[-1]
                control_dependencies.append((dst, dependent_node))

    return control_dependencies

def write_dot_file(control_dependencies, output_file='control_dep.dot'):
    with open(output_file, 'w') as file:
        file.write('digraph control_dep {\n')
        for src, dst in control_dependencies:
            file.write(f'    "{src}" -> "{dst}";\n')
        file.write('   }\n')

def main():
    file_path = 'submission.dot'
    cfg, parents, children, branches, merges, duplicates = load_cfg_from_dot(file_path)
    print("Total connections:", len(cfg))
    print("Parents:", len(parents))
    print("Children:", len(children))
    if duplicates:
        print("Duplicates:", duplicates)
    control_dependencies = generate_control_dependency_graph(cfg, branches, merges)
    write_dot_file(control_dependencies)

if __name__ == '__main__':
    main()
