from ghidra.program.model.block import BasicBlockModel
from ghidra.program.model.symbol import RefType
import ghidra.util.task.ConsoleTaskMonitor as ConsoleTaskMonitor

functions_count = 0
instructions_count = 0
addresses_count = 0
mnemonicSet = set()

def create_dot_graph(func, instruction_list, jumps):
    entry_point = "0x{}".format(func.getEntryPoint().toString().lstrip('0'))
    dot_graph = 'digraph "{}" {{\n'.format(entry_point)
    node_counter = 1

    # Mapping from address to node name (n1, n2, ...)
    address_to_node = {}

    # Create nodes
    for addr in instruction_list:
        node_name = 'n{}'.format(node_counter)
        addr_label = "0x{}".format(addr)  # Ensure '0x' prefix here
        dot_graph += '    {} [label = "{};"];\n'.format(node_name, addr_label)
        address_to_node[addr] = node_name
        node_counter += 1

    dot_graph += '\n'  # Empty line between nodes and edges

    # Sequential edges and jump edges integrated into flow
    for i, addr in enumerate(instruction_list):
        if i+1 < len(instruction_list):
            current_node = address_to_node[addr]
            next_addr = instruction_list[i+1]
            next_node = address_to_node[next_addr]
            
            # If current instruction has a jump, draw it accordingly
            if addr in jumps and jumps[addr] in address_to_node:
                jump_node = address_to_node[jumps[addr]]
                # Draw dotted line for jump
                dot_graph += '    {} -> {} [jump];\n'.format(current_node, jump_node)
                if jumps[addr] != next_addr:  # If the jump is not to the next sequential instruction, continue
                    continue
            
            # Draw normal flow
            dot_graph += '    {} -> {};\n'.format(current_node, next_node)

    dot_graph += '}'
    return dot_graph

def collect_instructions(func):
    global instructions_count
    global addresses_count
    instruction_list = []
    jumps = {}  # src_addr -> dst_addr as hex string without leading zeros

    basicBlockModel = BasicBlockModel(currentProgram)
    monitor = ConsoleTaskMonitor()
    addrSet = func.getBody()
    codeBlockIter = basicBlockModel.getCodeBlocksContaining(addrSet, monitor)

    while codeBlockIter.hasNext():
        code_block = codeBlockIter.next()
        for addr in code_block.getAddresses(True):
            instruction = getInstructionAt(addr)
            if instruction:
                addr_str = addr.toString()[2:]  # Remove the "0x" and keep the rest
                instruction_list.append(addr_str)
                addresses_count += 1
                instructions_count += 1
                # Check for jumps and add to jumps dictionary
                if instruction.getFlowType().isJump() and instruction.getFlows():
                    dst_addr = instruction.getFlows()[0].toString()[2:]  # Likewise, remove "0x"
                    jumps[addr_str] = dst_addr

    instruction_list.sort(key=lambda x: int(x, 16))  # Sort instructions by address
    return create_dot_graph(func, instruction_list, jumps)

def process_functions():
    global functions_count
    function_manager = currentProgram.getFunctionManager()
    functions = function_manager.getFunctions(True)
    
    for func in functions:
        functions_count += 1
        dot_graph = collect_instructions(func)
        print(dot_graph)

def main():
    process_functions()
    print("{} functions, {} addresses, {} instructions processed.".format(functions_count, addresses_count, instructions_count))

if __name__ == '__main__':
    main()
