from ghidra.program.model.block import BasicBlockModel
import ghidra.util.task.ConsoleTaskMonitor as ConsoleTaskMonitor

functions_count = 0
instructions_count = 0
addresses_count = 0

def create_dot_graph(func, instruction_list, jumps, conditional_jumps, def_use_info):
    # Convert the entry point to a hexadecimal string.
    entry_point = "0x{}".format(func.getEntryPoint().toString().lstrip('0'))
    dot_graph = 'digraph "{}" {{\n'.format(entry_point)
    node_counter = 1
    address_to_node = {}  # Maps addresses to node names

    # Create nodes
    for addr in instruction_list:
        node_name = 'n{}'.format(node_counter)
        addr_label = "0x{}".format(addr)  # Ensure '0x' prefix
        # Assign a label with define-use information if available
        if addr in def_use_info:
            label = "{}; {}".format(addr_label, def_use_info[addr])
        else:
            label = "{};".format(addr_label)
        dot_graph += '    {} [label = "{}"];\n'.format(node_name, label)
        address_to_node[addr] = node_name
        node_counter += 1

    dot_graph += '\n'  # Separate nodes from edges

    # Add edges between nodes based on sequential and jump instructions:
    for i, addr in enumerate(instruction_list):
        if i+1 < len(instruction_list):
            current_node = address_to_node[addr]
            next_addr = instruction_list[i+1]
            next_node = address_to_node[next_addr]

            # Check if the current instruction is a jump and add an edge accordingly
            if addr in jumps:
                jump_to_node = address_to_node[jumps[addr]]
                # Draw line for jump with style based on jump type
                jump_style = 'conditional_jump' if addr in conditional_jumps else 'unconditional_jump'
                dot_graph += '    {} -> {}; [{}]\n'.format(current_node, jump_to_node, jump_style)
                
                # For conditional jumps, also connect to the next sequential instruction
                if addr in conditional_jumps:
                    dot_graph += '    {} -> {};\n'.format(current_node, next_node)
                # Skip connecting to the next node if the jump is unconditional and not to the next instruction
                elif jumps[addr] != next_addr:
                    continue
            else:
                # Draw normal flow for sequential instructions
                dot_graph += '    {} -> {};\n'.format(current_node, next_node)

    dot_graph += '}'
    return dot_graph

def analyze_instruction(instruction, addr_str):
    # Define a set of mnemonics (assembly instructions) to be analyzed.
    mnemonicSet = {'ADD', 'AND', 'CALL', 'CMP', 'DEC', 'IMUL', 'INC', 'JA', 'JBE', 'JC', 'JG', 'JL', 'JLE', 'JMP', 'JNC', 'JNZ', 'JZ', 'LEA', 'LEAVE', 'MOV', 'MOVSX', 'MOVZX', 'OR', 'POP', 'PUSH', 'RET', 'SAR', 'SETNZ', 'SHR', 'STOSD.REP', 'SUB', 'TEST', 'XOR'}
    remainSet = {'ADD', 'AND', 'CMP', 'DEC', 'IMUL', 'INC', 'JA', 'JBE', 'JC', 'JG', 'JL', 'JLE', 'JMP', 'JNC', 'JNZ', 'JZ', 'LEA', 'LEAVE', 'MOV', 'MOVSX', 'MOVZX', 'OR', 'POP', 'PUSH', 'RET', 'SAR', 'SETNZ', 'SHR', 'STOSD.REP', 'SUB', 'TEST', 'XOR'}

    mnemonic = instruction.getMnemonicString()
    defs = []  # List to hold defined variables
    uses = []  # List to hold used variables

    # Ignore 'CALL' instructions
    if mnemonic == 'CALL':
        return
    # Analyze instruction based on its type and collect define-use information
    elif mnemonic == 'ADD':
        pass
    elif mnemonic == 'AND':
        pass
    elif mnemonic == 'CALL':
        pass
    elif mnemonic == 'CMP':
        pass
    elif mnemonic == 'DEC':
        pass
    elif mnemonic == 'IMUL':
        pass
    elif mnemonic == 'INC':
        pass
    elif mnemonic == 'JA':
        pass
    elif mnemonic == 'JBE':
        pass
    elif mnemonic == 'JC':
        pass
    elif mnemonic == 'JG':
        pass
    elif mnemonic == 'JL':
        pass
    elif mnemonic == 'JLE':
        pass
    elif mnemonic == 'JMP':
        pass
    elif mnemonic == 'JNC':
        pass
    elif mnemonic == 'JNZ':
        pass
    elif mnemonic == 'JZ':
        pass
    elif mnemonic == 'LEA':
        pass
    elif mnemonic == 'LEAVE':
        pass
    elif mnemonic == 'MOV':
        pass
    elif mnemonic == 'MOVSX':
        pass
    elif mnemonic == 'MOVZX':
        pass
    elif mnemonic == 'OR':
        pass
    elif mnemonic == 'POP':
        pass
    elif mnemonic == 'PUSH':
        pass
    elif mnemonic == 'RET':
        pass
    elif mnemonic == 'SAR':
        pass
    elif mnemonic == 'SETNZ':
        pass
    elif mnemonic == 'SHR':
        pass
    elif mnemonic == 'STOSD.REP':
        pass
    elif mnemonic == 'SUB':
        pass
    elif mnemonic == 'TEST':
        pass
    elif mnemonic == 'XOR':
        pass
    else:
        return

    # Generate and return the define-use label without handling 'CALL'
    def_use_label = "D: {} U: {}".format(", ".join(defs), ", ".join(uses))
    return def_use_label


def is_in_eflags(register):
    EFLAGS = {"CF", "PF", "AF", "ZF", "SF", "OF", "DF", "TF", "IF", "IOPL", "NT", "RF", "VM", "AC", "VIF", "VIP", "ID"}
    return register in EFLAGS

def collect_instructions(func):
    global addresses_count
    global instructions_count

    instruction_list = []
    jumps = {}  # Maps source to destination addresses for jumps
    conditional_jumps = set()  # Holds source addresses of conditional jumps
    def_use_info = {}  # Maps addresses to define-use information

    # Initialize the basic block model and task monitor
    basicBlockModel = BasicBlockModel(currentProgram)
    monitor = ConsoleTaskMonitor()
    addrSet = func.getBody()
    codeBlockIter = basicBlockModel.getCodeBlocksContaining(addrSet, monitor)

    # Iterate through blocks and instructions to collect information
    while codeBlockIter.hasNext():
        codeBlock = codeBlockIter.next()
        addressIterator = codeBlock.getAddresses(True)
        for addr in addressIterator:
            addresses_count += 1
            instruction = getInstructionAt(addr)
            if instruction:
                instructions_count += 1
                addr_str = addr.toString()[2:]  # Extract address without "0x"
                instruction_list.append(addr_str)

                def_use_label = analyze_instruction(instruction, addr_str)
                def_use_info[addr_str] = def_use_label

                # Record jump instructions
                if instruction.getFlowType().isJump() and instruction.getFlows():
                    dst_addr = instruction.getFlows()[0].toString()[2:]  # Extract address without "0x"
                    jumps[addr_str] = dst_addr
                    # Determine if the jump is conditional
                    if instruction.getFlowType().isConditional():
                        conditional_jumps.add(addr_str)

    instruction_list.sort(key=lambda x: int(x, 16))  # Sort instructions by address
    return create_dot_graph(func, instruction_list, jumps, conditional_jumps, def_use_info)

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
