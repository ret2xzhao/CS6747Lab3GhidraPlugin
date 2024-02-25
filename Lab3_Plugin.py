import os
from ghidra.program.model.block import BasicBlockModel
from ghidra.program.model.lang import OperandType, Register
import ghidra.program.model.symbol.RefType as RefType
import ghidra.util.task.ConsoleTaskMonitor as ConsoleTaskMonitor
from ghidra.program.model.lang import Register



functions_count = 0
addresses_count = 0
instructions_count = 0


def create_dot_graph(func, instruction_list, jumps, conditional_jumps, ret_instructions, def_use_info):

    """
    Generates a DOT graph representation of the control flow within a function.
    """
    # Convert the entry point of the function to a hexadecimal string

    entry_point = "0x{}".format(func.getEntryPoint().toString().lstrip('0'))
    dot_graph = 'digraph "{}" {{\n'.format(entry_point)
    node_counter = 1
    address_to_node = {}  # Maps addresses to node names

    # Create graph nodes for each instruction address
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
        if addr in ret_instructions:  # Skip edge creation for RET instructions
            continue
        if i + 1 < len(instruction_list):
            current_node = address_to_node[addr]
            next_addr = instruction_list[i + 1]
            next_node = address_to_node[next_addr]

            # Check if the current instruction is a jump and add an edge accordingly
            if addr in jumps:
                jump_to_node = address_to_node[jumps[addr]]
                # Draw line for jump with style based on jump type
                #jump_style = 'conditional_jump' if addr in conditional_jumps else 'unconditional_jump'
                #dot_graph += '    {} -> {}; [{}]\n'.format(current_node, jump_to_node, jump_style)
                dot_graph += '    {} -> {};\n'.format(current_node, jump_to_node)

                # For conditional jumps, also connect to the next sequential instruction
                if addr in conditional_jumps:
                    dot_graph += '    {} -> {};\n'.format(current_node, next_node)
            elif next_node:  # Ensure sequential flow except for RET instructions
                dot_graph += '    {} -> {};\n'.format(current_node, next_node)

    dot_graph += '}'
    return dot_graph


def operandRegisterHelper(instruction, defs, uses, addr_str):
    numOperand = instruction.getNumOperands()
    for i in range(numOperand):
        operand = instruction.getRegister(i)
        opType = instruction.getOperandRefType(i)
        
        # Check if operand is a register and update uses/defs lists accordingly
        if operand is not None:
            if opType.isConditional() and opType.isFlow():
                if "eflags" not in uses:
                    uses.append("eflags")
            if opType.isRead() and str(operand) not in uses:
                    uses.append(str(operand))
            if opType.isWrite() and str(operand) not in defs:
                    defs.append(str(operand))

        # Handle memory references involving registers
        else:
            refListing = instruction.getDefaultOperandRepresentationList(i)
            refSpec = instruction.getDefaultOperandRepresentation(i)
            for element in refListing:
                if isinstance(element, Register):
                    if opType.isRead():
                        if str(refSpec) not in uses:
                            uses.append(str(refSpec))
                        if str(element) not in uses:
                            uses.append(str(element))
                    if opType.isWrite():
                        if str(refSpec) not in defs:
                            defs.append(str(refSpec))
                        if str(element) not in defs:
                            defs.append(str(element))


def analyze_instruction(instruction, addr_str):
    # Define a set of mnemonics (assembly instructions) to be analyzed.
    mnemonicSet = {'ADD', 'AND', 'CALL', 'CMP', 'DEC', 'IMUL', 'INC', 'JA', 'JBE', 'JC', 'JG', 'JL', 'JLE', 'JMP',
                   'JNC', 'JNZ', 'JZ', 'LEA', 'LEAVE', 'MOV', 'MOVSX', 'MOVZX', 'OR', 'POP', 'PUSH', 'RET', 'SAR',
                   'SETNZ', 'SHR', 'STOSD.REP', 'SUB', 'TEST', 'XOR'}

    mnemonic = instruction.getMnemonicString()
    defs = []  # List to hold defined variables
    uses = []  # List to hold used variables

    operandRegisterHelper(instruction, defs, uses, addr_str)
    # Ignore 'CALL' instructions
    if mnemonic == 'CALL':
        pass
    # Analyze instruction based on its type and collect define-use information
    elif mnemonic == 'ADD' or mnemonic == 'SUB':
        # operandRegisterHelper(instruction, defs, uses, addr_str)
        if 'eflags' not in defs:
            defs.append('eflags')
    elif mnemonic == 'AND' or mnemonic == 'OR' or mnemonic == 'XOR':
        pass
    elif mnemonic == 'CMP':
        # operandRegisterHelper(instruction, defs, uses, addr_str)
        if 'eflags' not in defs:
            defs.append('eflags')
    elif mnemonic == 'IMUL':
        pass
    elif mnemonic == 'INC' or mnemonic == 'DEC':
        # operandRegisterHelper(instruction, defs, uses, addr_str)
        pass
    elif mnemonic in ['JA', 'JZ', 'JBE', 'JC', 'JG', 'JL', 'JLE', 'JNC', 'JNZ']:
        # uses.append('eflags')
        pass
    elif mnemonic == 'JMP':
        pass
    elif mnemonic == 'LEA':
        pass
    elif mnemonic == 'LEAVE':
        pass
    elif mnemonic == 'MOV':
        # operandRegisterHelper(instruction, defs, uses, addr_str)
        pass
    elif mnemonic == 'MOVSX':
        pass
    elif mnemonic == 'MOVZX':
        pass
    elif mnemonic == 'POP':
        pass
    elif mnemonic == 'PUSH':
        if 'ESP' not in defs:
            defs.append('ESP')
        if '[ESP]' not in defs:
            defs.append('[ESP]')
        if 'ESP' not in uses:
            uses.append('ESP')
    elif mnemonic == 'RET':
        if 'ESP' not in uses:
            defs.append('ESP')
        if '[ESP]' not in uses:
            defs.append('[ESP]')
        if 'ESP' not in defs:
            uses.append('ESP')
    elif mnemonic == 'SAR' or mnemonic == 'SAL':
        pass
    elif mnemonic == 'SETNZ':
        pass
    elif mnemonic == 'SHR' or mnemonic == 'SHL':
        pass
    elif mnemonic == 'STOSD.REP':
        pass
    elif mnemonic == 'TEST':
        pass
    else:
        return

    # Generate and return the define-use label without handling 'CALL'
    def_use_label = "D: {} U: {}".format(", ".join(sorted(defs)), ", ".join(sorted(uses)))
    return def_use_label


def is_in_eflags(register):
    EFLAGS = {"CF", "PF", "AF", "ZF", "SF", "OF", "DF", "TF", "IF", "IOPL", "NT", "RF", "VM", "AC", "VIF", "VIP", "ID"}
    return register in EFLAGS


def collect_instructions(func):
    global addresses_count
    global instructions_count

    instruction_list = []
    jumps = {}  # Maps source to destination addresses for jumps

    conditional_jumps = set()  # Addresses of conditional jumps
    ret_instructions = set() # Addresses of return instructions

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

                # Check if the current instruction is a 'RET' instruction. If so, add its address to the "ret_instructions" set.
                if instruction.getMnemonicString() == 'RET':
                    ret_instructions.add(addr_str)

                # Record jump instructions
                if instruction.getFlowType().isJump() and instruction.getFlows():
                    dst_addr = instruction.getFlows()[0].toString()[2:]  # Extract address without "0x"
                    jumps[addr_str] = dst_addr
                    # Determine if the jump is conditional
                    if instruction.getFlowType().isConditional():
                        conditional_jumps.add(addr_str)

    instruction_list.sort(key=lambda x: int(x, 16))  # Sort instructions by address
    return create_dot_graph(func, instruction_list, jumps, conditional_jumps, ret_instructions, def_use_info)


def process_functions():
    global functions_count
    final_result = ""
    function_manager = currentProgram.getFunctionManager()
    functions = function_manager.getFunctions(True)

    for func in functions:
        functions_count += 1
        dot_graph = collect_instructions(func)
        print(dot_graph)
        final_result += dot_graph + "\n\n"

    return final_result

def main():
    try:
        final_result = process_functions()
        print("{} functions, {} addresses, {} instructions processed.".format(functions_count, addresses_count,
                                                                              instructions_count))
        # Define the file path to the Desktop directory
        desktop_path = os.path.join(os.path.expanduser("~"), "Desktop")
        file_path = os.path.join(desktop_path, "submission.dot")

        # Attempt to write content to the file
        with open(file_path, "w") as file:
            file.write(final_result)

        print("submission.dot created.")
    except Exception as e:
        raise Exception("Failed to create submission.dot. Error: {}".format(e))

if __name__ == '__main__':
    main()
