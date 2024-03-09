"""
Data Dependence Algorithm:
1. Enhance the analyze_instruction function to accurately capture all definitions and uses of variables.
    - Fix existing bugs in the function.
2. Traverse the Control Flow Graph (CFG): Implement a method to traverse the Control Flow Graph (CFG) to find dependencies based on the collected definitions and uses.
    - Building a dictionary where the key is each path within the function, and the values are the instructions that the path can traverse, starting from "Start"
    - To avoid the path explosion problem often encountered with loops, set a loop unrolling limit.
3. Along the path for each instruction, find the most recent definition of a variable before its use by traversing the path backwards.
4. Modify the output to include data dependencies for each instruction.
5. Generate a data dependency graph in DOT format.
"""

import os
import re
from ghidra.program.model.block import BasicBlockModel
from ghidra.program.model.lang import OperandType, Register
import ghidra.program.model.symbol.RefType as RefType
import ghidra.util.task.ConsoleTaskMonitor as ConsoleTaskMonitor
from ghidra.program.model.lang import Register


functions_count = 0
addresses_count = 0
instructions_count = 0
instruction_def_use = {}


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
        opType  = instruction.getOperandRefType(i)
        
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
            thisDynamic = ''
            isPart = False
            isInstance = False
            isRead = False
            isWrite = False
            eor = False
            refListing = instruction.getDefaultOperandRepresentationList(i)
            for element in refListing:
                if isPart:
                    thisDynamic += str(element)
                if element == '[':
                    isPart = True
                    thisDynamic += str(element)
                if element == ']':
                    isPart = False
                    eor = True
                if isinstance(element, Register):
                    isInstance = True
                    if opType.isRead():
                        isRead = True
                        if str(element) not in uses:
                            uses.append(str(element))
                    if opType.isWrite():
                        isWrite = True
                        if str(element) not in defs:
                            defs.append(str(element))
                if isInstance and eor:
                    if (thisDynamic not in uses) and isRead:
                        uses.append(thisDynamic)
                    if (thisDynamic not in defs) and isWrite:
                        defs.append(thisDynamic)


def analyze_instruction(instruction, addr_str):
    """
    # Define a set of mnemonics (assembly instructions) to be analyzed.
    mnemonicSet = {'ADD', 'AND', 'CALL', 'CMP', 'DEC', 'IMUL', 'INC', 'JA', 'JBE', 'JC', 'JG', 'JL', 'JLE', 'JMP',
                   'JNC', 'JNZ', 'JZ', 'LEA', 'LEAVE', 'MOV', 'MOVSX', 'MOVZX', 'OR', 'POP', 'PUSH', 'RET', 'SAR',
                   'SETNZ', 'SHR', 'STOSD.REP', 'SUB', 'TEST', 'XOR'}
    """
    global instruction_def_use
    mnemonic = instruction.getMnemonicString()
    defs = []  # List to hold defined variables
    uses = []  # List to hold used variables

    operandRegisterHelper(instruction, defs, uses, addr_str)
    if mnemonic == 'CALL':
        callTargetRepresentation = instruction.getDefaultOperandRepresentation(0)
        addressMatch = re.search(r'\[([0-9a-fx]+)\]', callTargetRepresentation, re.IGNORECASE)
        if addressMatch:
            callTarget = '[{}]'.format(addressMatch.group(1))
        else:
            callTarget = callTargetRepresentation
        uses.append(callTarget)
    # Analyze instruction based on its type and collect define-use information
    elif mnemonic == 'ADD' or mnemonic == 'SUB':
        if 'eflags' not in defs:
            defs.append('eflags')
    elif mnemonic == 'AND' or mnemonic == 'OR' or mnemonic == 'XOR':  #Done
        if 'eflags' not in defs:
            defs.append('eflags')
    elif mnemonic == 'CMP':
        if 'eflags' not in defs:
            defs.append('eflags')
    elif mnemonic == 'IMUL' or mnemonic == 'MUL':
        if 'eflags' not in defs:
            defs.append('eflags')
    elif mnemonic == 'INC' or mnemonic == 'DEC':
        if 'eflags' not in defs:
            defs.append('eflags')
    elif mnemonic in ['JA', 'JZ', 'JBE', 'JC', 'JG', 'JL', 'JLE', 'JNC', 'JNZ']:
        if 'eflags' not in uses:
            uses.append('eflags')
    elif mnemonic == 'JMP':
        pass
    elif mnemonic == 'LEA':
        destReg = instruction.getRegister(0)
        if destReg is not None and str(destReg) not in defs:
            defs.append(str(destReg))
        sourceOperand = instruction.getDefaultOperandRepresentation(1)
        memoryRefMatch = re.search(r'\[(.*?)\]', sourceOperand)
        foundRegisters = set(re.findall(r'\b([a-zA-Z]+)\b', memoryRefMatch.group(1)))
        for reg in foundRegisters:
            if reg not in uses:
                uses.append(reg)
    elif mnemonic == 'LEAVE':
        defs.append('EBP')
        defs.append('ESP')
        uses.append('EBP')
        uses.append('[EBP]')
    elif mnemonic == 'MOV':
        pass
    elif mnemonic == 'MOVSX':
        pass
    elif mnemonic == 'MOVZX':
        pass
    elif mnemonic == 'POP': #Done
        if 'ESP' not in defs:
            defs.append('ESP')
        if '[ESP]' not in uses:
            uses.append('[ESP]')
        if 'ESP' not in uses:
            uses.append('ESP')
    elif mnemonic == 'PUSH':
        if 'ESP' not in defs:
            defs.append('ESP')
        if '[ESP]' not in defs:
            defs.append('[ESP]')
        if 'ESP' not in uses:
            uses.append('ESP')
    elif mnemonic == 'RET':
        if 'ESP' not in uses:
            uses.append('ESP')
        if '[ESP]' not in uses:
            uses.append('[ESP]')
        if 'ESP' not in defs:
            defs.append('ESP')
    elif mnemonic == 'SAR' or mnemonic == 'SAL':
        if 'eflags' not in defs:
            defs.append('eflags')
    elif mnemonic == 'SETNZ':
        if 'eflags' not in uses:
            uses.append('eflags')
    elif mnemonic == 'SHR' or mnemonic == 'SHL':
        if 'eflags' not in defs:
            defs.append('eflags')
    elif mnemonic == 'STOSD.REP':
        defs = []
        defs.append('[EDI]')
        defs.append('EDI')
        uses.append('EAX')
        uses.append('EDI')
        uses.append('eflags')
    elif mnemonic == 'TEST':  #Done
        if 'eflags' not in defs:
            defs.append('eflags')
    else:
        return

    # Generate and return the define-use label without handling 'CALL'
    def_use_label = "D: {} U: {}".format(", ".join(sorted(defs)), ", ".join(sorted(uses)))
    instruction_def_use[addr_str] = {"def": defs, "use": uses}
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
    ret_instructions = set()  # Addresses of return instructions
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
        print(instruction_def_use)

    except Exception as e:
        raise Exception("Failed to create submission.dot. Error: {}".format(e))

if __name__ == '__main__':
    main()
