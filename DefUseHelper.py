from ghidra.program.model.lang import Register


def run():
    # Iterate over all instructions in the current instruction list
    instructions = []
    for instr in instructions:
        analyze_instruction(instr)


def analyze_instruction(instruction):
    # Retrieve the mnemonic of the instruction
    mnemonic = instruction.getMnemonicString()

    # Determine defs and uses based on the mnemonic
    defs, uses = get_defs_uses(mnemonic, instruction)

    # Print out the defs and uses for each instruction
    print("Instruction: %s" % mnemonic)
    print("Defs: %s" % defs)
    print("Uses: %s" % uses)


def get_defs_uses(mnemonic, instruction):
    # Maps for defs and uses based on the mnemonic
    defs_uses_map = {
        'MOV': {'defs': [0], 'uses': [1]},
        'ADD': {'defs': [0], 'uses': [0, 1]},
        'SUB': {'defs': [0], 'uses': [0, 1]},
        'MUL': {'defs': ['EAX', 'EDX'], 'uses': [0]},
        'DIV': {'defs': ['EAX', 'EDX'], 'uses': ['EAX']},
        'IDIV': {'defs': ['EAX', 'EDX'], 'uses': ['EAX']},
        'INC': {'defs': [0], 'uses': [0]},
        'DEC': {'defs': [0], 'uses': [0]},
        'PUSH': {'defs': ['ESP'], 'uses': [0]},
        'POP': {'defs': ['ESP', 0], 'uses': ['ESP']},
        'CMP': {'defs': [], 'uses': [0, 1]},
        'JMP': {'defs': [], 'uses': []},
        'JE': {'defs': [], 'uses': []},
        'JZ': {'defs': [], 'uses': []},
        'CALL': {'defs': ['ESP'], 'uses': [0, 'ESP']},
        'RET': {'defs': ['ESP'], 'uses': ['ESP']},
        'LEA': {'defs': [0], 'uses': [1]},
        'AND': {'defs': [0], 'uses': [0, 1]},
        'OR': {'defs': [0], 'uses': [0, 1]},
        'XOR': {'defs': [0], 'uses': [0, 1]},
        'SHL': {'defs': [0], 'uses': [0, 1]},
        'SHR': {'defs': [0], 'uses': [0, 1]},
        'SAR': {'defs': [0], 'uses': [0, 1]},
        'SAL': {'defs': [0], 'uses': [0, 1]},
    }

    defs = []
    uses = []

    # Check if the mnemonic is in the map
    if mnemonic in defs_uses_map:
        for def_idx in defs_uses_map[mnemonic]['defs']:
            if isinstance(def_idx, int):  # Operand index
                defs.append(get_operand_name(instruction, def_idx))
            else:  # Register name
                defs.append(def_idx)

        for use_idx in defs_uses_map[mnemonic]['uses']:
            if isinstance(use_idx, int):  # Operand index
                uses.append(get_operand_name(instruction, use_idx))
            else:  # Register name
                uses.append(use_idx)
    else:
        print("%s is not in the map" % mnemonic)

    return defs, uses


def get_operand_name(instruction, operand_index):
    operand_objects = instruction.getOpObjects(operand_index)
    names = []
    for operand in operand_objects:
        if isinstance(operand, Register):
            names.append(operand.getName())
        elif isinstance(operand, Address):
            pass
        else:
            pass
    return names


if __name__ == "__main__":
    run()
