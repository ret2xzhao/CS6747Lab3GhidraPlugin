#@category _NEW_
#@author YuChen Gu, Xin Zhao
#@keybinding 
#@menupath 
#@toolbar 

from ghidra.program.model.block import BasicBlockModel
from ghidra.program.model.listing import CodeUnitIterator



functions_count = 0
instructions_count = 0
addresses_count = 0
mnemonicSet = set()


def collect_instructions(func, func_with_instructions):
    global instructions_count
    global addresses_count


    # Create a basic block model
    basicBlockModel = BasicBlockModel(currentProgram)
    
    # Get address set for the function

    addrSet = func.getBody() # <type 'ghidra.program.model.address.AddressSet'>
    
    # Get iterator for code blocks
    codeBlockIter = basicBlockModel.getCodeBlocksContaining(addrSet, getMonitor()) # <type 'ghidra.program.model.block.SimpleBlockIterator'>

    # Iterate through code blocks and collect basic blocks
    while codeBlockIter.hasNext():
        codeBlock = codeBlockIter.next() # <type 'ghidra.program.model.block.CodeBlockImpl'>
        addressIterator = codeBlock.getAddresses(True) # Get all addresses within the block

        # Iterate over each address and display the instruction
        while addressIterator.hasNext():
            address = addressIterator.next()
            instruction = getInstructionAt(address)
            if instruction:

                addresses_count += 1
                instructions_count += 1
                getMnemonicSet(instruction)
                address_instruction  = "%s : %s" % (address.toString(), instruction.toString())
                if func in func_with_instructions:
                    func_with_instructions[func].append(address_instruction)
                else:
                    func_with_instructions[func] = [address_instruction]


def process_functions(func_with_instructions):
    """
    Process all functions in the binary.
    """
    global functions_count
    function_manager = currentProgram.getFunctionManager()
    
    # Iterate through all functions

    for func in function_manager.getFunctions(True): # <type 'ghidra.program.database.function.FunctionDB'>
        #print(func) # Print function name
        func_address = func.getEntryPoint()
        func_info = "{}: {}".format(func, func_address)
        #print(func_info)
        functions_count += 1
        collect_instructions(func, func_with_instructions) # Get basic blocks for the function


def generate_DOT_directed_graph(func_with_first_address):
    function_manager = currentProgram.getFunctionManager()
    
    # Iterate through all functions
    for func in function_manager.getFunctions(True):
        func_address = func.getEntryPoint()
        if func in func_with_first_address:
            func_with_first_address[func].append(func_address)
        else:
            func_with_first_address[func] = [func_address]


def getMnemonicSet(instruction):
    global mnemonicSet
    mnemonicSet.add(instruction.getMnemonicString())
    return mnemonicSet


def displayInfo(func_with_instructions):
    print("{} functions, {} addresses, {} instructions in total.".format(functions_count, addresses_count, instructions_count))
    print(func_with_instructions)
    # mnemonicSet: set([u'RET', u'ADD', u'CALL', u'JL', u'JLE', u'SAR', u'JBE', u'JZ', u'MOVZX', u'JNZ', u'LEAVE', u'IMUL', u'SHR', u'SUB', u'OR', u'DEC', u'CMP', u'LEA', u'JMP', u'POP', u'MOV', u'TEST', u'AND', u'JA', u'JC', u'XOR', u'STOSD.REP', u'MOVSX', u'SETNZ', u'JG', u'JNC', u'PUSH', u'INC'])
    #print(mnemonicSet)



def main():
    func_with_instructions = {}
    process_functions(func_with_instructions)

    displayInfo(func_with_instructions)

if __name__ == '__main__':
    main()
