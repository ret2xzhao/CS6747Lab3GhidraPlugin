#@category _NEW_
#@author YuChen Gu, Xin Zhao
#@keybinding 
#@menupath 
#@toolbar 

from ghidra.program.model.block import BasicBlockModel
from ghidra.program.model.listing import CodeUnitIterator

functions_count    = 0
instructions_count = 0

def collect_instructions(func, func_with_instructions):
    global instructions_count
    
    # Create a basic block model
    basicBlockModel = BasicBlockModel(currentProgram)
    
    # Get address set for the function
    addrSet = func.getBody()
    #print(type(addrSet)) # <type 'ghidra.program.model.address.AddressSet'>
    
    # Get iterator for code blocks
    codeBlockIter = basicBlockModel.getCodeBlocksContaining(addrSet, getMonitor())
    #print(type(codeBlockIter)) # <type 'ghidra.program.model.block.SimpleBlockIterator'>

    # Iterate through code blocks and collect basic blocks
    while codeBlockIter.hasNext():
        codeBlock = codeBlockIter.next()
        #print(type(codeBlock)) # <type 'ghidra.program.model.block.CodeBlockImpl'>
        
        addressIterator = codeBlock.getAddresses(True) # Get all addresses within the block

        # Iterate over each address and display the instruction
        while addressIterator.hasNext():
            address = addressIterator.next()
            instruction = getInstructionAt(address)
            if instruction:
                instructions_count = instructions_count + 1
                if func in func_with_instructions:
                    func_with_instructions[func].append(instruction)
                else:
                    func_with_instructions[func] = [instruction]


def process_functions(func_with_instructions):
    """
    Process all functions in the binary.
    """
    global functions_count
    function_manager = currentProgram.getFunctionManager()
    
    # Iterate through all functions
    for func in function_manager.getFunctions(True):
        #print(func) # Print function name
        #print(type(func)) # <type 'ghidra.program.database.function.FunctionDB'>
        func_address = func.getEntryPoint()
        func_info = "{}: {}".format(func, func_address)
        print(func_info)
        functions_count = functions_count + 1
        basic_blocks = collect_instructions(func, func_with_instructions) # Get basic blocks for the function


def main():
    func_with_instructions = {}
    process_functions(func_with_instructions)
    print(func_with_instructions)
    
    print("{} functions in total.".format(functions_count))
    print("{} instructions in total.".format(instructions_count))


if __name__ == '__main__':
    main()
