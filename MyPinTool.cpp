#include "pin.H"
#include <iostream>
#include <fstream>
#include <map>
#include <set>
#include <stack>

// Imagebase: 0x400000L
// Headers[start: 0x400000, end: 0x4003ff]
// .text  [start: 0x401000, end: 0x402dff]
// .rdata [start: 0x403000, end: 0x4039ff]
// .data  [start: 0x404000, end: 0x4047ff]
// .rsrc  [start: 0x405000, end: 0x4053ff]

std::ofstream OutFile;
bool instrumentationEnabled = false; // Global flag to control instrumentation

ADDRINT binaryStart = 0;
ADDRINT binaryEnd = 0;
ADDRINT targetAddress = 0x40297D; // The target address to start instrumentation
ADDRINT prevInstruction = 0; // Address of the previous instruction
std::map<ADDRINT, std::set<ADDRINT>> controlFlowGraph; // Map of instruction addresses to subsequent instruction addresses
std::stack<ADDRINT> callStack; // Stack to track return addresses for calls


VOID Instruction(INS ins, VOID* v)
{
    ADDRINT insAddress = INS_Address(ins);

    // Ensure the instruction is within the main binary range
    if (insAddress >= binaryStart && insAddress <= binaryEnd) {
        // Enable instrumentation at the target address (WinMain function)
        if (insAddress == targetAddress) {
            instrumentationEnabled = true;
        }

        // Perform instrumentation logic if enabled
        if (instrumentationEnabled) {
            // Instrumentation for all instructions to ensure linear execution is tracked
            if (prevInstruction != 0) {
                // Link the current instruction with the previous one unless it's the start
                controlFlowGraph[prevInstruction].insert(insAddress);
            }

            // For call instructions, push the return address onto the stack and link in CFG
            if (INS_IsCall(ins)) {
                ADDRINT returnAddress = INS_NextAddress(ins);
                callStack.push(returnAddress);
                controlFlowGraph[insAddress].insert(returnAddress);
            }
            // For return instructions, pop the return address from the stack and link it
            else if (INS_IsRet(ins) && !callStack.empty()) {
                ADDRINT returnToAddress = callStack.top();
                callStack.pop();
                // Link return instruction to the actual return address
                controlFlowGraph[insAddress].insert(returnToAddress);
            }

            // Handling direct and indirect branches
            if (INS_IsBranchOrCall(ins)) {
                if (INS_HasFallThrough(ins)) {
                    // Fall-through path for branches that can continue to the next instruction
                    controlFlowGraph[insAddress].insert(INS_NextAddress(ins));
                }
                else if (INS_IsDirectBranchOrCall(ins)) {
                    // Direct branch/call
                    controlFlowGraph[insAddress].insert(INS_DirectBranchOrCallTargetAddress(ins));
                }
            }

            // Update the previous instruction address for the next iteration
            prevInstruction = insAddress;
        }
    }
}

// This function is called when an image is loaded
VOID ImageLoad(IMG img, VOID* v)
{
    // Check if this is the main executable
    if (IMG_IsMainExecutable(img)) {
        binaryStart = IMG_LowAddress(img);
        binaryEnd = IMG_HighAddress(img);
    }
}


// Function to be called when the application exits
VOID Fini(INT32 code, VOID* v)
{
    OutFile << "digraph controlflow {" << std::endl;

    // Add the start and end address as a special node or comment
    //OutFile << "// Start Address: " << std::hex << binaryStart << std::endl;
    //OutFile << "// End Address: " << std::hex << binaryEnd << std::endl;

    // Add an extra newline for readability
    //OutFile << std::endl;

    // Iterate through the control flow graph and print edges
    for (const auto& pair : controlFlowGraph) {
        for (const auto& dest : pair.second) {
            OutFile << "     \"0x" << std::hex << pair.first << "\" -> \"0x" << std::hex << dest << "\";" << std::endl;
        }
    }
    OutFile << "  }" << std::endl;
    OutFile.close();
}


// Usage function
INT32 Usage()
{
    std::cerr << "This Pintool generates a file named submission.dot." << std::endl;
    std::cerr << "Usage:" << std::endl << "\tpin -t <toolname>.so -- <application>" << std::endl;
    return -1;
}


int main(int argc, char* argv[])
{
    // Initialize pin
    if (PIN_Init(argc, argv)) {
        return Usage();
    }

    OutFile.open("submission.dot");

    // Register the function to be called when the application exits
    PIN_AddFiniFunction(Fini, 0);

    // Register ImageLoad to be called when an image is loaded
    IMG_AddInstrumentFunction(ImageLoad, 0);

    // Register Instruction to be called to instrument instructions
    INS_AddInstrumentFunction(Instruction, 0);

    // Start the program, never returns
    PIN_StartProgram();

    return 0;
}
