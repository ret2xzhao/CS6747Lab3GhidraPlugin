#include "pin.H"
#include <iostream>
#include <fstream>
#include <map>
#include <set>
#include <stack>

std::ofstream OutFile;
bool instrumentationEnabled = false;

ADDRINT binaryStart = 0;
ADDRINT binaryEnd = 0;
ADDRINT targetAddress = 0x40297D; // The target address to start instrumentation

// A map from each instruction to the set of instructions it directly controls
std::map<ADDRINT, std::set<ADDRINT>> controlFlowGraph;

// Stack for control dependencies, storing pairs of (address, immediate post-dominator)
std::stack<std::pair<ADDRINT, ADDRINT>> controlDependenceStack;

// Implementation of IPD (Immediate Post-Dominator) calculation.
ADDRINT IPD(ADDRINT address) {
    // TODO: Replace with actual IPD calculation logic
    return 0;
}

// Function to retrieve the current control dependency from the CDS
ADDRINT GetCurrentCD() {
    if (!controlDependenceStack.empty()) {
        return controlDependenceStack.top().first;
    }
    return 0;
}

VOID Branch(ADDRINT branchAddr) {
    controlDependenceStack.push(std::make_pair(branchAddr, IPD(branchAddr)));
}

VOID Merge(ADDRINT mergeAddr) {
    while (!controlDependenceStack.empty() && controlDependenceStack.top().second == mergeAddr) {
        controlDependenceStack.pop();
    }
}

// Instruction instrumentation function
VOID Instruction(INS ins, VOID* v) {
    ADDRINT insAddress = INS_Address(ins);

    if (insAddress >= binaryStart && insAddress <= binaryEnd) {
        if (insAddress == targetAddress) {
            instrumentationEnabled = true;
        }

        if (instrumentationEnabled) {
            // Handling branches and push to CDS
            if (INS_IsBranchOrCall(ins) && !INS_IsRet(ins)) {
                Branch(insAddress);
            }

            // Handling merge points and pop from CDS
            if (INS_IsRet(ins) || (INS_IsBranchOrCall(ins) && INS_HasFallThrough(ins))) {
                ADDRINT nextAddr = INS_NextAddress(ins);
                Merge(nextAddr);
            }

            // Add the control dependency for the current instruction
            ADDRINT currentCD = GetCurrentCD();
            if (currentCD != 0) {
                controlFlowGraph[currentCD].insert(insAddress);
            }
        }
    }
}

// Image loading event handler
VOID ImageLoad(IMG img, VOID* v) {
    if (IMG_IsMainExecutable(img)) {
        binaryStart = IMG_LowAddress(img);
        binaryEnd = IMG_HighAddress(img);
    }
}

// Application exit event handler
VOID Fini(INT32 code, VOID* v) {
    OutFile << "digraph controlflow {" << std::endl;

    // Iterate through the control flow graph and print edges
    for (const auto& pair : controlFlowGraph) {
        for (const auto& dest : pair.second) {
            OutFile << "    \"0x" << std::hex << pair.first << "\" -> \"0x" << std::hex << dest << "\";" << std::endl;
        }
    }

    OutFile << "}" << std::endl;
    OutFile.close();
}

// Usage function
INT32 Usage() {
    std::cerr << "This Pintool generates a file named submission.dot." << std::endl;
    std::cerr << "Usage:" << std::endl << "\tpin -t <toolname>.so -- <application>" << std::endl;
    return -1;
}

int main(int argc, char* argv[]) {
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
