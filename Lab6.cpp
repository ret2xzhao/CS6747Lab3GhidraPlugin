#include "pin.H"
#include <iostream>
#include <fstream>
#include <map>
#include <set>
#include <stack>

std::ofstream OutFile;
std::ifstream IPDFile;
std::map<ADDRINT, ADDRINT> ipdMap; // Maps each address to its immediate post-dominator

bool instrumentationEnabled = false;
ADDRINT binaryStart = 0;
ADDRINT binaryEnd = 0;
ADDRINT targetAddress = 0x40297D; // The target address to start instrumentation
std::map<ADDRINT, std::set<ADDRINT>> controlFlowGraph;
std::stack<std::pair<ADDRINT, ADDRINT>> controlDependenceStack;

ADDRINT IPD(ADDRINT address) {
    auto it = ipdMap.find(address);
    return (it != ipdMap.end()) ? it->second : 0;
}

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

VOID Instruction(INS ins, VOID* v) {
    ADDRINT insAddress = INS_Address(ins);

    if (insAddress >= binaryStart && insAddress <= binaryEnd) {
        if (insAddress == targetAddress) {
            instrumentationEnabled = true;
        }

        if (instrumentationEnabled) {
            if (INS_IsRet(ins) || (INS_IsBranchOrCall(ins) && INS_HasFallThrough(ins))) {
                ADDRINT nextAddr = INS_NextAddress(ins);
                Merge(nextAddr);
            }

            ADDRINT currentCD = GetCurrentCD();

            if (INS_IsBranchOrCall(ins) && !INS_IsRet(ins)) {
                if (currentCD != 0) {
                    controlFlowGraph[currentCD].insert(insAddress);
                }
                Branch(insAddress);
            }

            if (currentCD != 0) {
                controlFlowGraph[currentCD].insert(insAddress);
            }
        }
    }
}

VOID ImageLoad(IMG img, VOID* v) {
    if (IMG_IsMainExecutable(img)) {
        binaryStart = IMG_LowAddress(img);
        binaryEnd = IMG_HighAddress(img);
    }
}

VOID LoadIPDData() {
    IPDFile.open("C:\\Repo\\cs6747\\post_dominators.txt");
    ADDRINT address, ipd;
    while (IPDFile >> std::hex >> address >> ipd) {
        ipdMap[address] = ipd;
    }
    IPDFile.close();
}

VOID Fini(INT32 code, VOID* v) {
    OutFile << "digraph controlflow {" << std::endl;
    for (const auto& pair : controlFlowGraph) {
        for (const auto& dest : pair.second) {
            OutFile << "    \"0x" << std::hex << pair.first << "\" -> \"0x" << std::hex << dest << "\";" << std::endl;
        }
    }
    OutFile << "}" << std::endl;
    OutFile.close();
}

INT32 Usage() {
    std::cerr << "This Pintool generates a file named submission.dot." << std::endl;
    std::cerr << "Usage:" << std::endl << "\tpin -t <toolname>.so -- <application>" << std::endl;
    return -1;
}

int main(int argc, char* argv[]) {
    if (PIN_Init(argc, argv)) {
        return Usage();
    }

    OutFile.open("submission.dot");
    LoadIPDData();  // Load the IPD data at startup

    PIN_AddFiniFunction(Fini, 0);
    IMG_AddInstrumentFunction(ImageLoad, 0);
    INS_AddInstrumentFunction(Instruction, 0);

    PIN_StartProgram();
    return 0;
}
