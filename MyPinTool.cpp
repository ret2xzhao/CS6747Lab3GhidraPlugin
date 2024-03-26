#include "pin.H"
#include <iostream>
#include <fstream>

std::ofstream OutFile;

// Function to be called when the application exits
VOID Fini(INT32 code, VOID* v)
{
    OutFile << "digraph controlflow {" << std::endl;
    // Place for control flow graph here
    OutFile << "  }" << std::endl;
    OutFile.close();
}

// Usage function
INT32 Usage()
{
    std::cerr << "This Pintool generates a file named submission.dot with a specific content." << std::endl;
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

    // Start the program, never returns
    PIN_StartProgram();

    return 0;
}
