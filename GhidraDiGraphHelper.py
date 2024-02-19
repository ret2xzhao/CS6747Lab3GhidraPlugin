# TODO write a description for this script
# @author
# @category _NEW_
# @keybinding
# @menupath
# @toolbar


# TODO Add User Code Here

from ghidra.util.graph import DirectedGraph
from ghidra.util.graph import Edge
from ghidra.util.graph import Vertex
from ghidra.program.model.symbol import SourceType


def getAddress(offset):
    return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(offset)


digraph = DirectedGraph()
listing = currentProgram.getListing()
fm = currentProgram.getFunctionManager()

funcs = fm.getFunctions(True)  # True mean iterate forward
for func in funcs:
    # Add function vertices
    print("Function: {} @ 0x{}".format(func.getName(), func.getEntryPoint()))  # FunctionDB
    digraph.add(Vertex(func))

    # Add edges for static calls
    entryPoint = func.getEntryPoint()
    instructions = listing.getInstructions(entryPoint, True)
    print(instructions)
    for instruction in instructions:
        addr = instruction.getAddress()
        print("addr: {}".format(addr))
        oper = instruction.getMnemonicString()
        if oper == "CALL":

            print("    0x{} : {}".format(addr, instruction))
            flows = instruction.getFlows()
            print("flow: {}".format(flows[0]))
            if len(flows) == 1:
                calledFunction = getFunctionAt(addr)
                if calledFunction:
                    target_addr = "0x{}".format(flows[0])
                    digraph.add(Edge(Vertex(func), Vertex(fm.getFunctionAt(getAddress(target_addr)))))
            # else:
            # externalLocation = currentProgram.getExternalManager().getExternalLocation(addrc)
            # digraph.add(Edge(Vertex(func), Vertex(externalLocation.getLabel())))

print("DiGraph info:")
edges = digraph.edgeIterator()
while edges.hasNext():
    edge = edges.next()
    from_vertex = edge.from()
    to_vertex = edge.to()
    print("  Edge from {} to {}".format(from_vertex, to_vertex))

vertices = digraph.vertexIterator()
while vertices.hasNext():
    vertex = vertices.next()
    print("  Vertex: {} (key: {})".format(vertex, vertex.key()))
# some extra stuff you might want to see
# print("    type(vertex):      {}".format(type(vertex)))
# print("    vertex.hashCode(): {}".format(vertex.hashCode()))
# print("    vertex.referent(): {}".format(vertex.referent()))
# print("    type(referent):    {}".format(type(vertex.referent())))
