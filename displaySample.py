import ghidra.app.script.GhidraScript
import ghidra.app.services.GraphDisplayBroker as GraphDisplayBroker
import ghidra.framework.plugintool.PluginTool
from ghidra.service.graph import *

graph = AttributedGraph("Test", EmptyGraphType())
nextEdgeID = 1
def displayGraph():
    tool = getState().getTool()
    service = tool.getService(GraphDisplayBroker)
    display = service.getDefaultGraphDisplay(False, monitor)
    generateGraph()
    display.setGraph(graph, "Test", False, monitor)
def generateGraph():
    A = vertex("A")
    B = vertex("B")
    C = vertex("C")
    D = vertex("D")
    edge(A, B)
    edge(A, C)
    edge(B, D)
    edge(C, D)
    edge(D, A)


def vertex(name):
    return graph.addVertex(name, name)


def edge(v1,v2):
    return graph.addEdge(v1, v2)


displayGraph()
