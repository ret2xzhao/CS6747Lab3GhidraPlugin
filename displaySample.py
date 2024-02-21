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
    A = vertex(graph,"A")
    B = vertex(graph,"B")
    C = vertex(graph,"C")
    D = vertex(graph,"D")
    edge(graph,A, B)
    edge(graph,A, C)
    edge(graph,B, D)
    edge(graph,C, D)
    edge(graph,D, A)

    E = vertex(graph, "E")
    F = vertex(graph, "F")
    edge(graph, E, F)

def vertex(graph, name):
    return graph.addVertex(name, name)


def edge(graph, v1,v2):
    return graph.addEdge(v1, v2)


displayGraph()
