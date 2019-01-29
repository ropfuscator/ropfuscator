// ==============================================================================
//   XCHG GRAPH
//   part of the ROPfuscator project
// ==============================================================================
// This module parses all the XCHG microgadgets found by Binary Autopsy,
// building a graph basing on their operands.
// In this graph, registers are the nodes, while each XCHG gadget is represented
// by an edge between the involved registers.
//
// Once the graph has been built, it is possible to tell whether the content of
// two registers can be exchanged: in this case we say that they belong to the
// same "exchange path".
// Obtaining this kind of information is crucial to extend the scope of our
// gadgets. For instance, if we have a gadget like "mov eax, esi" and we figure
// out that the "esi" register is exchangable with "ebx", the following semantic
// equivalence is verified:
//
//                                   xchg esi, ebx
//          mov eax, ebx  < === >    mov eax, esi
//                                   xchg esi, ebx
//

#ifndef XCHGGRAPH_H
#define XCHGGRAPH_H

#include <vector>

#define REGS 100

class XchgGraph {
public:
  std::vector<int> adj[REGS];

  void addEdge(int Op0, int Op1);
  bool BFS(int src, int dest, int pred[], int dist[]);
  void generateCode(int s, int dest);
  bool areExchangeable();
};

#endif
