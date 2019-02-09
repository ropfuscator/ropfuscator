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
// NOTE: XchgGraph only handles the graph data structure and fills it with
// register IDs, without knowing any abstraction about gadgets.
// BinAutopsy is in charge of taking the graph data and find the actual xchg
// gadgets to fulfill our needs.

#ifndef XCHGGRAPH_H
#define XCHGGRAPH_H

#include <utility>
#include <vector>

#define REGS 100

class XchgGraph {
  // adj[] - adjacency list
  std::vector<int> adj[REGS];

public:
  // addEdge - adds a new edge between Op0 and Op1.
  void addEdge(int Op0, int Op1);

  // checkPath - Breadth First Search algorithm implementation. It simply
  // returns tells whether two nodes are mutually reachable. If the two optional
  // output parameters are given, it is possible to compute the actual path
  // (this is done by getPath()).
  bool checkPath(int src, int dest, int pred[], int dist[], bool visited[]);

  // getPath - returns the entire path from src to dest, edge by edge. The path
  // is specified as a vector of pairs, which one of them contains source and
  // destination of each edge.
  std::vector<std::pair<int, int>> getPath(int src, int dest);
};

#endif
