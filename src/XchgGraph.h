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

namespace ropf {

#define N_REGS 100

typedef std::vector<std::pair<int, int>> XchgPath;

class XchgState {
  XchgPath xchgStack;

  // PhysReg - maps the location logical registers to physical registers.
  // E.g.: if PhysReg[X86_REG_EAX] = X86_REG_EDX, it means that, due to an
  // exchange, the logical register EAX is held in the physical register EDX.
  short int PhysReg[N_REGS];

  friend class XchgGraph;

public:
  // constructor
  XchgState();

  // searchLogicalReg - performs a recursive search to find the physical
  // register that holds the given logical register.
  int searchLogicalReg(int LogReg, int PhysReg) const;

  int searchLogicalReg(int LReg) const;

  void exchange(int reg1, int reg2);

  void printAll() const;
};

class XchgGraph {
  // adj[] - adjacency list
  std::vector<int> adj[N_REGS];

  // fixPath - given a straight path between the two registers to exchange, this
  // function elaborates the full path in order to avoid having other
  // intermediate registers scrambled through the whole path.
  // E.g. if in our graph the following registers are exchangeable:
  //        EAX   <-->   ECX   <-->   EDX
  // in case we would like to exchange EAX with EDX, the straight exchange path
  // would be [(EAX, ECX), (ECX, EDX)]. However, this only brings EAX in EDX,
  // while the contrary is not true:
  //        ECX   <-->   EDX   <-->   EAX
  // Here, we must exchange ECX and EDX again, to finally obtain:
  //        EDX   <-->   ECX   <-->   EAX
  XchgPath fixPath(XchgState &state, XchgPath path) const;

public:
  // addEdge - adds a new edge between Op0 and Op1.
  void addEdge(int reg1, int reg2);

  // checkPath - Breadth First Search algorithm implementation. It simply
  // returns tells whether two nodes are mutually reachable. If the two optional
  // output parameters are given, it is possible to compute the actual path
  // (this is done by getPath()).
  bool checkPath(int src, int dest, int pred[], int dist[],
                 bool visited[]) const;

  // getPath - returns the entire path from src to dest, edge by edge. The path
  // is specified as a vector of pairs, which one of them contains source and
  // destination of each edge.
  XchgPath getPath(XchgState &state, int src, int dest) const;

  // reorderRegisters - exchanges back all the logical registers, so that each
  // of them is in the correct physical register (e.g., PhysReg[X86_REG_EAX] =
  // X86_REG_EAX). Returns the proper exchange path.
  XchgPath reorderRegisters(XchgState &state) const;
};

} // namespace ropf

#endif
