#include "XchgGraph.h"
#include "Debug.h"
#include <limits.h>
#include <list>

using namespace std;

XchgGraph::XchgGraph() {
  // sets up each logical register in the proper physical register.
  for (int i = 0; i < N_REGS; i++) {
    PhysReg[i] = i;
  }
}

void XchgGraph::addEdge(int reg1, int reg2) {
  adj[reg1].push_back(reg2);
  adj[reg2].push_back(reg1);
}

bool XchgGraph::checkPath(int src, int dest, int pred[], int dist[],
                          bool visited[]) {
  list<int> queue;

  for (int i = 0; i < N_REGS; i++) {
    visited[i] = false;
    dist[i] = INT_MAX;
    pred[i] = -1;
  }

  if (src == dest)
    return true;

  visited[src] = true;
  dist[src] = 0;
  queue.push_back(src);

  while (!queue.empty()) {
    int u = queue.front();

    queue.pop_front();

    for (unsigned int i = 0; i < adj[u].size(); i++) {
      if (!visited[adj[u][i]]) {
        visited[adj[u][i]] = true;
        dist[adj[u][i]] = dist[u] + 1;
        pred[adj[u][i]] = u;
        queue.push_back(adj[u][i]);

        if (adj[u][i] == dest)
          return true;
      }
    }
  }

  return false;
}

XchgPath XchgGraph::getPath(int src, int dest) {

  XchgPath result;
  vector<int> path;
  int pred[N_REGS], dist[N_REGS], crawl;
  bool visited[N_REGS];

  // llvm::dbgs() << "[getPath] Trying to exchange " << src << " with " << dest
  //              << "\n";
  // src = searchLogicalReg(src);
  // dest = searchLogicalReg(dest);
  // llvm::dbgs() << "[getPath] Exchanging " << src << " with " << dest
  //              << " instead!\n";

  if (!checkPath(src, dest, pred, dist, visited))
    return result;

  crawl = dest;
  path.push_back(crawl);
  while (pred[crawl] != -1) {
    path.push_back(pred[crawl]);
    crawl = pred[crawl];
  }
  for (int i = path.size() - 1, j = path.size() - 2; j >= 0; i--, j--) {
    result.emplace_back(make_pair(path[i], path[j]));
  }

  // update the internal state
  short int tmp = PhysReg[src];
  PhysReg[src] = PhysReg[dest];
  PhysReg[dest] = tmp;

  return fixPath(result);
}

int XchgGraph::searchLogicalReg(int LReg, int PReg) {
  // llvm::dbgs() << "** Searching [" << LReg << "] -> " << PReg << "\n";
  if (PhysReg[LReg] == PReg)
    return LReg;
  return searchLogicalReg(PhysReg[LReg], PReg);
}

int XchgGraph::searchLogicalReg(int LReg) {
  return searchLogicalReg(LReg, LReg);
  // return PhysReg[LReg];
}

XchgPath XchgGraph::fixPath(XchgPath path) {
  XchgPath result;
  result.insert(result.begin(), path.begin(), path.end());
  if (path.size() > 1)
    result.insert(result.end(), path.rbegin() + 1, path.rend());
  llvm::dbgs() << "---> xchgStack contains " << xchgStack.size()
               << " elements!\n";
  xchgStack.insert(xchgStack.end(), result.begin(), result.end());
  llvm::dbgs() << "---> xchgStack filled with " << xchgStack.size()
               << " elements!\n";
  return result;
}

XchgPath XchgGraph::reorderRegisters() {
  XchgPath result;
  result.insert(result.end(), xchgStack.rbegin(), xchgStack.rend()); //, tmp;

  llvm::dbgs() << "---> xchgStack cleared (" << xchgStack.size()
               << " elements)\n";
  DEBUG_WITH_TYPE(XCHG_CHAIN, llvm::dbgs() << "Exchanging back...\n");

  for (int i = 0; i < N_REGS; i++) {
    if (PhysReg[i] != i) {
      // // finds the real location of the two registers
      // src = searchLogicalReg(src, src);
      // dest = searchLogicalReg(dest, dest);

      short int PReg = searchLogicalReg(i, i);
      DEBUG_WITH_TYPE(XCHG_CHAIN, llvm::dbgs()
                                      << "Xchanging logical register " << i
                                      << " with " << PReg << " !\n");
      getPath(PReg, i);
      // result.insert(result.end(), tmp.begin(), tmp.end());
      // printAll();
    }
  }
  xchgStack.clear();

  return result;
}

void XchgGraph::printAll() {
  for (int i = 19; i < 30; i++) {

    llvm::dbgs() << "\t[" << i << "]: " << PhysReg[i] << "\n";
  }
}

short int *XchgGraph::bindLogicalReg(int LReg) { return &PhysReg[LReg]; }