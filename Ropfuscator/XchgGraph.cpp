#include "XchgGraph.h"
#include "Debug.h"
#include <limits.h>
#include <list>
#include <algorithm>

using namespace std;

XchgState::XchgState() {
  // sets up each logical register in the proper physical register.
  for (int i = 0; i < N_REGS; i++) {
    PhysReg[i] = i;
  }
}

void XchgState::exchange(int reg1, int reg2) {
  std::swap(PhysReg[reg1], PhysReg[reg2]);
}

void XchgGraph::addEdge(int reg1, int reg2) {
  adj[reg1].push_back(reg2);
  adj[reg2].push_back(reg1);
}

bool XchgGraph::checkPath(int src, int dest, int pred[], int dist[],
                          bool visited[]) const {
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

XchgPath XchgGraph::getPath(XchgState &state, int src, int dest) const {

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
  state.exchange(src, dest);

  return fixPath(state, result);
}

int XchgState::searchLogicalReg(int LReg, int PReg) const {
  // llvm::dbgs() << "** Searching [" << LReg << "] -> " << PReg << "\n";
  int r;
  for (r = LReg; PhysReg[r] != PReg; r = PhysReg[r])
    ;
  return r;
}

int XchgState::searchLogicalReg(int LReg) const {
  return searchLogicalReg(LReg, LReg);
}

XchgPath XchgGraph::fixPath(XchgState &state, XchgPath path) const {
  XchgPath result;

  result.insert(result.begin(), path.begin(), path.end());
  if (path.size() > 1)
    result.insert(result.end(), path.rbegin() + 1, path.rend());

  state.xchgStack.insert(state.xchgStack.end(), result.begin(), result.end());
  return result;
}

XchgPath XchgGraph::reorderRegisters(XchgState &state) const {
  XchgPath result;
  result.insert(result.end(), state.xchgStack.rbegin(), state.xchgStack.rend()); //, tmp;

  DEBUG_WITH_TYPE(XCHG_CHAIN, llvm::dbgs() << "Exchanging back...\n");

  for (int i = 0; i < N_REGS; i++) {
    if (state.PhysReg[i] != i) {
      // // finds the real location of the two registers
      // src = searchLogicalReg(src, src);
      // dest = searchLogicalReg(dest, dest);

      short int PReg = state.searchLogicalReg(i, i);
      DEBUG_WITH_TYPE(XCHG_CHAIN, llvm::dbgs()
                                      << "Xchanging logical register " << i
                                      << " with " << PReg << " !\n");
      getPath(state, PReg, i);
      // result.insert(result.end(), tmp.begin(), tmp.end());
      // printAll();
    }
  }
  state.xchgStack.clear();

  return result;
}

void XchgState::printAll() const {
  for (int i = 19; i < 30; i++) {

    llvm::dbgs() << "\t[" << i << "]: " << PhysReg[i] << "\n";
  }
}
