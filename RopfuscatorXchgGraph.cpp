#include "RopfuscatorXchgGraph.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/raw_ostream.h"
#include <limits.h>
#include <list>

using namespace std;

void XchgGraph::addEdge(int Op0, int Op1) {
  adj[Op0].push_back(Op1);
  adj[Op1].push_back(Op0);
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

vector<pair<int, int>> XchgGraph::getPath(int src, int dest, bool inv) {
  //
  int real_src = inv ? src : node_content[src];
  int real_dest = inv ? dest : node_content[dest];

  if (real_src != src)
    llvm::dbgs() << "[XchgGraph]\tsrc:" << src << " is in " << real_src
                 << "!\n";
  if (real_dest != dest)
    llvm::dbgs() << "[XchgGraph]\tdest:" << dest << "is in " << real_dest
                 << "!\n";

  vector<pair<int, int>> exchangePath;
  vector<int> path;
  int pred[N_REGS], dist[N_REGS], crawl;
  bool visited[N_REGS];

  assert(checkPath(real_src, real_dest, pred, dist, visited) &&
         "Src and dest operand are not connected. Use checkPath() first.");

  crawl = dest;
  path.push_back(crawl);

  while (pred[crawl] != -1) {
    path.push_back(pred[crawl]);
    crawl = pred[crawl];
  }

  for (int i = path.size() - 1, j = path.size() - 2; j >= 0; i--, j--) {
    exchangePath.emplace_back(make_pair(path[i], path[j]));
  }

  int tmp = node_content[real_src];
  // exchange in the internal representation
  node_content[real_src] = inv ? node_content[dest] : dest;
  llvm::dbgs() << "[XchgGraph]\t"
               << "committing xchg: node_content[" << real_src << "] = " << dest
               << "!\n";
  node_content[real_dest] = inv ? tmp : src;
  llvm::dbgs() << "[XchgGraph]\t"
               << "committing xchg: node_content[" << real_dest << "] = " << src
               << "!\n";

  for (int i = 19; i < 30; i++) {
    llvm::dbgs() << "node_content[" << i << "] = " << node_content[i] << "\n";
  }
  return exchangePath;
}
