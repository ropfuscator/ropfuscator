#include "XchgGraph.h"
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

  for (int i = 0; i < REGS; i++) {
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
      if (visited[adj[u][i]] == false) {
        visited[adj[u][i]] = true;
        dist[adj[u][i]] = dist[u] + 1;
        pred[adj[u][i]] = u;
        queue.push_back(adj[u][i]);

        if (adj[u][i] == dest) {

          return true;
        }
      }
    }
  }

  return false;
}

vector<pair<int, int>> XchgGraph::getPath(int src, int dest) {
  vector<pair<int, int>> exchangePath;

  int pred[REGS], dist[REGS];
  bool visited[REGS];

  assert(checkPath(src, dest, pred, dist, visited) &&
         "Src and dest operand are not connected. Use checkPath() first.");

  vector<int> path;
  int crawl = dest;
  path.push_back(crawl);
  while (pred[crawl] != -1) {
    path.push_back(pred[crawl]);
    crawl = pred[crawl];
  }

  for (int i = path.size() - 1, j = path.size() - 2; j >= 0; i--, j--) {
    exchangePath.emplace_back(make_pair(path[i], path[j]));
  }

  return exchangePath;
}
