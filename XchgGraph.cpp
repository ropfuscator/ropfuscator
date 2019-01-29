#include "XchgGraph.h"
#include <iostream>
#include <limits.h>
#include <list>

using namespace std;

void XchgGraph::addEdge(int Op0, int Op1) {
  adj[Op0].push_back(Op1);
  adj[Op1].push_back(Op0);
}

bool XchgGraph::BFS(int src, int dest, int pred[], int dist[]) {
  list<int> queue;
  bool visited[REGS];

  for (int i = 0; i < REGS; i++) {
    visited[i] = false;
    dist[i] = INT_MAX;
    pred[i] = -1;
  }

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

        if (adj[u][i] == dest)
          return true;
      }
    }
  }

  return false;
}

void XchgGraph::generateCode(int s, int dest) {
  int pred[REGS], dist[REGS];

  if (BFS(s, dest, pred, dist) == false) {
    cout << "Given source and destination"
         << " are not connected";
    return;
  }

  vector<int> path;
  int crawl = dest;
  path.push_back(crawl);
  while (pred[crawl] != -1) {
    path.push_back(pred[crawl]);
    crawl = pred[crawl];
  }

  cout << "Shortest path length is : " << dist[dest];

  cout << "\nPath is::\n";
  for (int i = path.size() - 1; i >= 0; i--)

    if (i > 0)
      cout << "xchg " << path[i] << " " << path[i - 1] << "\n";
}

bool XchgGraph::areExchangeable(int Op0, int Op1) {
  int pred[REGS], dist[REGS];

  return BFS(Op0, Op1, pred, dist);
}
