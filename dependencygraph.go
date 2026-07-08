package strangelove

const SyntheticRootID = "@root"

func newDependencyGraph(components []Component) *DependencyGraph {
	nodes := make(map[string]*Node, len(components))
	for i := range components {
		c := &components[i]
		nodes[c.ID] = &Node{
			ID:         c.ID,
			Component:  c,
			DependsOn:  make(map[string]*Node),
			DependedBy: make(map[string]*Node),
		}
	}
	return &DependencyGraph{Nodes: nodes}
}

func (g *DependencyGraph) addEdge(fromID, toID string) {
	g.node(fromID).DependsOn[toID] = g.node(toID)
	g.node(toID).DependedBy[fromID] = g.node(fromID)
}

func (g *DependencyGraph) node(id string) *Node {
	n, ok := g.Nodes[id]
	if !ok {
		n = &Node{
			ID:         id,
			DependsOn:  make(map[string]*Node),
			DependedBy: make(map[string]*Node),
		}
		g.Nodes[id] = n
	}
	return n
}

func (g *DependencyGraph) ensureRoot(rootID string) {
	if rootID == "" {
		rootID = SyntheticRootID
	}
	g.Root = rootID
	g.node(rootID)

	for id, n := range g.Nodes {
		if id == rootID {
			continue
		}
		if len(n.DependedBy) == 0 {
			g.addEdge(rootID, id)
		}
	}
}
