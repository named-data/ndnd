package schema

// (AI GENERATED DESCRIPTION): Initializes the node and policy registries by creating the maps and populating them with base node, express point, leaf node, and policy descriptors.
func init() {
	NodeRegister = make(map[string]*NodeImplDesc)
	PolicyRegister = make(map[string]*PolicyImplDesc)
	initBaseNodeImplDesc()
	initExpressPointDesc()
	initLeafNodeDesc()
	initPolicies()
}
