package dvc

import (
	"fmt"
	"os"

	"github.com/named-data/ndnd/std/engine"
	"github.com/named-data/ndnd/std/ndn"
	"github.com/spf13/cobra"
)

// (AI GENERATED DESCRIPTION): Builds and returns the Cobra command set for querying router status, creating a new active neighbor link, and destroying an existing neighbor link.
func Cmds() []*cobra.Command {
	t := Tool{}

	return []*cobra.Command{{
		Use:   "status",
		Short: "Print general status of the router",
		Args:  cobra.NoArgs,
		Run:   t.RunDvStatus,
	}, {
		Use:   "link-create NEIGHBOR-URI",
		Short: "Create a new active neighbor link",
		Args:  cobra.ExactArgs(1),
		Run:   t.RunDvLinkCreate,
	}, {
		Use:   "link-destroy NEIGHBOR-URI",
		Short: "Destroy an active neighbor link",
		Args:  cobra.ExactArgs(1),
		Run:   t.RunDvLinkDestroy,
	}}
}

type Tool struct {
	engine ndn.Engine
}

// (AI GENERATED DESCRIPTION): Initializes the Tool’s engine with a default face and starts it, terminating the program if the engine fails to start.
func (t *Tool) Start() {
	t.engine = engine.NewBasicEngine(engine.NewDefaultFace())

	err := t.engine.Start()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to start engine: %+v\n", err)
		os.Exit(1)
		return
	}
}

// (AI GENERATED DESCRIPTION): Stops the Tool’s engine, terminating its operation.
func (t *Tool) Stop() {
	t.engine.Stop()
}
