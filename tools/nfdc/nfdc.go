package nfdc

import (
	"fmt"
	"os"

	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/engine"
	"github.com/named-data/ndnd/std/ndn"
	"github.com/named-data/ndnd/std/utils"
)

func GetNfdcCmdTree() utils.CmdTree {
	nfdc := &Nfdc{}
	cmd := func(mod string, cmd string, defaults []string) func([]string) {
		return func(args []string) {
			nfdc.ExecCmd(mod, cmd, args, defaults)
		}
	}
	start := func(fun func([]string)) func([]string) {
		return func(args []string) {
			nfdc.Start()
			defer nfdc.Stop()
			fun(args)
		}
	}

	return utils.CmdTree{
		Name: "nfdc",
		Help: "NDNd Forwarder Control",
		Sub: []*utils.CmdTree{{
			Name: "status",
			Help: "Print general status",
			Fun:  start(nfdc.ExecStatusGeneral),
		}, {
			Name: "face list",
			Help: "Print face table",
			Fun:  start(nfdc.ExecFaceList),
		}, {
			Name: "face create",
			Help: "Create a face",
			Fun: start(cmd("faces", "create", []string{
				"persistency=persistent",
			})),
		}, {
			Name: "face destroy",
			Help: "Destroy a face",
			Fun:  start(cmd("faces", "destroy", []string{})),
		}, {
			Name: "route list",
			Help: "Print RIB routes",
			Fun:  start(nfdc.ExecRouteList),
		}, {
			Name: "route add",
			Help: "Add a route to the RIB",
			Fun: start(cmd("rib", "register", []string{
				"cost=0", "origin=255",
			})),
		}, {
			Name: "route remove",
			Help: "Remove a route from the RIB",
			Fun: start(cmd("rib", "unregister", []string{
				"origin=255",
			})),
		}, {
			Name: "fib list",
			Help: "Print FIB entries",
			Fun:  start(nfdc.ExecFibList),
		}, {
			Name: "cs info",
			Help: "Print content store info",
			Fun:  start(nfdc.ExecCsInfo),
		}, {
			Name: "strategy list",
			Help: "Print strategy choices",
			Fun:  start(nfdc.ExecStrategyList),
		}, {
			Name: "strategy set",
			Help: "Set strategy choice",
			Fun:  start(cmd("strategy-choice", "set", []string{})),
		}, {
			Name: "strategy unset",
			Help: "Unset strategy choice",
			Fun:  start(cmd("strategy-choice", "unset", []string{})),
		}},
	}
}

type Nfdc struct {
	engine        ndn.Engine
	statusPadding int
}

func (n *Nfdc) Start() {
	n.engine = engine.NewBasicEngine(engine.NewDefaultFace())

	err := n.engine.Start()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to start engine: %+v\n", err)
		return
	}
}

func (n *Nfdc) Stop() {
	n.engine.Stop()
}

func (n *Nfdc) GetPrefix() enc.Name {
	return enc.Name{
		enc.LOCALHOST,
		enc.NewStringComponent(enc.TypeGenericNameComponent, "nfd"),
	}
}
