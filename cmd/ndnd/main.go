package main

import (
	"os"

	dv "github.com/named-data/ndnd/dv/executor"
	fw "github.com/named-data/ndnd/fw/executor"
	"github.com/named-data/ndnd/std/utils"
	tools "github.com/named-data/ndnd/tools"
	dvc "github.com/named-data/ndnd/tools/dvc"
	nfdc "github.com/named-data/ndnd/tools/nfdc"
)

func main() {
	// subtrees from other packages
	nfdcTree := nfdc.GetNfdcCmdTree()

	// create a command tree
	tree := utils.CmdTree{
		Name: "ndnd",
		Help: "Named Data Networking Daemon",
		Sub: []*utils.CmdTree{{
			Name: "fw",
			Help: "NDN Forwarding Daemon",
			Sub: append([]*utils.CmdTree{{
				Name: "run",
				Help: "Start the NDN Forwarding Daemon",
				Fun:  fw.Main,
			}, {},
			}, nfdcTree.Sub...),
		}, {
			Name: "dv",
			Help: "NDN Distance Vector Routing Daemon",
			Sub: []*utils.CmdTree{{
				Name: "run",
				Help: "Start the NDN Distance Vector Routing Daemon",
				Fun:  dv.Main,
			}, {}, {
				Name: "link create",
				Help: "Create a new active neighbor link",
				Fun:  dvc.RunDvLinkCreate(&nfdcTree),
			}, {
				Name: "link destroy",
				Help: "Destroy an active neighbor link",
				Fun:  dvc.RunDvLinkDestroy(&nfdcTree),
			}},
		}, {
			// tools separator
		}, {
			Name: "ping",
			Help: "Send Interests to an NDN ping server",
			Fun:  tools.RunPingClient,
		}, {
			Name: "pingserver",
			Help: "Start an NDN ping server under a prefix",
			Fun:  tools.RunPingServer,
		}, {
			Name: "cat",
			Help: "Retrieve data under a prefix",
			Fun:  tools.RunCatChunks,
		}, {
			Name: "put",
			Help: "Publish data under a prefix",
			Fun:  tools.RunPutChunks,
		}},
	}

	// Parse the command line arguments
	args := os.Args
	args[0] = tree.Name
	tree.Execute(args)
}
