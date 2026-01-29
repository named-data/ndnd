package nfdc

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	enc "github.com/named-data/ndnd/std/encoding"
	mgmt "github.com/named-data/ndnd/std/ndn/mgmt_2022"
	"github.com/named-data/ndnd/std/types/optional"
	"github.com/spf13/cobra"
)

// (AI GENERATED DESCRIPTION): Executes a specified management command on the engine, applying default and user‑supplied arguments (after preprocessing), invoking the command, and printing the resulting control response.
func (t *Tool) ExecCmd(_ *cobra.Command, mod string, cmd string, args []string, defaults []string) {
	t.Start()
	defer t.Stop()

	// parse command arguments
	ctrlArgs := mgmt.ControlArgs{}

	// set default values first, then user-provided values
	for _, arg := range append(defaults, args...) {
		kv := strings.SplitN(arg, "=", 2)
		if len(kv) != 2 {
			fmt.Fprintf(os.Stderr, "Invalid argument: %s (should be key=value)\n", arg)
			os.Exit(9)
			return
		}

		key, val := t.preprocessArg(&ctrlArgs, mod, cmd, kv[0], kv[1])
		t.convCmdArg(&ctrlArgs, key, val)
	}

	// execute command
	raw, execErr := t.engine.ExecMgmtCmd(mod, cmd, &ctrlArgs)
	if raw == nil {
		fmt.Fprintf(os.Stderr, "Error executing command: %+v\n", execErr)
		os.Exit(1)
		return
	}

	// parse response
	res, ok := raw.(*mgmt.ControlResponse)
	if !ok || res == nil || res.Val == nil || res.Val.Params == nil {
		fmt.Fprintf(os.Stderr, "Invalid or empty response type: %T\n", raw)
		os.Exit(1)
		return
	}
	t.printCtrlResponse(res)

	if execErr != nil {
		os.Exit(1)
	}
}

// (AI GENERATED DESCRIPTION): Converts a face URI argument into its numeric face ID, querying existing faces or creating a new one as needed for the faces/destroy, rib/unregister, and rib/register management commands.
func (n *Tool) preprocessArg(
	ctrlArgs *mgmt.ControlArgs,
	mod string, cmd string,
	key string, val string,
) (string, string) {
	// convert face from URI to face ID
	if key == "face" && strings.Contains(val, "://") {
		// query the existing face (without attempting to create a new one)
		// for faces/create, we require specifying "remote" and/or "local" instead
		if (mod == "faces" && cmd == "destroy") ||
			(mod == "rib" && cmd == "unregister") {

			filter := mgmt.FaceQueryFilter{
				Val: &mgmt.FaceQueryFilterValue{Uri: optional.Some(val)},
			}

			dataset, err := n.fetchStatusDataset(enc.Name{
				enc.NewGenericComponent("faces"),
				enc.NewGenericComponent("query"),
				enc.NewGenericBytesComponent(filter.Encode().Join()),
			})
			if dataset == nil {
				fmt.Fprintf(os.Stderr, "Error fetching face status dataset: %+v\n", err)
				os.Exit(1)
			}

			status, err := mgmt.ParseFaceStatusMsg(enc.NewWireView(dataset), true)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error parsing face status: %+v\n", err)
				os.Exit(1)
			}

			// face needs to exist, otherwise no point in continuing
			if len(status.Vals) == 0 {
				fmt.Fprintf(os.Stderr, "Face not found for URI: %s\n", val)
				os.Exit(9)
			} else if len(status.Vals) > 1 {
				fmt.Fprintf(os.Stderr, "Multiple faces found for URI: %s\n", val)
				os.Exit(9)
			}

			// found the face we need
			return key, fmt.Sprintf("%d", status.Vals[0].FaceId)
		}

		// only for rib/register, create a new face if it doesn't exist
		if mod == "rib" && cmd == "register" {
			// copy over any face arguments that are already set
			faceArgs := mgmt.ControlArgs{Uri: optional.Some(val)}
			if ctrlArgs.LocalUri.IsSet() {
				faceArgs.LocalUri = ctrlArgs.LocalUri
				ctrlArgs.LocalUri.Unset()
			}
			if ctrlArgs.Mtu.IsSet() {
				faceArgs.Mtu = ctrlArgs.Mtu
				ctrlArgs.Mtu.Unset()
			}
			if ctrlArgs.FacePersistency.IsSet() {
				faceArgs.FacePersistency = ctrlArgs.FacePersistency
				ctrlArgs.FacePersistency.Unset()
			}

			// create or use existing face
			raw, execErr := n.engine.ExecMgmtCmd("faces", "create", &faceArgs)
			if raw == nil {
				fmt.Fprintf(os.Stderr, "Error creating face: %+v\n", execErr)
				os.Exit(1)
			}

			res, ok := raw.(*mgmt.ControlResponse)
			if !ok {
				fmt.Fprintf(os.Stderr, "Invalid or empty response type: %T\n", raw)
				os.Exit(1)
			}
			n.printCtrlResponse(res)
			if res.Val == nil || res.Val.Params == nil || !res.Val.Params.FaceId.IsSet() {
				fmt.Fprintf(os.Stderr, "Failed to create face for route\n")
				os.Exit(1)
			}

			return key, fmt.Sprintf("%d", res.Val.Params.FaceId.Unwrap())
		}
	}

	return key, val
}

// (AI GENERATED DESCRIPTION): Converts a key/value pair from a command into the appropriate field of a ControlArgs struct, parsing numeric and name values, validating persistency and strategy options, and setting optional fields for face, route, and strategy arguments.
func (n *Tool) convCmdArg(ctrlArgs *mgmt.ControlArgs, key string, val string) {
	// helper function to parse uint64 values
	parseUint := func(val string) uint64 {
		v, err := strconv.ParseUint(val, 10, 64)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Invalid value for %s: %s\n", key, val)
			os.Exit(9)
		}
		return v
	}

	// helper function to parse name values
	parseName := func(val string) enc.Name {
		name, err := enc.NameFromStr(val)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Invalid name for %s: %s\n", key, val)
			os.Exit(9)
		}
		return name
	}

	// convert key-value pairs to command arguments
	switch key {
	// face arguments
	case "face":
		ctrlArgs.FaceId = optional.Some(parseUint(val))
	case "remote":
		ctrlArgs.Uri = optional.Some(val)
	case "local":
		ctrlArgs.LocalUri = optional.Some(val)
	case "mtu":
		ctrlArgs.Mtu = optional.Some(parseUint(val))
	case "persistency":
		persistency, err := mgmt.ParsePersistency(val)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Invalid persistency: %s\n", val)
			os.Exit(9)
		}
		ctrlArgs.FacePersistency = optional.Some(uint64(persistency))

	// route arguments
	case "prefix":
		ctrlArgs.Name = parseName(val)
	case "cost":
		ctrlArgs.Cost = optional.Some(parseUint(val))
	case "origin":
		ctrlArgs.Origin = optional.Some(parseUint(val))
	case "expires":
		ctrlArgs.ExpirationPeriod = optional.Some(parseUint(val))

	// strategy arguments
	case "strategy":
		ctrlArgs.Strategy = &mgmt.Strategy{Name: parseName(val)}

	// unknown argument
	default:
		fmt.Fprintf(os.Stderr, "Unknown command argument key: %s\n", key)
		os.Exit(9)
	}
}

// (AI GENERATED DESCRIPTION): Prints a control response’s status code and text, then lists its parameters in sorted order, converting selected values to human‑readable strings before output.
func (n *Tool) printCtrlResponse(res *mgmt.ControlResponse) {
	// print status code and text
	fmt.Printf("Status=%d (%s)\n", res.Val.StatusCode, res.Val.StatusText)

	// iterate over parameters in sorted order
	if res.Val.Params == nil {
		return
	}
	params := res.Val.Params.ToDict()
	keys := make([]string, 0, len(params))
	for key := range params {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	// print parameters
	for _, key := range keys {
		val := params[key]

		// convert some values to human-readable form
		switch key {
		case "FacePersistency":
			val = mgmt.Persistency(val.(uint64)).String()
		case "Origin":
			val = mgmt.RouteOrigin(val.(uint64)).String()
		}

		fmt.Printf("  %s=%v\n", key, val)
	}
}
