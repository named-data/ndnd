package nfdc

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	enc "github.com/named-data/ndnd/std/encoding"
	mgmt "github.com/named-data/ndnd/std/ndn/mgmt_2022"
	"github.com/named-data/ndnd/std/utils"
)

func (n *Nfdc) ExecCmd(mod string, cmd string, args []string, defaults []string) {
	// parse command arguments
	ctrlArgs := mgmt.ControlArgs{}

	// set default values first, then user-provided values
	for _, arg := range append(defaults, args[1:]...) {
		kv := strings.SplitN(arg, "=", 2)
		if len(kv) != 2 {
			fmt.Fprintf(os.Stderr, "Invalid argument: %s (should be key=value)\n", arg)
			return
		}

		key, val := n.preprocessArg(&ctrlArgs, mod, cmd, kv[0], kv[1])
		n.convCmdArg(&ctrlArgs, key, val)
	}

	// execute command
	raw, execErr := n.engine.ExecMgmtCmd(mod, cmd, &ctrlArgs)
	if raw == nil {
		fmt.Fprintf(os.Stderr, "Error executing command: %+v\n", execErr)
		return
	}

	// parse response
	res, ok := raw.(*mgmt.ControlResponse)
	if !ok || res == nil || res.Val == nil || res.Val.Params == nil {
		fmt.Fprintf(os.Stderr, "Invalid or empty response type: %T\n", raw)
		return
	}
	n.printCtrlResponse(res)

	if execErr != nil {
		os.Exit(1)
	}
}

func (n *Nfdc) preprocessArg(
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
				Val: &mgmt.FaceQueryFilterValue{Uri: utils.IdPtr(val)},
			}

			dataset, err := n.fetchStatusDataset(enc.Name{
				enc.NewStringComponent(enc.TypeGenericNameComponent, "faces"),
				enc.NewStringComponent(enc.TypeGenericNameComponent, "query"),
				enc.NewBytesComponent(enc.TypeGenericNameComponent, filter.Encode().Join()),
			})
			if dataset == nil {
				fmt.Fprintf(os.Stderr, "Error fetching face status dataset: %+v\n", err)
				os.Exit(1)
			}

			status, err := mgmt.ParseFaceStatusMsg(enc.NewBufferReader(dataset), true)
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
			faceArgs := mgmt.ControlArgs{Uri: utils.IdPtr(val)}
			if ctrlArgs.LocalUri != nil {
				faceArgs.LocalUri = ctrlArgs.LocalUri
				ctrlArgs.LocalUri = nil
			}
			if ctrlArgs.Mtu != nil {
				faceArgs.Mtu = ctrlArgs.Mtu
				ctrlArgs.Mtu = nil
			}
			if ctrlArgs.FacePersistency != nil {
				faceArgs.FacePersistency = ctrlArgs.FacePersistency
				ctrlArgs.FacePersistency = nil
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
			if res.Val == nil || res.Val.Params == nil || res.Val.Params.FaceId == nil {
				fmt.Fprintf(os.Stderr, "Failed to create face for route\n")
				os.Exit(1)
			}

			return key, fmt.Sprintf("%d", *res.Val.Params.FaceId)
		}
	}

	return key, val
}

func (n *Nfdc) convCmdArg(ctrlArgs *mgmt.ControlArgs, key string, val string) {
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
		ctrlArgs.FaceId = utils.IdPtr(parseUint(val))
	case "remote":
		ctrlArgs.Uri = utils.IdPtr(val)
	case "local":
		ctrlArgs.LocalUri = utils.IdPtr(val)
	case "mtu":
		ctrlArgs.Mtu = utils.IdPtr(parseUint(val))
	case "persistency":
		persistency, err := mgmt.ParsePersistency(val)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Invalid persistency: %s\n", val)
			os.Exit(9)
		}
		ctrlArgs.FacePersistency = utils.IdPtr(uint64(persistency))

	// route arguments
	case "prefix":
		ctrlArgs.Name = parseName(val)
	case "cost":
		ctrlArgs.Cost = utils.IdPtr(parseUint(val))
	case "origin":
		ctrlArgs.Origin = utils.IdPtr(parseUint(val))
	case "expires":
		ctrlArgs.ExpirationPeriod = utils.IdPtr(parseUint(val))

	// strategy arguments
	case "strategy":
		ctrlArgs.Strategy = &mgmt.Strategy{Name: parseName(val)}

	// unknown argument
	default:
		fmt.Fprintf(os.Stderr, "Unknown command argument key: %s\n", key)
		os.Exit(9)
	}
}

func (n *Nfdc) printCtrlResponse(res *mgmt.ControlResponse) {
	// print status code and text
	fmt.Printf("Status=%d (%s)\n", res.Val.StatusCode, res.Val.StatusText)

	// iterate over parameters in sorted order
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
