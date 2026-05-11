package dvc

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/named-data/ndnd/std/ndn"
	mgmt "github.com/named-data/ndnd/std/ndn/mgmt_2022"
	sig "github.com/named-data/ndnd/std/security/signer"
	"github.com/named-data/ndnd/std/types/optional"
	"github.com/named-data/ndnd/std/utils"
	"github.com/spf13/cobra"
)

// ExecPrefixCmd executes a prefix management command against the DV prefix state.
func (t *Tool) ExecPrefixCmd(_ *cobra.Command, cmd string, args []string, defaults []string) {
	t.Start()
	defer t.Stop()

	ctrlArgs := mgmt.ControlArgs{}

	for _, arg := range append(defaults, args...) {
		kv := strings.SplitN(arg, "=", 2)
		if len(kv) != 2 {
			fmt.Fprintf(os.Stderr, "Invalid argument: %s (should be key=value)\n", arg)
			os.Exit(9)
			return
		}

		key, val := t.preprocessPetArg(kv[0], kv[1])

		switch cmd {
		case "announce":
			switch key {
			case "expires":
				expires, err := strconv.ParseUint(val, 10, 64)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Invalid value for expires: %s\n", val)
					os.Exit(9)
					return
				}
				if expires == 0 {
					fmt.Fprintln(os.Stderr, "prefix-announce expires must be > 0 when provided")
					os.Exit(9)
					return
				}
				ctrlArgs.ExpirationPeriod = optional.Some(expires)
				continue
			}
		case "withdraw":
			// face/cost are handled by convPetArg
		}

		if key == "expires" {
			fmt.Fprintf(os.Stderr, "%s does not accept expires\n", cmd)
			os.Exit(9)
			return
		}

		t.convPetArg(&ctrlArgs, key, val)
	}

	res, err := mgmt.ExecServiceCmd(
		t.engine,
		true,
		"dv",
		"prefix",
		cmd,
		&ctrlArgs,
		&ndn.InterestConfig{
			Lifetime:    optional.Some(1 * time.Second),
			Nonce:       utils.ConvertNonce(t.engine.Timer().Nonce()),
			MustBeFresh: true,
			SigNonce:    t.engine.Timer().Nonce(),
			SigTime:     optional.Some(time.Duration(t.engine.Timer().Now().UnixMilli()) * time.Millisecond),
		},
		sig.NewSha256Signer(),
		nil,
	)
	if res == nil {
		fmt.Fprintf(os.Stderr, "Error executing command: %+v\n", err)
		os.Exit(1)
		return
	}

	t.printCtrlResponse(res)
	if err != nil {
		os.Exit(1)
	}
}
