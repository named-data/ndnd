package mgmt_2022

import (
	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/ndn"
)

type MgmtConfig struct {
	// local means whether NFD is of localhost
	local bool
	// signer is the signer used to sign the command
	signer ndn.Signer
	// spec is the NDN spec used to make Interests
	spec ndn.Spec
}

// MakeCmd makes and encodes a NFD mgmt command Interest.
// Currently NFD and YaNFD supports signed Interest.
func (mgmt *MgmtConfig) MakeCmd(module string, cmd string,
	args *ControlArgs, config *ndn.InterestConfig) (*ndn.EncodedInterest, error) {

	params := ControlParameters{Val: args}

	var name enc.Name
	if mgmt.local {
		name = enc.Name{enc.LOCALHOST}
	} else {
		name = enc.Name{enc.LOCALHOP}
	}

	name = append(name,
		enc.NewGenericComponent("nfd"),
		enc.NewGenericComponent(module),
		enc.NewGenericComponent(cmd),
		enc.NewGenericBytesComponent(params.Bytes()),
	)

	// Make and sign Interest
	return mgmt.spec.MakeInterest(name, config, enc.Wire{}, mgmt.signer)
}

// MakeCmdDict is the same as MakeCmd but receives a map[string]any as arguments.
func (mgmt *MgmtConfig) MakeCmdDict(module string, cmd string, args map[string]any,
	config *ndn.InterestConfig) (*ndn.EncodedInterest, error) {
	// Parse arguments
	vv, err := DictToControlArgs(args)
	if err != nil {
		return nil, err
	}
	return mgmt.MakeCmd(module, cmd, vv, config)
}

// (AI GENERATED DESCRIPTION): Sets the Signer used by MgmtConfig for signing management packets.
func (mgmt *MgmtConfig) SetSigner(signer ndn.Signer) {
	mgmt.signer = signer
}

// (AI GENERATED DESCRIPTION): Creates a new MgmtConfig with the given local flag, signer, and spec, returning nil if either signer or spec is nil.
func NewConfig(local bool, signer ndn.Signer, spec ndn.Spec) *MgmtConfig {
	if signer == nil || spec == nil {
		return nil
	}
	return &MgmtConfig{
		local:  local,
		signer: signer,
		spec:   spec,
	}
}
