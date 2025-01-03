/* YaNFD - Yet another NDN Forwarding Daemon
 *
 * Copyright (C) 2020-2021 Eric Newberry.
 *
 * This file is licensed under the terms of the MIT License, as found in LICENSE.md.
 */

package mgmt

import (
	"time"

	"github.com/named-data/ndnd/fw/core"
	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/ndn"
	mgmt "github.com/named-data/ndnd/std/ndn/mgmt_2022"
	spec "github.com/named-data/ndnd/std/ndn/spec_2022"
	sec "github.com/named-data/ndnd/std/security"
	"github.com/named-data/ndnd/std/utils"
)

const (
	CsFlagEnableAdmit = 1
	CsFlagEnableServe = 2
)

func decodeControlParameters(m Module, interest ndn.Interest) *mgmt.ControlArgs {
	paramVal := interest.Name()[m.getManager().prefixLength()+2].Val
	params, err := mgmt.ParseControlParameters(enc.NewBufferReader(paramVal), true)
	if err != nil {
		core.LogWarn(m, "Could not decode ControlParameters in ", interest.Name(), ": ", err)
		return nil
	}
	return params.Val
}

func makeControlResponse(statusCode uint64, statusText string, args map[string]any) *mgmt.ControlResponse {
	if args == nil {
		args = map[string]any{}
	}
	ret, err := mgmt.DictToControlArgs(args)
	if err != nil {
		return nil
	} else {
		return &mgmt.ControlResponse{
			Val: &mgmt.ControlResponseVal{
				StatusCode: statusCode,
				StatusText: statusText,
				Params:     ret,
			},
		}
	}
}

// makeStatusDataset creates a set of status dataset packets based upon the specified prefix, version,
// and dataset information.
// Note: The old mgmt.MakeStatusDataset is clearly wrong as it is against the single-Interest-single-Data
// principle. Thus, we simply assume that the data packet should always fit in one segment.
func makeStatusDataset(name enc.Name, version uint64, dataset enc.Wire) enc.Wire {
	// Split into 8000 byte segments and publish
	if len(dataset) > 8000 {
		core.LogError("mgmt", "Status dataset is too large")
		return nil
	}
	name = append(name, enc.NewVersionComponent(version), enc.NewSegmentComponent(0))
	data, err := spec.Spec{}.MakeData(name,
		&ndn.DataConfig{
			ContentType:  utils.IdPtr(ndn.ContentTypeBlob),
			Freshness:    utils.IdPtr(time.Second),
			FinalBlockID: utils.IdPtr(enc.NewSegmentComponent(0)),
		},
		dataset,
		sec.NewSha256Signer(),
	)
	if err != nil {
		core.LogError("mgmt", "Unable to encode status dataset")
		return nil
	}
	return data.Wire
}
