package rdr

import (
	"crypto/sha256"
	"fmt"
	"time"

	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/log"
	"github.com/named-data/ndnd/std/ndn"
	rtlv "github.com/named-data/ndnd/std/ndn/rdr_2024"
	"github.com/named-data/ndnd/std/schema"
	"github.com/named-data/ndnd/std/utils"
)

// SegmentedNode handles the segmentation and reassembly
type SegmentedNode struct {
	schema.BaseNodeImpl

	ContentType         ndn.ContentType
	Freshness           time.Duration
	ValidDur            time.Duration
	Lifetime            time.Duration
	MustBeFresh         bool
	SegmentSize         uint64
	MaxRetriesOnFailure uint64
	Pipeline            string
}

func (n *SegmentedNode) NodeImplTrait() schema.NodeImpl {
	return n
}

func CreateSegmentedNode(node *schema.Node) schema.NodeImpl {
	ret := &SegmentedNode{
		BaseNodeImpl: schema.BaseNodeImpl{
			Node:        node,
			OnAttachEvt: &schema.EventTarget{},
			OnDetachEvt: &schema.EventTarget{},
		},
		ContentType:         ndn.ContentTypeBlob,
		MustBeFresh:         true,
		Lifetime:            4 * time.Second,
		ValidDur:            876000 * time.Hour,
		Freshness:           10 * time.Second,
		SegmentSize:         8000,
		MaxRetriesOnFailure: 15,
		Pipeline:            "SinglePacket",
	}
	path, _ := enc.NamePatternFromStr("<seg=segmentNumber>")
	node.PutNode(path, schema.LeafNodeDesc)
	return ret
}

func (n *SegmentedNode) String() string {
	return fmt.Sprintf("SegmentedNode (%s)", n.Node)
}

func (n *SegmentedNode) Provide(mNode schema.MatchedNode, content enc.Wire, needManifest bool) any {
	if mNode.Node != n.Node {
		panic("NTSchema tree compromised.")
	}

	var wireIdx, bufferIdx int = 0, 0
	var ret []enc.Buffer = nil
	// Segmentation
	segCnt := (content.Length() + n.SegmentSize - 1) / n.SegmentSize
	if needManifest {
		ret = make([]enc.Buffer, segCnt)
	}
	newName := make(enc.Name, len(mNode.Name)+1)
	copy(newName, mNode.Name)

	dataCfg := &ndn.DataConfig{
		ContentType:  utils.IdPtr(n.ContentType),
		Freshness:    utils.IdPtr(n.Freshness),
		FinalBlockID: utils.IdPtr(enc.NewSegmentComponent(segCnt - 1)),
	}

	for i := uint64(0); i < segCnt; i++ {
		newName[len(mNode.Name)] = enc.NewSegmentComponent(i)
		pktContent := enc.Wire{}
		remSize := n.SegmentSize
		for remSize > 0 && wireIdx < len(content) && bufferIdx < len(content[wireIdx]) {
			curSize := int(min(uint64(len(content[wireIdx])-bufferIdx), remSize))
			pktContent = append(pktContent, content[wireIdx][bufferIdx:bufferIdx+curSize])
			bufferIdx += curSize
			remSize -= uint64(curSize)
			if bufferIdx >= len(content[wireIdx]) {
				wireIdx += 1
				bufferIdx = 0
			}
		}
		// generate the data packet
		newMNode := mNode.Refine(newName)
		dataWire := newMNode.Call("Provide", pktContent, dataCfg).(enc.Wire)

		// compute implicit sha256 for manifest if needed
		if needManifest {
			h := sha256.New()
			for _, buf := range dataWire {
				h.Write(buf)
			}
			ret[i] = h.Sum(nil)
		}
	}
	log.Debug(n, "Segmented object", "segCnt", segCnt)
	if needManifest {
		return ret
	} else {
		return segCnt
	}
}

func (n *SegmentedNode) NeedCallback(
	mNode schema.MatchedNode, callback schema.Callback, manifest []enc.Buffer) error {
	if mNode.Node != n.Node {
		panic("NTSchema tree compromised.")
	}
	switch n.Pipeline {
	case "SinglePacket":
		go n.SinglePacketPipeline(mNode, callback, manifest)
		return nil
	}
	log.Error(n, "Unrecognized pipeline", "pipeline", n.Pipeline)
	return fmt.Errorf("unrecognized pipeline: %s", n.Pipeline)
}

func (n *SegmentedNode) NeedChan(mNode schema.MatchedNode, manifest []enc.Buffer) chan schema.NeedResult {
	ret := make(chan schema.NeedResult, 1)
	callback := func(event *schema.Event) any {
		result := schema.NeedResult{
			Status:      *event.NeedStatus,
			Content:     event.Content,
			Data:        event.Data,
			ValidResult: event.ValidResult,
			NackReason:  event.NackReason,
		}
		ret <- result
		close(ret)
		return nil
	}
	n.NeedCallback(mNode, callback, manifest)
	return ret
}

func (n *SegmentedNode) SinglePacketPipeline(
	mNode schema.MatchedNode, callback schema.Callback, manifest []enc.Buffer,
) {
	fragments := enc.Wire{}
	var lastData ndn.Data
	var lastNackReason *uint64
	var lastValidationRes *schema.ValidRes
	var lastNeedStatus ndn.InterestResult
	nameLen := len(mNode.Name)
	var newName enc.Name
	if len(manifest) > 0 {
		newName = make(enc.Name, nameLen+2)
	} else {
		newName = make(enc.Name, nameLen+1)
	}
	copy(newName, mNode.Name)
	succeeded := true
	for i := uint64(0); succeeded; i++ {
		newName[nameLen] = enc.NewSegmentComponent(i)
		if len(manifest) > 0 {
			newName[nameLen+1] = enc.Component{Typ: enc.TypeImplicitSha256DigestComponent, Val: manifest[i]}
		}
		newMNode := mNode.Refine(newName)
		succeeded = false
		for j := 0; !succeeded && j < int(n.MaxRetriesOnFailure); j++ {
			log.Debug(n, "Fetching packet", "trial", j, "retries")
			result := <-newMNode.Call("NeedChan").(chan schema.NeedResult)
			lastData = result.Data
			lastNackReason = result.NackReason
			lastValidationRes = result.ValidResult
			lastNeedStatus = result.Status
			switch result.Status {
			case ndn.InterestResultData:
				fragments = append(fragments, result.Content...)
				succeeded = true
			}
		}
		if len(manifest) > 0 {
			// If there is a manifest, we ignore the FinalBlockID
			if int(i) == len(manifest)-1 {
				break
			}
		} else {
			if succeeded && lastData.FinalBlockID().Compare(newName[nameLen]) == 0 {
				// In the last segment, finalBlockId equals the last name component
				break
			}
		}
	}

	event := &schema.Event{
		TargetNode:  n.Node,
		Target:      &mNode,
		Content:     fragments,
		Data:        lastData,
		NackReason:  lastNackReason,
		ValidResult: lastValidationRes,
	}
	if succeeded {
		event.NeedStatus = utils.IdPtr(ndn.InterestResultData)
	} else {
		event.NeedStatus = utils.IdPtr(lastNeedStatus)
	}
	callback(event)
}

func (n *SegmentedNode) CastTo(ptr any) any {
	switch ptr.(type) {
	case (*SegmentedNode):
		return n
	case (*schema.BaseNodeImpl):
		return &(n.BaseNodeImpl)
	default:
		return nil
	}
}

// RdrNode handles the version discovery
type RdrNode struct {
	schema.BaseNodeImpl

	MetaFreshness     time.Duration
	MaxRetriesForMeta uint64
}

func (n *RdrNode) String() string {
	return fmt.Sprintf("RdrNode (%s)", n.Node)
}

func (n *RdrNode) NodeImplTrait() schema.NodeImpl {
	return n
}

func CreateRdrNode(node *schema.Node) schema.NodeImpl {
	ret := &RdrNode{
		BaseNodeImpl: schema.BaseNodeImpl{
			Node:        node,
			OnAttachEvt: &schema.EventTarget{},
			OnDetachEvt: &schema.EventTarget{},
		},
		MetaFreshness:     10 * time.Millisecond,
		MaxRetriesForMeta: 15,
	}
	path, _ := enc.NamePatternFromStr("<v=versionNumber>")
	node.PutNode(path, SegmentedNodeDesc)
	path, _ = enc.NamePatternFromStr("32=metadata")
	node.PutNode(path, schema.ExpressPointDesc)
	path, _ = enc.NamePatternFromStr("32=metadata/<v=versionNumber>/seg=0")
	node.PutNode(path, schema.LeafNodeDesc)
	return ret
}

func (n *RdrNode) Provide(mNode schema.MatchedNode, content enc.Wire) uint64 {
	if mNode.Node != n.Node {
		panic("NTSchema tree compromised.")
	}

	// NOTE: This version of RDR node puts the metadata into storage (same as python-ndn's cmd_serve_rdrcontent).
	// It is possible to serve metadata packet in real time, but needs special handling for matching
	// There are two ways:
	// 1. Ask the storage to provide a function (via Node's event) to search with version
	// 2. Have a mapping between matching and version
	timer := mNode.Node.Engine().Timer()
	ver := utils.MakeTimestamp(timer.Now())
	nameLen := len(mNode.Name)
	metaName := make(enc.Name, nameLen+3)
	copy(metaName, mNode.Name) // Note this does not actually copies the component values
	metaName[nameLen] = enc.NewStringComponent(32, "metadata")
	metaName[nameLen+1] = enc.NewVersionComponent(ver)
	metaName[nameLen+2] = enc.NewSegmentComponent(0)
	metaMNode := mNode.Refine(metaName)

	dataName := make(enc.Name, nameLen+1)
	copy(dataName, mNode.Name)
	dataName[nameLen] = enc.NewVersionComponent(ver)
	dataMNode := mNode.Refine(dataName)

	// generate segmented data
	segCnt := dataMNode.Call("Provide", content).(uint64)

	// generate metadata
	metaDataCfg := &ndn.DataConfig{
		ContentType:  utils.IdPtr(ndn.ContentTypeBlob),
		Freshness:    utils.IdPtr(n.MetaFreshness),
		FinalBlockID: utils.IdPtr(enc.NewSegmentComponent(0)),
	}
	metaData := &rtlv.MetaData{
		Name:         dataName,
		FinalBlockID: enc.NewSegmentComponent(segCnt - 1).Bytes(),
		Size:         utils.IdPtr(content.Length()),
	}
	metaMNode.Call("Provide", metaData.Encode(), metaDataCfg)

	return ver
}

func (n *RdrNode) NeedCallback(mNode schema.MatchedNode, callback schema.Callback, version *uint64) {
	if mNode.Node != n.Node {
		panic("NTSchema tree compromised.")
	}

	go func() {
		nameLen := len(mNode.Name)
		var err error = nil
		var fullName enc.Name
		var metadata *rtlv.MetaData
		var lastResult schema.NeedResult

		if version == nil {
			// Fetch the version
			metaIntName := make(enc.Name, nameLen+1)
			copy(metaIntName, mNode.Name)
			metaIntName[nameLen] = enc.NewStringComponent(32, "metadata")
			epMNode := mNode.Refine(metaIntName)

			succeeded := false
			for j := 0; !succeeded && j < int(n.MaxRetriesForMeta); j++ {
				log.Debug(n, "Fetching the metadata", "trial", j)
				lastResult = <-epMNode.Call("NeedChan").(chan schema.NeedResult)
				switch lastResult.Status {
				case ndn.InterestResultData:
					succeeded = true
					metadata, err = rtlv.ParseMetaData(enc.NewWireReader(lastResult.Content), true)
					if err != nil {
						log.Error(n, "Unable to parse and extract name from the metadata packet", "err", err)
						lastResult.Status = ndn.InterestResultError
					}
					fullName = metadata.Name
				}
			}

			if !succeeded || lastResult.Status == ndn.InterestResultError || !mNode.Name.IsPrefix(fullName) {
				event := &schema.Event{
					TargetNode:  n.Node,
					Target:      &mNode,
					Data:        lastResult.Data,
					NackReason:  lastResult.NackReason,
					ValidResult: lastResult.ValidResult,
					NeedStatus:  utils.IdPtr(lastResult.Status),
					Content:     nil,
				}
				if succeeded {
					event.Error = fmt.Errorf("the metadata packet is malformed: %v", err)
				} else {
					event.Error = fmt.Errorf("unable to fetch the metadata packet")
				}
				callback(event)
				return
			}
		} else {
			fullName = make(enc.Name, nameLen+1)
			fullName[nameLen] = enc.NewVersionComponent(*version)
		}

		segMNode := mNode.Refine(fullName)
		segMNode.Call("Need", callback)
	}()
}

func (n *RdrNode) NeedChan(mNode schema.MatchedNode, version *uint64) chan schema.NeedResult {
	ret := make(chan schema.NeedResult, 1)
	callback := func(event *schema.Event) any {
		result := schema.NeedResult{
			Status:      *event.NeedStatus,
			Content:     event.Content,
			Data:        event.Data,
			ValidResult: event.ValidResult,
			NackReason:  event.NackReason,
		}
		ret <- result
		close(ret)
		return nil
	}
	n.NeedCallback(mNode, callback, version)
	return ret
}

func (n *RdrNode) CastTo(ptr any) any {
	switch ptr.(type) {
	case (*RdrNode):
		return n
	case (*schema.BaseNodeImpl):
		return &(n.BaseNodeImpl)
	default:
		return nil
	}
}

// GeneralObject in CNL
type GeneralObjNode struct {
	schema.BaseNodeImpl

	MetaFreshness         time.Duration
	MaxRetriesForMeta     uint64
	ManifestFreshness     time.Duration
	MaxRetriesForManifest uint64
}

func (n *GeneralObjNode) NodeImplTrait() schema.NodeImpl {
	return n
}

func (n *GeneralObjNode) CastTo(ptr any) any {
	switch ptr.(type) {
	case (*GeneralObjNode):
		return n
	case (*schema.BaseNodeImpl):
		return &(n.BaseNodeImpl)
	default:
		return nil
	}
}

func CreateGeneralObjNode(node *schema.Node) schema.NodeImpl {
	ret := &GeneralObjNode{
		BaseNodeImpl: schema.BaseNodeImpl{
			Node:        node,
			OnAttachEvt: &schema.EventTarget{},
			OnDetachEvt: &schema.EventTarget{},
		},
		MetaFreshness:         10 * time.Millisecond,
		MaxRetriesForMeta:     15,
		ManifestFreshness:     10 * time.Millisecond,
		MaxRetriesForManifest: 15,
	}
	path, _ := enc.NamePatternFromStr("32=data")
	node.PutNode(path, SegmentedNodeDesc)
	path, _ = enc.NamePatternFromStr("32=metadata")
	node.PutNode(path, schema.LeafNodeDesc)
	path, _ = enc.NamePatternFromStr("32=manifest")
	node.PutNode(path, schema.LeafNodeDesc)
	// Note: I don't think manifest needs to be segmented here.
	// If it is that large (> 1MB), it is improper to hold the whole object in memory.
	return ret
}

func (n *GeneralObjNode) String() string {
	return fmt.Sprintf("GeneralObjNode (%s)", n.Node)
}

func (n *GeneralObjNode) Provide(mNode schema.MatchedNode, content enc.Wire) uint64 {
	if mNode.Node != n.Node {
		panic("NTSchema tree compromised.")
	}

	// generate segmented data
	nameLen := len(mNode.Name)
	dataName := make(enc.Name, nameLen+1)
	copy(dataName, mNode.Name)
	dataName[nameLen] = enc.NewStringComponent(32, "data")
	dataMNode := mNode.Refine(dataName)
	manifest := dataMNode.Call("Provide", content, true).([]enc.Buffer)
	segCnt := uint64(len(manifest))

	// generate metadata
	metaName := make(enc.Name, nameLen+1)
	copy(metaName, mNode.Name) // Note this does not actually copies the component values
	metaName[nameLen] = enc.NewStringComponent(32, "metadata")
	metaMNode := mNode.Refine(metaName)
	metaDataCfg := &ndn.DataConfig{
		ContentType: utils.IdPtr(ndn.ContentTypeBlob),
		Freshness:   utils.IdPtr(n.MetaFreshness),
	}
	metaData := &rtlv.MetaData{
		Name:         dataName,
		FinalBlockID: enc.NewSegmentComponent(segCnt - 1).Bytes(),
		Size:         utils.IdPtr(content.Length()),
	}
	metaMNode.Call("Provide", metaData.Encode(), metaDataCfg)

	// generate manifest
	manifestName := make(enc.Name, nameLen+1)
	copy(manifestName, mNode.Name)
	manifestName[nameLen] = enc.NewStringComponent(32, "manifest")
	manifestMNode := mNode.Refine(manifestName)
	manifestDataCfg := &ndn.DataConfig{
		ContentType: utils.IdPtr(ndn.ContentTypeBlob),
		Freshness:   utils.IdPtr(n.ManifestFreshness),
	}
	manifestData := &rtlv.ManifestData{
		Entries: make([]*rtlv.ManifestDigest, segCnt),
	}
	for i, v := range manifest {
		manifestData.Entries[i] = &rtlv.ManifestDigest{
			SegNo:  uint64(i),
			Digest: v,
		}
	}
	manifestMNode.Call("Provide", manifestData.Encode(), manifestDataCfg)

	return segCnt
}

func (n *GeneralObjNode) NeedCallback(mNode schema.MatchedNode, callback schema.Callback) {
	if mNode.Node != n.Node {
		panic("NTSchema tree compromised.")
	}

	go func() {
		nameLen := len(mNode.Name)
		var err error = nil
		var manifest *rtlv.ManifestData
		var lastResult schema.NeedResult

		// fetch the manifest
		manifestName := make(enc.Name, nameLen+1)
		copy(manifestName, mNode.Name)
		manifestName[nameLen] = enc.NewStringComponent(32, "manifest")
		manifestMNode := mNode.Refine(manifestName)

		succeeded := false
		for j := 0; !succeeded && j < int(n.MaxRetriesForManifest); j++ {
			log.Debug(n, "Fetching the manifest packet", "trial", j)
			lastResult = <-manifestMNode.Call("NeedChan").(chan schema.NeedResult)
			switch lastResult.Status {
			case ndn.InterestResultData:
				succeeded = true
				manifest, err = rtlv.ParseManifestData(enc.NewWireReader(lastResult.Content), true)
				if err != nil {
					log.Error(n, "Unable to parse the manifest packet", "err", err)
					lastResult.Status = ndn.InterestResultError
				}
			}
		}

		if !succeeded || lastResult.Status == ndn.InterestResultError {
			event := &schema.Event{
				TargetNode:  n.Node,
				Target:      &mNode,
				Data:        lastResult.Data,
				NackReason:  lastResult.NackReason,
				ValidResult: lastResult.ValidResult,
				NeedStatus:  utils.IdPtr(lastResult.Status),
				Content:     nil,
			}
			if succeeded {
				event.Error = fmt.Errorf("the manifest packet is malformed: %v", err)
			} else {
				event.Error = fmt.Errorf("unable to fetch the manifest packet")
			}
			callback(event)
			return
		}

		manifestBuf := make([]enc.Buffer, len(manifest.Entries))
		for i, v := range manifest.Entries {
			manifestBuf[i] = v.Digest
		}

		// fetch the segments
		dataName := make(enc.Name, nameLen+1)
		copy(dataName, mNode.Name)
		dataName[nameLen] = enc.NewStringComponent(32, "data")
		segMNode := mNode.Refine(dataName)
		segMNode.Call("Need", callback, manifestBuf)
	}()
}

func (n *GeneralObjNode) NeedChan(mNode schema.MatchedNode) chan schema.NeedResult {
	ret := make(chan schema.NeedResult, 1)
	callback := func(event *schema.Event) any {
		result := schema.NeedResult{
			Status:      *event.NeedStatus,
			Content:     event.Content,
			Data:        event.Data,
			ValidResult: event.ValidResult,
			NackReason:  event.NackReason,
		}
		ret <- result
		close(ret)
		return nil
	}
	n.NeedCallback(mNode, callback)
	return ret
}

var (
	RdrNodeDesc        *schema.NodeImplDesc
	SegmentedNodeDesc  *schema.NodeImplDesc
	GeneralObjNodeDesc *schema.NodeImplDesc
)

func initRdrNodes() {
	SegmentedNodeDesc = &schema.NodeImplDesc{
		ClassName: "SegmentedNode",
		Properties: map[schema.PropKey]schema.PropertyDesc{
			"ContentType":         schema.DefaultPropertyDesc("ContentType"),
			"Lifetime":            schema.TimePropertyDesc("Lifetime"),
			"Freshness":           schema.TimePropertyDesc("Freshness"),
			"ValidDuration":       schema.TimePropertyDesc("ValidDur"),
			"MustBeFresh":         schema.DefaultPropertyDesc("MustBeFresh"),
			"SegmentSize":         schema.DefaultPropertyDesc("SegmentSize"),
			"MaxRetriesOnFailure": schema.DefaultPropertyDesc("MaxRetriesOnFailure"),
			"Pipeline":            schema.DefaultPropertyDesc("Pipeline"),
		},
		Events: map[schema.PropKey]schema.EventGetter{
			schema.PropOnAttach: schema.DefaultEventTarget(schema.PropOnAttach), // Inherited from base
			schema.PropOnDetach: schema.DefaultEventTarget(schema.PropOnDetach), // Inherited from base
		},
		Functions: map[string]schema.NodeFunc{
			"Provide": func(mNode schema.MatchedNode, args ...any) any {
				if len(args) < 1 || len(args) > 2 {
					err := fmt.Errorf("SegmentedNode.Provide requires 1~2 arguments but got %d", len(args))
					log.Error(mNode.Node, err.Error())
					return err
				}
				content, ok := args[0].(enc.Wire)
				if !ok && args[0] != nil {
					err := ndn.ErrInvalidValue{Item: "content", Value: args[0]}
					log.Error(mNode.Node, err.Error())
					return err
				}
				var needManifest bool = false
				if len(args) >= 2 {
					needManifest, ok = args[1].(bool)
					if !ok && args[1] != nil {
						err := ndn.ErrInvalidValue{Item: "needManifest", Value: args[0]}
						log.Error(mNode.Node, err.Error())
						return err
					}
				}
				return schema.QueryInterface[*SegmentedNode](mNode.Node).Provide(mNode, content, needManifest)
			},
			"Need": func(mNode schema.MatchedNode, args ...any) any {
				if len(args) < 1 || len(args) > 2 {
					err := fmt.Errorf("SegmentedNode.Need requires 1~2 arguments but got %d", len(args))
					log.Error(mNode.Node, err.Error())
					return err
				}
				callback, ok := args[0].(schema.Callback)
				if !ok {
					err := ndn.ErrInvalidValue{Item: "callback", Value: args[0]}
					log.Error(mNode.Node, err.Error())
					return err
				}
				var manifest []enc.Buffer = nil
				if len(args) >= 2 {
					manifest, ok = args[1].([]enc.Buffer)
					if !ok && args[1] != nil {
						err := ndn.ErrInvalidValue{Item: "manifest", Value: args[0]}
						log.Error(mNode.Node, err.Error())
						return err
					}
				}
				return schema.QueryInterface[*SegmentedNode](mNode.Node).NeedCallback(mNode, callback, manifest)
			},
			"NeedChan": func(mNode schema.MatchedNode, args ...any) any {
				if len(args) > 1 {
					err := fmt.Errorf("SegmentedNode.NeedChan requires 0~1 arguments but got %d", len(args))
					log.Error(mNode.Node, err.Error())
					return err
				}
				var manifest []enc.Buffer = nil
				var ok bool = true
				if len(args) >= 1 {
					manifest, ok = args[0].([]enc.Buffer)
					if !ok && args[0] != nil {
						err := ndn.ErrInvalidValue{Item: "manifest", Value: args[0]}
						log.Error(mNode.Node, err.Error())
						return err
					}
				}
				return schema.QueryInterface[*SegmentedNode](mNode.Node).NeedChan(mNode, manifest)
			},
		},
		Create: CreateSegmentedNode,
	}
	schema.RegisterNodeImpl(SegmentedNodeDesc)

	RdrNodeDesc = &schema.NodeImplDesc{
		ClassName: "RdrNode",
		Properties: map[schema.PropKey]schema.PropertyDesc{
			"MetaFreshness":       schema.TimePropertyDesc("MetaFreshness"),
			"MaxRetriesForMeta":   schema.DefaultPropertyDesc("MaxRetriesForMeta"),
			"MetaLifetime":        schema.SubNodePropertyDesc("32=metadata", schema.PropLifetime),
			"ContentType":         schema.SubNodePropertyDesc("<v=versionNumber>", "ContentType"),
			"Lifetime":            schema.SubNodePropertyDesc("<v=versionNumber>", "Lifetime"),
			"Freshness":           schema.SubNodePropertyDesc("<v=versionNumber>", "Freshness"),
			"ValidDuration":       schema.SubNodePropertyDesc("<v=versionNumber>", "ValidDuration"),
			"MustBeFresh":         schema.SubNodePropertyDesc("<v=versionNumber>", "MustBeFresh"),
			"SegmentSize":         schema.SubNodePropertyDesc("<v=versionNumber>", "SegmentSize"),
			"MaxRetriesOnFailure": schema.SubNodePropertyDesc("<v=versionNumber>", "MaxRetriesOnFailure"),
			"Pipeline":            schema.SubNodePropertyDesc("<v=versionNumber>", "Pipeline"),
		},
		Events: map[schema.PropKey]schema.EventGetter{
			schema.PropOnAttach: schema.DefaultEventTarget(schema.PropOnAttach), // Inherited from base
			schema.PropOnDetach: schema.DefaultEventTarget(schema.PropOnDetach), // Inherited from base
		},
		Functions: map[string]schema.NodeFunc{
			"Provide": func(mNode schema.MatchedNode, args ...any) any {
				if len(args) != 1 {
					err := fmt.Errorf("RdrNode.Provide requires 1 arguments but got %d", len(args))
					log.Error(mNode.Node, err.Error())
					return err
				}
				content, ok := args[0].(enc.Wire)
				if !ok && args[0] != nil {
					err := ndn.ErrInvalidValue{Item: "content", Value: args[0]}
					log.Error(mNode.Node, err.Error())
					return err
				}
				return schema.QueryInterface[*RdrNode](mNode.Node).Provide(mNode, content)
			},
			"Need": func(mNode schema.MatchedNode, args ...any) any {
				if len(args) < 1 || len(args) > 2 {
					err := fmt.Errorf("RdrNode.Need requires 1~2 arguments but got %d", len(args))
					log.Error(mNode.Node, err.Error())
					return err
				}
				callback, ok := args[0].(schema.Callback)
				if !ok {
					err := ndn.ErrInvalidValue{Item: "callback", Value: args[0]}
					log.Error(mNode.Node, err.Error())
					return err
				}
				var version *uint64 = nil
				if len(args) >= 2 {
					version, ok = args[1].(*uint64)
					if !ok && args[1] != nil {
						err := ndn.ErrInvalidValue{Item: "version", Value: args[0]}
						log.Error(mNode.Node, err.Error())
						return err
					}
				}
				schema.QueryInterface[*RdrNode](mNode.Node).NeedCallback(mNode, callback, version)
				return nil
			},
			"NeedChan": func(mNode schema.MatchedNode, args ...any) any {
				if len(args) > 1 {
					err := fmt.Errorf("RdrNode.NeedChan requires 0~1 arguments but got %d", len(args))
					log.Error(mNode.Node, err.Error())
					return err
				}
				var version *uint64 = nil
				var ok bool = true
				if len(args) >= 1 {
					version, ok = args[0].(*uint64)
					if !ok && args[0] != nil {
						err := ndn.ErrInvalidValue{Item: "version", Value: args[0]}
						log.Error(mNode.Node, err.Error())
						return err
					}
				}
				return schema.QueryInterface[*RdrNode](mNode.Node).NeedChan(mNode, version)
			},
		},
		Create: CreateRdrNode,
	}
	schema.RegisterNodeImpl(RdrNodeDesc)

	GeneralObjNodeDesc = &schema.NodeImplDesc{
		ClassName: "GeneralObjNode",
		Properties: map[schema.PropKey]schema.PropertyDesc{
			"MetaFreshness":         schema.TimePropertyDesc("MetaFreshness"),
			"MaxRetriesForMeta":     schema.DefaultPropertyDesc("MaxRetriesForMeta"),
			"ManifestFreshness":     schema.TimePropertyDesc("ManifestFreshness"),
			"MaxRetriesForManifest": schema.DefaultPropertyDesc("MaxRetriesForManifest"),
			"MetaLifetime":          schema.SubNodePropertyDesc("32=metadata", schema.PropLifetime),
			"ManifestLifetime":      schema.SubNodePropertyDesc("32=manifest", schema.PropLifetime),
			"ContentType":           schema.SubNodePropertyDesc("32=data", "ContentType"),
			"Lifetime":              schema.SubNodePropertyDesc("32=data", "Lifetime"),
			"Freshness":             schema.SubNodePropertyDesc("32=data", "Freshness"),
			"ValidDuration":         schema.SubNodePropertyDesc("32=data", "ValidDuration"),
			"MustBeFresh":           schema.SubNodePropertyDesc("32=data", "MustBeFresh"),
			"SegmentSize":           schema.SubNodePropertyDesc("32=data", "SegmentSize"),
			"MaxRetriesOnFailure":   schema.SubNodePropertyDesc("32=data", "MaxRetriesOnFailure"),
			"Pipeline":              schema.SubNodePropertyDesc("32=data", "Pipeline"),
		},
		Events: map[schema.PropKey]schema.EventGetter{
			schema.PropOnAttach: schema.DefaultEventTarget(schema.PropOnAttach), // Inherited from base
			schema.PropOnDetach: schema.DefaultEventTarget(schema.PropOnDetach), // Inherited from base
		},
		Functions: map[string]schema.NodeFunc{
			"Provide": func(mNode schema.MatchedNode, args ...any) any {
				if len(args) != 1 {
					err := fmt.Errorf("GeneralObjNode.Provide requires 1 arguments but got %d", len(args))
					log.Error(mNode.Node, err.Error())
					return err
				}
				content, ok := args[0].(enc.Wire)
				if !ok && args[0] != nil {
					err := ndn.ErrInvalidValue{Item: "content", Value: args[0]}
					log.Error(mNode.Node, err.Error())
					return err
				}
				return schema.QueryInterface[*GeneralObjNode](mNode.Node).Provide(mNode, content)
			},
			"Need": func(mNode schema.MatchedNode, args ...any) any {
				if len(args) != 1 {
					err := fmt.Errorf("GeneralObjNode.Need requires 1 arguments but got %d", len(args))
					log.Error(mNode.Node, err.Error())
					return err
				}
				callback, ok := args[0].(schema.Callback)
				if !ok {
					err := ndn.ErrInvalidValue{Item: "callback", Value: args[0]}
					log.Error(mNode.Node, err.Error())
					return err
				}
				schema.QueryInterface[*GeneralObjNode](mNode.Node).NeedCallback(mNode, callback)
				return nil
			},
			"NeedChan": func(mNode schema.MatchedNode, args ...any) any {
				if len(args) > 0 {
					err := fmt.Errorf("GeneralObjNode.NeedChan requires 0 arguments but got %d", len(args))
					log.Error(mNode.Node, err.Error())
					return err
				}
				return schema.QueryInterface[*GeneralObjNode](mNode.Node).NeedChan(mNode)
			},
		},
		Create: CreateGeneralObjNode,
	}
	schema.RegisterNodeImpl(GeneralObjNodeDesc)
}

func init() {
	initRdrNodes()
}
