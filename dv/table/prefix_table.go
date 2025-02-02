package table

import (
	"github.com/named-data/ndnd/dv/config"
	"github.com/named-data/ndnd/dv/tlv"
	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/log"
	"github.com/named-data/ndnd/std/ndn"
	"github.com/named-data/ndnd/std/object"
	ndn_sync "github.com/named-data/ndnd/std/sync"
)

const PrefixSnapThreshold = 100
const PrefixSnapKeyword = "SNAP"

type PrefixTable struct {
	config *config.Config
	client ndn.Client
	svs    *ndn_sync.SvSync

	routers map[string]*PrefixTableRouter
	me      *PrefixTableRouter

	snapshotAt uint64
	objDir     *object.MemoryFifoDir
}

type PrefixTableRouter struct {
	Name     enc.Name
	Fetching bool
	BootTime uint64
	Known    uint64
	Latest   uint64
	Prefixes map[string]*PrefixEntry
}

type PrefixEntry struct {
	Name enc.Name
}

func NewPrefixTable(
	config *config.Config,
	client ndn.Client,
	svs *ndn_sync.SvSync,
) *PrefixTable {
	pt := &PrefixTable{
		config: config,
		client: client,
		svs:    svs,

		routers: make(map[string]*PrefixTableRouter),
		me:      nil,

		snapshotAt: 0,
		objDir:     object.NewMemoryFifoDir(3 * PrefixSnapThreshold),
	}

	pt.me = pt.GetRouter(config.RouterName())
	pt.me.BootTime = svs.GetBootTime()
	pt.Reset()

	return pt
}

func (pt *PrefixTable) String() string {
	return "dv-prefix"
}

func (pt *PrefixTable) GetRouter(name enc.Name) *PrefixTableRouter {
	hash := name.String()
	router := pt.routers[hash]
	if router == nil {
		router = &PrefixTableRouter{
			Name:     name,
			Prefixes: make(map[string]*PrefixEntry),
		}
		pt.routers[hash] = router
	}
	return router
}

func (pt *PrefixTable) Reset() {
	log.Info(pt, "Reset table")
	pt.me.Prefixes = make(map[string]*PrefixEntry)

	op := tlv.PrefixOpList{
		ExitRouter:    &tlv.Destination{Name: pt.config.RouterName()},
		PrefixOpReset: true,
	}
	pt.publishOp(op.Encode())
}

func (pt *PrefixTable) Announce(name enc.Name) {
	log.Info(pt, "Announce prefix", "name", name)
	hash := name.String()

	// Skip if matching entry already exists
	// This will also need to check that all params are equal
	if entry := pt.me.Prefixes[hash]; entry != nil && entry.Name.Equal(name) {
		return
	}

	// Create new entry and announce globally
	pt.me.Prefixes[hash] = &PrefixEntry{Name: name}

	op := tlv.PrefixOpList{
		ExitRouter: &tlv.Destination{Name: pt.config.RouterName()},
		PrefixOpAdds: []*tlv.PrefixOpAdd{{
			Name: name,
			Cost: 1,
		}},
	}
	pt.publishOp(op.Encode())
}

func (pt *PrefixTable) Withdraw(name enc.Name) {
	log.Info(pt, "Withdraw prefix", "name", name)
	hash := name.String()

	// Check if entry does not exist
	if entry := pt.me.Prefixes[hash]; entry == nil {
		return
	}

	// Delete the existing entry and announce globally
	delete(pt.me.Prefixes, hash)

	op := tlv.PrefixOpList{
		ExitRouter:      &tlv.Destination{Name: pt.config.RouterName()},
		PrefixOpRemoves: []*tlv.PrefixOpRemove{{Name: name}},
	}
	pt.publishOp(op.Encode())
}

// Applies ops from a list. Returns if dirty.
func (pt *PrefixTable) Apply(ops *tlv.PrefixOpList) (dirty bool) {
	if ops.ExitRouter == nil || len(ops.ExitRouter.Name) == 0 {
		log.Error(pt, "Received PrefixOpList has no ExitRouter")
		return false
	}

	router := pt.GetRouter(ops.ExitRouter.Name)

	if ops.PrefixOpReset {
		log.Info(pt, "Reset remote prefixes", "router", ops.ExitRouter.Name)
		router.Prefixes = make(map[string]*PrefixEntry)
		dirty = true
	}

	for _, add := range ops.PrefixOpAdds {
		log.Info(pt, "Add remote prefix", "router", ops.ExitRouter.Name, "name", add.Name)
		router.Prefixes[add.Name.String()] = &PrefixEntry{Name: add.Name}
		dirty = true
	}

	for _, remove := range ops.PrefixOpRemoves {
		log.Info(pt, "Remove remote prefix", "router", ops.ExitRouter.Name, "name", remove.Name)
		delete(router.Prefixes, remove.Name.String())
		dirty = true
	}

	return dirty
}

// Get the object name to fetch the next prefix table data.
// If the difference between Known and Latest is greater than the threshold,
// fetch the latest snapshot. Otherwise, fetch the next sequence number.
func (r *PrefixTableRouter) GetNextDataName() enc.Name {
	// /<router>/32=DV/32=PFX/t=<boot>/32=SNAP/v=<seq>
	// /<router>/32=DV/32=PFX/t=<boot>/seq=<seq>/v=0
	prefix := r.Name.
		Append(enc.NewKeywordComponent("DV")).
		Append(enc.NewKeywordComponent("PFX")).
		Append(enc.NewTimestampComponent(r.BootTime))

	if r.Latest-r.Known > PrefixSnapThreshold {
		return prefix.
			Append(enc.NewKeywordComponent(PrefixSnapKeyword))
	}

	return prefix.
		Append(enc.NewSequenceNumComponent(r.Known + 1)).
		WithVersion(enc.VersionImmutable)
}

// Process the received prefix data. Returns if dirty.
func (pt *PrefixTable) ApplyData(name enc.Name, data enc.Wire, router *PrefixTableRouter) bool {
	if len(name) < 2 {
		log.Warn(pt, "Unexpected name length", "len", len(name))
		return false
	}

	// Get sequence number from name
	// /<router>/32=DV/32=PFX/t=<boot>/32=SNAP/v=<seq>
	// /<router>/32=DV/32=PFX/t=<boot>/seq=<seq>/v=0
	var seqNo uint64
	if name.At(-2).IsKeyword(PrefixSnapKeyword) {
		// version is sequence number for snapshot
		seqNo = name.At(-1).NumberVal()
	} else if name.At(-2).IsSequenceNum() {
		// version is immutable, sequence number is in name
		seqNo = name.At(-2).NumberVal()
	} else {
		log.Warn(pt, "Unexpected prefix data name", "name", name)
		return false
	}

	// Parse the prefix data
	ops, err := tlv.ParsePrefixOpList(enc.NewFastReader(data), true)
	if err != nil {
		log.Warn(pt, "Failed to parse PrefixOpList", "err", err)
		return false
	}

	// Update the prefix table
	router.Known = seqNo
	return pt.Apply(ops)
}

func (pt *PrefixTable) publishOp(content enc.Wire) {
	// Increment our sequence number
	seq := pt.svs.IncrSeqNo(pt.config.RouterName())
	pt.me.Known = seq
	pt.me.Latest = seq

	// Produce the operation
	// /<router>/32=DV/32=PFX/t=<boot>/seq=<seq>/v=0
	name, err := pt.client.Produce(ndn.ProduceArgs{
		Name: pt.config.PrefixTableDataPrefix().
			Append(enc.NewTimestampComponent(pt.me.BootTime)).
			Append(enc.NewSequenceNumComponent(seq)).
			WithVersion(enc.VersionImmutable),
		Content: content,
	})
	if err != nil {
		log.Error(pt, "Failed to produce op", "err", err)
		return
	}
	pt.objDir.Push(name)

	// Create snapshot if needed
	if seq-pt.snapshotAt >= PrefixSnapThreshold/2 {
		pt.publishSnap()
	}
}

func (pt *PrefixTable) publishSnap() {
	// Encode the snapshot
	snap := tlv.PrefixOpList{
		ExitRouter:    &tlv.Destination{Name: pt.config.RouterName()},
		PrefixOpReset: true,
		PrefixOpAdds:  make([]*tlv.PrefixOpAdd, 0, len(pt.me.Prefixes)),
	}

	for _, entry := range pt.me.Prefixes {
		snap.PrefixOpAdds = append(snap.PrefixOpAdds, &tlv.PrefixOpAdd{
			Name: entry.Name,
			Cost: 1,
		})
	}

	// Produce the snapshot
	// /<router>/32=DV/32=PFX/t=<boot>/32=SNAP/v=<seq>
	name, err := pt.client.Produce(ndn.ProduceArgs{
		Name: pt.config.PrefixTableDataPrefix().
			Append(enc.NewTimestampComponent(pt.me.BootTime)).
			Append(enc.NewKeywordComponent(PrefixSnapKeyword)).
			WithVersion(pt.me.Latest),
		Content: snap.Encode(),
	})
	if err != nil {
		log.Error(pt, "Failed to produce snap", "err", err)
	}
	pt.objDir.Push(name)
	pt.objDir.Evict(pt.client)

	// Mark current snapshot time for next
	pt.snapshotAt = pt.me.Latest
}
