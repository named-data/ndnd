package nfdc

type ndndPET struct {
	Entries []ndndPETEntry `xml:"entry" json:"entries"`
}

type ndndPETEntry struct {
	Prefix        string        `xml:"prefix,attr" json:"prefix"`
	Multicast     bool          `xml:"multicast,attr" json:"multicast"`
	EgressRouters []string      `xml:"egress>router" json:"egressRouters"`
	NextHops      []ndndNextHop `xml:"nextHop" json:"nextHop"`
}

type ndndBIFT struct {
	Enabled   bool               `xml:"enabled,attr" json:"enabled"`
	BierIndex *uint64            `xml:"bierIndex,omitempty" json:"bierIndex,omitempty"`
	Entries   []ndndBIFTEntry    `xml:"entries>entry" json:"entries"`
	Neighbors []ndndBIFTNeighbor `xml:"neighbors>neighbor" json:"neighbors"`
}

type ndndBIFTEntry struct {
	BfrID    uint64            `xml:"bfrId,attr" json:"bfrId"`
	Router   string            `xml:"router" json:"router"`
	NextHops []ndndBIERNextHop `xml:"nextHop" json:"nextHop"`
	FbmBits  []uint64          `xml:"fbmBits>bit" json:"fbmBits"`
}

type ndndBIERNextHop struct {
	FaceID uint64 `xml:"faceId,attr" json:"faceId,string"`
}

type ndndBIFTNeighbor struct {
	FaceID  uint64   `xml:"faceId,attr" json:"faceId,string"`
	FbmBits []uint64 `xml:"fbmBits>bit" json:"fbmBits"`
}

func (t *Tool) populatePET(report *ndndStatusReport) error {
	status, err := t.fetchPetStatus()
	if err != nil {
		return err
	}
	for _, entry := range status.Entries {
		item := ndndPETEntry{Prefix: entry.Name.String(), Multicast: entry.Multicast}
		for _, egress := range entry.EgressRecords {
			item.EgressRouters = append(item.EgressRouters, egress.Name.String())
		}
		item.NextHops = ndndNextHops(entry.NextHopRecords)
		report.PET.Entries = append(report.PET.Entries, item)
	}
	return nil
}

func (t *Tool) populateBIFT(report *ndndStatusReport) error {
	status, err := t.fetchBiftStatus()
	if err != nil {
		return err
	}
	report.BIFT = ndndBIFT{Enabled: status.General.BierIndex.IsSet()}
	if index, enabled := status.General.BierIndex.Get(); enabled {
		report.BIFT.BierIndex = &index
	}
	for _, entry := range status.Entries {
		item := ndndBIFTEntry{BfrID: entry.BfrId, Router: entry.RouterName.String(), FbmBits: entry.FbmBits}
		for _, face := range entry.NextHops {
			item.NextHops = append(item.NextHops, ndndBIERNextHop{FaceID: face})
		}
		report.BIFT.Entries = append(report.BIFT.Entries, item)
	}
	for _, neighbor := range status.Neighbors {
		report.BIFT.Neighbors = append(report.BIFT.Neighbors, ndndBIFTNeighbor{FaceID: neighbor.FaceID, FbmBits: neighbor.FbmBits})
	}
	return nil
}
