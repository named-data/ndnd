package nfdc

import (
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	dvconfig "github.com/named-data/ndnd/dv/config"
	dvtlv "github.com/named-data/ndnd/dv/tlv"
	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/log"
	mgmt "github.com/named-data/ndnd/std/ndn/mgmt_2022"
	"github.com/spf13/cobra"
)

type ndndStatusReport struct {
	XMLName      xml.Name          `xml:"ndndStatus" json:"-"`
	GeneratedAt  string            `xml:"generatedAt,attr" json:"generatedAt"`
	General      ndndGeneralStatus `xml:"general" json:"general"`
	Faces        ndndFaces         `xml:"faces" json:"faces"`
	FIB          ndndFIB           `xml:"fib" json:"fib"`
	RIB          ndndRIB           `xml:"rib" json:"rib"`
	ContentStore ndndContentStore  `xml:"contentStore" json:"contentStore"`
	Strategies   ndndStrategies    `xml:"strategies" json:"strategies"`
	DV           ndndDVStatus      `xml:"dv" json:"dv"`
}

type ndndGeneralStatus struct {
	Version               string `xml:"version" json:"version"`
	StartTime             string `xml:"startTime" json:"startTime"`
	CurrentTime           string `xml:"currentTime" json:"currentTime"`
	Uptime                string `xml:"uptime" json:"uptime"`
	NFIBEntries           uint64 `xml:"nFibEntries" json:"nFibEntries"`
	NPITEntries           uint64 `xml:"nPitEntries" json:"nPitEntries"`
	NCsEntries            uint64 `xml:"nCsEntries" json:"nCsEntries"`
	NInInterests          uint64 `xml:"nInInterests" json:"nInInterests,string"`
	NOutInterests         uint64 `xml:"nOutInterests" json:"nOutInterests,string"`
	NInData               uint64 `xml:"nInData" json:"nInData,string"`
	NOutData              uint64 `xml:"nOutData" json:"nOutData,string"`
	NSatisfiedInterests   uint64 `xml:"nSatisfiedInterests" json:"nSatisfiedInterests,string"`
	NUnsatisfiedInterests uint64 `xml:"nUnsatisfiedInterests" json:"nUnsatisfiedInterests,string"`
}

type ndndFace struct {
	ID                         uint64  `xml:"faceId,attr" json:"faceId,string"`
	RemoteURI                  string  `xml:"remoteUri" json:"remoteUri"`
	LocalURI                   string  `xml:"localUri" json:"localUri"`
	Scope                      string  `xml:"scope" json:"scope"`
	Persistency                string  `xml:"persistency" json:"persistency"`
	LinkType                   string  `xml:"linkType" json:"linkType"`
	MTU                        *uint64 `xml:"mtu,omitempty" json:"mtu,omitempty"`
	BaseCongestionMarkInterval *uint64 `xml:"baseCongestionMarkInterval,omitempty" json:"baseCongestionMarkInterval,omitempty,string"`
	DefaultCongestionThreshold *uint64 `xml:"defaultCongestionThreshold,omitempty" json:"defaultCongestionThreshold,omitempty,string"`
	Flags                      string  `xml:"flags" json:"flags"`
	ExpirationMilliseconds     *uint64 `xml:"expirationMilliseconds,omitempty" json:"expirationMilliseconds,omitempty"`
	NInInterests               uint64  `xml:"nInInterests" json:"nInInterests,string"`
	NInData                    uint64  `xml:"nInData" json:"nInData,string"`
	NInBytes                   uint64  `xml:"nInBytes" json:"nInBytes,string"`
	NOutInterests              uint64  `xml:"nOutInterests" json:"nOutInterests,string"`
	NOutData                   uint64  `xml:"nOutData" json:"nOutData,string"`
	NOutBytes                  uint64  `xml:"nOutBytes" json:"nOutBytes,string"`
}

type ndndDVStatus struct {
	Available        bool           `xml:"available,attr" json:"available"`
	Version          string         `xml:"version" json:"version"`
	NetworkName      string         `xml:"networkName" json:"networkName"`
	RouterName       string         `xml:"routerName" json:"routerName"`
	NRibEntries      uint64         `xml:"nRibEntries" json:"nRibEntries"`
	NNeighbors       uint64         `xml:"nNeighbors" json:"nNeighbors"`
	NFibEntries      uint64         `xml:"nFibEntries" json:"nFibEntries"`
	DatasetAvailable bool           `xml:"datasetAvailable,attr" json:"datasetAvailable"`
	Routers          []ndndDVRouter `xml:"routers>router" json:"routers"`
}

type ndndDVRouter struct {
	Name     string         `xml:"name,attr" json:"name"`
	NextHop  string         `xml:"nextHop" json:"nextHop"`
	Cost     uint64         `xml:"cost" json:"cost"`
	Prefixes []ndndDVPrefix `xml:"prefixes>prefix" json:"prefixes"`
}

type ndndDVPrefix struct {
	Name string `xml:"name,attr" json:"name"`
	Cost uint64 `xml:"cost,attr" json:"cost"`
}

type ndndFaces struct {
	Entries []ndndFace `xml:"face" json:"entries"`
}

type ndndFIBEntry struct {
	Prefix   string        `xml:"prefix,attr" json:"prefix"`
	NextHops []ndndNextHop `xml:"nextHop" json:"nextHop"`
}

type ndndFIB struct {
	Entries []ndndFIBEntry `xml:"entry" json:"entries"`
}

type ndndRIBEntry struct {
	Prefix string      `xml:"prefix,attr" json:"prefix"`
	Routes []ndndRoute `xml:"route" json:"route"`
}

type ndndRIB struct {
	Entries []ndndRIBEntry `xml:"entry" json:"entries"`
}

type ndndNextHop struct {
	FaceID uint64 `xml:"faceId,attr" json:"faceId,string"`
	Cost   uint64 `xml:"cost,attr" json:"cost,string"`
}

type ndndRoute struct {
	FaceID           uint64  `xml:"faceId,attr" json:"faceId,string"`
	Origin           string  `xml:"origin,attr" json:"origin"`
	Cost             uint64  `xml:"cost,attr" json:"cost,string"`
	Flags            string  `xml:"flags,attr" json:"flags"`
	ExpirationMillis *uint64 `xml:"expirationMilliseconds,attr,omitempty" json:"expirationMilliseconds,omitempty"`
}

type ndndContentStore struct {
	Capacity uint64 `xml:"capacity,attr" json:"capacity"`
	Admit    bool   `xml:"admit,attr" json:"admit"`
	Serve    bool   `xml:"serve,attr" json:"serve"`
	Entries  uint64 `xml:"entries,attr" json:"entries"`
	Hits     uint64 `xml:"hits,attr" json:"hits,string"`
	Misses   uint64 `xml:"misses,attr" json:"misses,string"`
}

type ndndStrategy struct {
	Prefix   string `xml:"prefix,attr" json:"prefix"`
	Strategy string `xml:"strategy,attr" json:"strategy"`
}

type ndndStrategies struct {
	Entries []ndndStrategy `xml:"strategy" json:"entries"`
}

func (t *Tool) RunStatusReport(_ *cobra.Command, _ []string) error {
	encode := encodeNdndStatusXML
	switch t.statusFormat {
	case "xml":
	case "json":
		encode = encodeNdndStatusJSON
	default:
		return fmt.Errorf("unsupported status format %q: use xml or json", t.statusFormat)
	}
	if err := t.configureStatusTrust(); err != nil {
		return err
	}
	t.Start()
	defer t.Stop()

	report, err := t.buildNdndStatusReport()
	if err != nil {
		return fmt.Errorf("unable to build NDNd status report: %w", err)
	}
	encoded, err := encode(report)
	if err != nil {
		return fmt.Errorf("unable to encode NDNd status report: %w", err)
	}
	if _, err := os.Stdout.Write(encoded); err != nil {
		return fmt.Errorf("unable to write NDNd status report: %w", err)
	}
	return nil
}

func encodeNdndStatusXML(report *ndndStatusReport) ([]byte, error) {
	encoded, err := xml.MarshalIndent(report, "", "  ")
	if err != nil {
		return nil, err
	}
	return append([]byte(xml.Header), encoded...), nil
}

func encodeNdndStatusJSON(report *ndndStatusReport) ([]byte, error) {
	return json.MarshalIndent(report, "", "  ")
}

func (t *Tool) buildNdndStatusReport() (*ndndStatusReport, error) {
	generalData, err := t.fetchStatusDataset(enc.Name{enc.NewGenericComponent("status"), enc.NewGenericComponent("general")})
	if err != nil {
		return nil, fmt.Errorf("fetch general status: %w", err)
	}
	general, err := mgmt.ParseGeneralStatus(enc.NewWireView(generalData), true)
	if err != nil {
		return nil, fmt.Errorf("parse general status: %w", err)
	}

	report := &ndndStatusReport{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		General: ndndGeneralStatus{
			Version:               general.NfdVersion,
			StartTime:             time.Unix(0, int64(general.StartTimestamp)).UTC().Format(time.RFC3339),
			CurrentTime:           time.Unix(0, int64(general.CurrentTimestamp)).UTC().Format(time.RFC3339),
			Uptime:                (general.CurrentTimestamp - general.StartTimestamp).String(),
			NFIBEntries:           general.NFibEntries,
			NPITEntries:           general.NPitEntries,
			NCsEntries:            general.NCsEntries,
			NInInterests:          general.NInInterests,
			NOutInterests:         general.NOutInterests,
			NInData:               general.NInData,
			NOutData:              general.NOutData,
			NSatisfiedInterests:   general.NSatisfiedInterests,
			NUnsatisfiedInterests: general.NUnsatisfiedInterests,
		},
	}

	if err := t.populateFaces(report); err != nil {
		return nil, err
	}
	if err := t.populateFIB(report); err != nil {
		return nil, err
	}
	if err := t.populateRIB(report); err != nil {
		return nil, err
	}
	if err := t.populateContentStore(report); err != nil {
		return nil, err
	}
	if err := t.populateStrategies(report); err != nil {
		return nil, err
	}
	// DV is optional; its errors are logged without discarding forwarder status.
	_ = t.populateDVStatus(report)
	return report, nil
}

func (t *Tool) populateFaces(report *ndndStatusReport) error {
	data, err := t.fetchStatusDataset(enc.Name{enc.NewGenericComponent("faces"), enc.NewGenericComponent("list")})
	if err != nil {
		return fmt.Errorf("fetch faces: %w", err)
	}
	status, err := mgmt.ParseFaceStatusMsg(enc.NewWireView(data), true)
	if err != nil {
		return fmt.Errorf("parse faces: %w", err)
	}
	for _, item := range status.Vals {
		face := ndndFace{
			ID:            item.FaceId,
			RemoteURI:     item.Uri,
			LocalURI:      item.LocalUri,
			Scope:         faceScopeName(item.FaceScope),
			Persistency:   mgmt.Persistency(item.FacePersistency).String(),
			LinkType:      faceLinkTypeName(item.LinkType),
			Flags:         faceFlagsName(item.Flags),
			NInInterests:  item.NInInterests,
			NInData:       item.NInData,
			NInBytes:      item.NInBytes,
			NOutInterests: item.NOutInterests,
			NOutData:      item.NOutData,
			NOutBytes:     item.NOutBytes,
		}
		if interval, ok := item.BaseCongestionMarkInterval.Get(); ok {
			face.BaseCongestionMarkInterval = &interval
		}
		if threshold, ok := item.DefaultCongestionThreshold.Get(); ok {
			face.DefaultCongestionThreshold = &threshold
		}
		if mtu, ok := item.Mtu.Get(); ok {
			face.MTU = &mtu
		}
		if expiration, ok := item.ExpirationPeriod.Get(); ok {
			face.ExpirationMilliseconds = &expiration
		}
		report.Faces.Entries = append(report.Faces.Entries, face)
	}
	return nil
}

func (t *Tool) populateFIB(report *ndndStatusReport) error {
	data, err := t.fetchStatusDataset(enc.Name{enc.NewGenericComponent("fib"), enc.NewGenericComponent("list")})
	if err != nil {
		return fmt.Errorf("fetch FIB: %w", err)
	}
	status, err := mgmt.ParseFibStatus(enc.NewWireView(data), true)
	if err != nil {
		return fmt.Errorf("parse FIB: %w", err)
	}
	for _, item := range status.Entries {
		entry := ndndFIBEntry{Prefix: item.Name.String()}
		for _, nextHop := range item.NextHopRecords {
			entry.NextHops = append(entry.NextHops, ndndNextHop{FaceID: nextHop.FaceId, Cost: nextHop.Cost})
		}
		report.FIB.Entries = append(report.FIB.Entries, entry)
	}
	return nil
}

func (t *Tool) populateRIB(report *ndndStatusReport) error {
	data, err := t.fetchStatusDataset(enc.Name{enc.NewGenericComponent("rib"), enc.NewGenericComponent("list")})
	if err != nil {
		return fmt.Errorf("fetch RIB: %w", err)
	}
	status, err := mgmt.ParseRibStatus(enc.NewWireView(data), true)
	if err != nil {
		return fmt.Errorf("parse RIB: %w", err)
	}
	for _, item := range status.Entries {
		entry := ndndRIBEntry{Prefix: item.Name.String()}
		for _, route := range item.Routes {
			flags := make([]string, 0)
			for flag, name := range mgmt.RouteFlagList {
				if flag.IsSet(route.Flags) {
					flags = append(flags, name)
				}
			}
			statusRoute := ndndRoute{
				FaceID: route.FaceId,
				Origin: mgmt.RouteOrigin(route.Origin).String(),
				Cost:   route.Cost,
				Flags:  strings.Join(flags, ", "),
			}
			if expiration, ok := route.ExpirationPeriod.Get(); ok {
				statusRoute.ExpirationMillis = &expiration
			}
			entry.Routes = append(entry.Routes, statusRoute)
		}
		report.RIB.Entries = append(report.RIB.Entries, entry)
	}
	return nil
}
func (t *Tool) populateContentStore(report *ndndStatusReport) error {
	data, err := t.fetchStatusDataset(enc.Name{enc.NewGenericComponent("cs"), enc.NewGenericComponent("info")})
	if err != nil {
		return fmt.Errorf("fetch content store: %w", err)
	}
	status, err := mgmt.ParseCsInfoMsg(enc.NewWireView(data), true)
	if err != nil {
		return fmt.Errorf("parse content store: %w", err)
	}
	report.ContentStore, err = ndndContentStoreFromStatus(status)
	if err != nil {
		return err
	}
	return nil
}

func ndndContentStoreFromStatus(status *mgmt.CsInfoMsg) (ndndContentStore, error) {
	if status == nil || status.CsInfo == nil {
		return ndndContentStore{}, errors.New("content-store status has no CsInfo payload")
	}
	info := status.CsInfo
	return ndndContentStore{
		Capacity: info.Capacity,
		Admit:    info.Flags&mgmt.CsEnableAdmit != 0,
		Serve:    info.Flags&mgmt.CsEnableServe != 0,
		Entries:  info.NCsEntries,
		Hits:     info.NHits,
		Misses:   info.NMisses,
	}, nil
}

func (t *Tool) populateStrategies(report *ndndStatusReport) error {
	data, err := t.fetchStatusDataset(enc.Name{enc.NewGenericComponent("strategy-choice"), enc.NewGenericComponent("list")})
	if err != nil {
		return fmt.Errorf("fetch strategies: %w", err)
	}
	status, err := mgmt.ParseStrategyChoiceMsg(enc.NewWireView(data), true)
	if err != nil {
		return fmt.Errorf("parse strategies: %w", err)
	}
	for _, item := range status.StrategyChoices {
		if item.Strategy != nil {
			report.Strategies.Entries = append(report.Strategies.Entries, ndndStrategy{Prefix: item.Name.String(), Strategy: item.Strategy.Name.String()})
		}
	}
	return nil
}

func (t *Tool) populateDVStatus(report *ndndStatusReport) (err error) {
	defer func() {
		if err != nil && t.statusTrust != nil {
			log.Warn(nil, "DV routing dataset unavailable", "router", report.DV.RouterName, "err", err)
		}
	}()
	data, err := t.fetchDataPacket(dvStatusName())
	if err != nil {
		return fmt.Errorf("fetch local DV summary: %w", err)
	}

	status, err := ndndDVStatusFromWire(data.Content())
	if err != nil {
		return fmt.Errorf("parse local DV summary: %w", err)
	}
	report.DV = status
	if t.statusTrust == nil {
		return nil
	}
	router, err := enc.NameFromStr(status.RouterName)
	if err != nil {
		return fmt.Errorf("parse DV router name %q: %w", status.RouterName, err)
	}
	if len(router) == 0 {
		return fmt.Errorf("local DV summary contains an empty router name")
	}
	wire, err := t.fetchObjectDataset(dvconfig.StatusDatasetPrefix(router), false, t.statusTrust)
	if err != nil {
		return fmt.Errorf("fetch or validate DV routing dataset: %w", err)
	}
	status, err = ndndDVStatusFromDataset(wire, router)
	if err != nil {
		return fmt.Errorf("parse DV routing dataset: %w", err)
	}
	report.DV = status
	return nil
}

func ndndDVStatusFromDataset(wire enc.Wire, router enc.Name) (ndndDVStatus, error) {
	dataset, err := dvtlv.ParseRoutingStatus(enc.NewWireView(wire), false)
	if err != nil {
		return ndndDVStatus{}, err
	}
	if dataset.Status == nil || dataset.Status.RouterName == nil || !dataset.Status.RouterName.Name.Equal(router) {
		return ndndDVStatus{}, fmt.Errorf("routing dataset does not identify the requested router")
	}
	status := ndndDVStatusFromStatus(dataset.Status)
	status.DatasetAvailable = true
	for _, item := range dataset.Routers {
		if item.Cost >= dvconfig.CostInfinity {
			return ndndDVStatus{}, fmt.Errorf("router cost %d for %s must be less than %d", item.Cost, item.Name, dvconfig.CostInfinity)
		}
		route := ndndDVRouter{Name: item.Name.String(), Cost: item.Cost}
		if item.NextHop != nil {
			route.NextHop = item.NextHop.Name.String()
		}
		for _, prefix := range item.Prefixes {
			if prefix.Cost >= dvconfig.CostPfxInfinity {
				return ndndDVStatus{}, fmt.Errorf("prefix cost %d for %s must be less than %d", prefix.Cost, prefix.Name, dvconfig.CostPfxInfinity)
			}
			route.Prefixes = append(route.Prefixes, ndndDVPrefix{Name: prefix.Name.String(), Cost: prefix.Cost})
		}
		status.Routers = append(status.Routers, route)
	}
	return status, nil
}

func dvStatusName() enc.Name {
	return enc.Name{
		enc.LOCALHOST,
		enc.NewGenericComponent("nlsr"),
		enc.NewGenericComponent("status"),
	}
}

func ndndDVStatusFromWire(data enc.Wire) (ndndDVStatus, error) {
	status, err := dvtlv.ParseStatus(enc.NewWireView(data), true)
	if err != nil {
		return ndndDVStatus{}, err
	}
	return ndndDVStatusFromStatus(status), nil
}

func ndndDVStatusFromStatus(status *dvtlv.Status) ndndDVStatus {
	dvStatus := ndndDVStatus{
		Available:   true,
		Version:     status.Version,
		NRibEntries: status.NRibEntries,
		NNeighbors:  status.NNeighbors,
		NFibEntries: status.NFibEntries,
	}
	if status.NetworkName != nil {
		dvStatus.NetworkName = status.NetworkName.Name.String()
	}
	if status.RouterName != nil {
		dvStatus.RouterName = status.RouterName.Name.String()
	}
	return dvStatus
}

func faceScopeName(value uint64) string {
	switch value {
	case mgmt.FaceScopeLocal:
		return "local"
	case mgmt.FaceScopeNonLocal:
		return "non-local"
	default:
		return "unknown"
	}
}

func faceLinkTypeName(value uint64) string {
	switch value {
	case mgmt.FaceLinkPointToPoint:
		return "point-to-point"
	case mgmt.FaceLinkMultiAccess:
		return "multi-access"
	case mgmt.FaceLinkAdHoc:
		return "ad-hoc"
	default:
		return "unknown"
	}
}

func faceFlagsName(value uint64) string {
	flags := make([]string, 0, 3)
	if value&mgmt.FaceFlagLocalFieldsEnabled != 0 {
		flags = append(flags, "local-fields")
	}
	if value&mgmt.FaceFlagLpReliabilityEnabled != 0 {
		flags = append(flags, "lp-reliability")
	}
	if value&mgmt.FaceFlagCongestionMarkingEnabled != 0 {
		flags = append(flags, "congestion-marking")
	}
	return strings.Join(flags, ", ")
}
