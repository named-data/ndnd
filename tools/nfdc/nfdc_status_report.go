package nfdc

import (
	"encoding/xml"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	dvtlv "github.com/named-data/ndnd/dv/tlv"
	enc "github.com/named-data/ndnd/std/encoding"
	mgmt "github.com/named-data/ndnd/std/ndn/mgmt_2022"
	"github.com/spf13/cobra"
)

type ndndStatusReport struct {
	XMLName      xml.Name          `xml:"ndndStatus"`
	GeneratedAt  string            `xml:"generatedAt,attr"`
	General      ndndGeneralStatus `xml:"general"`
	Faces        ndndFaces         `xml:"faces"`
	FIB          ndndFIB           `xml:"fib"`
	RIB          ndndRIB           `xml:"rib"`
	ContentStore ndndContentStore  `xml:"contentStore"`
	Strategies   ndndStrategies    `xml:"strategies"`
	DV           ndndDVStatus      `xml:"dv"`
}

type ndndGeneralStatus struct {
	Version               string `xml:"version"`
	StartTime             string `xml:"startTime"`
	CurrentTime           string `xml:"currentTime"`
	Uptime                string `xml:"uptime"`
	NFIBEntries           uint64 `xml:"nFibEntries"`
	NPITEntries           uint64 `xml:"nPitEntries"`
	NCsEntries            uint64 `xml:"nCsEntries"`
	NInInterests          uint64 `xml:"nInInterests"`
	NOutInterests         uint64 `xml:"nOutInterests"`
	NInData               uint64 `xml:"nInData"`
	NOutData              uint64 `xml:"nOutData"`
	NSatisfiedInterests   uint64 `xml:"nSatisfiedInterests"`
	NUnsatisfiedInterests uint64 `xml:"nUnsatisfiedInterests"`
}

type ndndFace struct {
	ID                         uint64  `xml:"faceId,attr"`
	RemoteURI                  string  `xml:"remoteUri"`
	LocalURI                   string  `xml:"localUri"`
	Scope                      string  `xml:"scope"`
	Persistency                string  `xml:"persistency"`
	LinkType                   string  `xml:"linkType"`
	MTU                        *uint64 `xml:"mtu,omitempty"`
	BaseCongestionMarkInterval *uint64 `xml:"baseCongestionMarkInterval,omitempty"`
	DefaultCongestionThreshold *uint64 `xml:"defaultCongestionThreshold,omitempty"`
	Flags                      string  `xml:"flags"`
	ExpirationMilliseconds     *uint64 `xml:"expirationMilliseconds,omitempty"`
	NInInterests               uint64  `xml:"nInInterests"`
	NInData                    uint64  `xml:"nInData"`
	NInBytes                   uint64  `xml:"nInBytes"`
	NOutInterests              uint64  `xml:"nOutInterests"`
	NOutData                   uint64  `xml:"nOutData"`
	NOutBytes                  uint64  `xml:"nOutBytes"`
}

type ndndDVStatus struct {
	Available   bool   `xml:"available,attr"`
	Version     string `xml:"version"`
	NetworkName string `xml:"networkName"`
	RouterName  string `xml:"routerName"`
	NRibEntries uint64 `xml:"nRibEntries"`
	NNeighbors  uint64 `xml:"nNeighbors"`
	NFibEntries uint64 `xml:"nFibEntries"`
}

type ndndFaces struct {
	Entries []ndndFace `xml:"face"`
}

type ndndFIBEntry struct {
	Prefix   string        `xml:"prefix,attr"`
	NextHops []ndndNextHop `xml:"nextHop"`
}

type ndndFIB struct {
	Entries []ndndFIBEntry `xml:"entry"`
}

type ndndRIBEntry struct {
	Prefix string      `xml:"prefix,attr"`
	Routes []ndndRoute `xml:"route"`
}

type ndndRIB struct {
	Entries []ndndRIBEntry `xml:"entry"`
}

type ndndNextHop struct {
	FaceID uint64 `xml:"faceId,attr"`
	Cost   uint64 `xml:"cost,attr"`
}

type ndndRoute struct {
	FaceID           uint64  `xml:"faceId,attr"`
	Origin           string  `xml:"origin,attr"`
	Cost             uint64  `xml:"cost,attr"`
	Flags            string  `xml:"flags,attr"`
	ExpirationMillis *uint64 `xml:"expirationMilliseconds,attr,omitempty"`
}

type ndndContentStore struct {
	Capacity uint64 `xml:"capacity,attr"`
	Admit    bool   `xml:"admit,attr"`
	Serve    bool   `xml:"serve,attr"`
	Entries  uint64 `xml:"entries,attr"`
	Hits     uint64 `xml:"hits,attr"`
	Misses   uint64 `xml:"misses,attr"`
}

type ndndStrategy struct {
	Prefix   string `xml:"prefix,attr"`
	Strategy string `xml:"strategy,attr"`
}

type ndndStrategies struct {
	Entries []ndndStrategy `xml:"strategy"`
}

func (t *Tool) RunStatusReport(_ *cobra.Command, _ []string) error {
	t.Start()
	defer t.Stop()

	report, err := t.buildNdndStatusReport()
	if err != nil {
		return fmt.Errorf("unable to build NDNd status report: %w", err)
	}
	encoded, err := encodeNdndStatusXML(report)
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
	output := []byte(xml.Header)
	output = append(output, "<?xml-stylesheet type=\"text/xsl\" href=\"ndnd-status.xsl\"?>\n"...)
	output = append(output, encoded...)
	return output, nil
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
	t.populateDVStatus(report)
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

func (t *Tool) populateDVStatus(report *ndndStatusReport) {
	data, err := t.fetchDataPacket(dvStatusName())
	if err != nil {
		return
	}

	status, err := ndndDVStatusFromWire(data.Content())
	if err == nil {
		report.DV = status
	}
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
	return dvStatus, nil
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
