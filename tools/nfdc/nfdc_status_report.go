package nfdc

import (
	"encoding/xml"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	specDV "github.com/named-data/ndnd/dv/tlv"
	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/ndn"
	mgmt "github.com/named-data/ndnd/std/ndn/mgmt_2022"
	"github.com/named-data/ndnd/std/types/optional"
	"github.com/named-data/ndnd/std/utils"
	"github.com/spf13/cobra"
)

type ndndStatusReport struct {
	XMLName      xml.Name                  `xml:"ndndStatus"`
	GeneratedAt  string                    `xml:"generatedAt,attr"`
	DVState      string                    `xml:"dvState,attr"`
	Polyfill     *ndndStatusPolyfillScript `xml:"script,omitempty"`
	General      ndndGeneralStatus         `xml:"general"`
	Channels     ndndChannels              `xml:"channels"`
	Faces        ndndFaces                 `xml:"faces"`
	FIB          ndndFIB                   `xml:"fib"`
	RIB          ndndRIB                   `xml:"rib"`
	ContentStore ndndContentStore          `xml:"contentStore"`
	Strategies   ndndStrategies            `xml:"strategies"`
	BIFT         ndndBIFT                  `xml:"bift"`
	PET          ndndPET                   `xml:"pet"`
	DV           *ndndDVStatus             `xml:"dv,omitempty"`
}

type ndndStatusPolyfillScript struct {
	XMLName xml.Name `xml:"http://www.w3.org/1999/xhtml script"`
	Src     string   `xml:"src,attr"`
}

type ndndGeneralStatus struct {
	Version               string `xml:"version"`
	StartTime             string `xml:"startTime"`
	CurrentTime           string `xml:"currentTime"`
	Uptime                string `xml:"uptime"`
	NFIBEntries           uint64 `xml:"nFibEntries"`
	NPITEntries           uint64 `xml:"nPitEntries"`
	NContentStoreEntries  uint64 `xml:"nContentStoreEntries"`
	NInInterests          uint64 `xml:"nInInterests"`
	NOutInterests         uint64 `xml:"nOutInterests"`
	NInData               uint64 `xml:"nInData"`
	NOutData              uint64 `xml:"nOutData"`
	NSatisfiedInterests   uint64 `xml:"nSatisfiedInterests"`
	NUnsatisfiedInterests uint64 `xml:"nUnsatisfiedInterests"`
}

type ndndChannel struct {
	LocalURI string `xml:"localUri"`
}

type ndndChannels struct {
	Entries []ndndChannel `xml:"channel"`
}

type ndndFace struct {
	ID                     uint64  `xml:"faceId,attr"`
	RemoteURI              string  `xml:"remoteUri"`
	LocalURI               string  `xml:"localUri"`
	Scope                  string  `xml:"scope"`
	Persistency            string  `xml:"persistency"`
	LinkType               string  `xml:"linkType"`
	MTU                    *uint64 `xml:"mtu,omitempty"`
	Flags                  string  `xml:"flags"`
	ExpirationMilliseconds *uint64 `xml:"expirationMilliseconds,omitempty"`
	NInInterests           uint64  `xml:"nInInterests"`
	NInData                uint64  `xml:"nInData"`
	NInBytes               uint64  `xml:"nInBytes"`
	NOutInterests          uint64  `xml:"nOutInterests"`
	NOutData               uint64  `xml:"nOutData"`
	NOutBytes              uint64  `xml:"nOutBytes"`
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

type ndndBIFT struct {
	Version   uint64             `xml:"version,attr"`
	BierIndex *uint64            `xml:"bierIndex,attr,omitempty"`
	Entries   []ndndBIFTEntry    `xml:"entry"`
	Neighbors []ndndBIFTNeighbor `xml:"neighbor"`
}

type ndndBIFTEntry struct {
	BFRID      uint64   `xml:"bfrId,attr"`
	RouterName string   `xml:"routerName,attr"`
	NextHops   []uint64 `xml:"nextHop"`
	FBMBits    []uint64 `xml:"forwardingBit"`
}

type ndndBIFTNeighbor struct {
	FaceID  uint64   `xml:"faceId,attr"`
	FBMBits []uint64 `xml:"forwardingBit"`
}

type ndndPETEntry struct {
	Prefix    string        `xml:"prefix,attr"`
	Multicast bool          `xml:"multicast,attr"`
	Egresses  []string      `xml:"egress"`
	NextHops  []ndndNextHop `xml:"nextHop"`
}

type ndndPET struct {
	Entries []ndndPETEntry `xml:"entry"`
}

type ndndDVStatus struct {
	Version         string              `xml:"version,attr"`
	NetworkName     string              `xml:"networkName,attr"`
	RouterName      string              `xml:"routerName,attr"`
	RIBEntries      uint64              `xml:"ribEntries,attr"`
	Neighbors       uint64              `xml:"neighbors,attr"`
	FIBEntries      uint64              `xml:"fibEntries,attr"`
	PSDEntries      uint64              `xml:"prefixStateEntries,attr"`
	PrefixListState string              `xml:"prefixListState,attr"`
	Prefixes        []ndndDVPrefixEntry `xml:"prefixState>entry"`
}

type ndndDVPrefixEntry struct {
	Prefix    string          `xml:"prefix,attr"`
	Router    string          `xml:"router,attr"`
	Multicast bool            `xml:"multicast,attr"`
	Validity  *ndndDVValidity `xml:"validity,omitempty"`
	NextHops  []ndndNextHop   `xml:"nextHop"`
}

type ndndDVValidity struct {
	NotBefore string `xml:"notBefore,omitempty"`
	NotAfter  string `xml:"notAfter,omitempty"`
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
	output := make([]byte, 0, len(xml.Header)+len(encoded)+96)
	output = append(output, xml.Header...)
	output = append(output, "<?xml-stylesheet type=\"text/xsl\" href=\"ndnd-status.xsl\"?>\n"...)
	output = append(output, encoded...)
	return output, nil
}

func encodeNdndStatusPageXML(report *ndndStatusReport) ([]byte, error) {
	pageReport := *report
	pageReport.Polyfill = &ndndStatusPolyfillScript{Src: "ndnd-status-polyfill.min.js"}
	return encodeNdndStatusXML(&pageReport)
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
		DVState:     "unavailable",
		General: ndndGeneralStatus{
			Version:               general.NfdVersion,
			StartTime:             time.Unix(0, int64(general.StartTimestamp)).UTC().Format(time.RFC3339),
			CurrentTime:           time.Unix(0, int64(general.CurrentTimestamp)).UTC().Format(time.RFC3339),
			Uptime:                (general.CurrentTimestamp - general.StartTimestamp).String(),
			NFIBEntries:           general.NFibEntries,
			NPITEntries:           general.NPitEntries,
			NContentStoreEntries:  general.NCsEntries,
			NInInterests:          general.NInInterests,
			NOutInterests:         general.NOutInterests,
			NInData:               general.NInData,
			NOutData:              general.NOutData,
			NSatisfiedInterests:   general.NSatisfiedInterests,
			NUnsatisfiedInterests: general.NUnsatisfiedInterests,
		},
	}

	if err := t.populateChannels(report); err != nil {
		return nil, err
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
	if err := t.populateBIFT(report); err != nil {
		return nil, err
	}
	if err := t.populatePET(report); err != nil {
		return nil, err
	}
	if dvStatus, err := t.fetchDVStatus(); err == nil {
		report.DV = dvStatus
		report.DVState = "available"
		if err := t.populateDVPrefixState(dvStatus); err != nil {
			dvStatus.PrefixListState = "unavailable"
		}
	}

	return report, nil
}

func (t *Tool) populateChannels(report *ndndStatusReport) error {
	data, err := t.fetchStatusDataset(enc.Name{enc.NewGenericComponent("faces"), enc.NewGenericComponent("channels")})
	if err != nil {
		return fmt.Errorf("fetch channels: %w", err)
	}
	status, err := mgmt.ParseChannelStatusMsg(enc.NewWireView(data), true)
	if err != nil {
		return fmt.Errorf("parse channels: %w", err)
	}
	for _, channel := range status.Vals {
		report.Channels.Entries = append(report.Channels.Entries, ndndChannel{LocalURI: channel.LocalUri})
	}
	return nil
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

func (t *Tool) populateBIFT(report *ndndStatusReport) error {
	data, err := t.fetchStatusDataset(enc.Name{enc.NewGenericComponent("bift"), enc.NewGenericComponent("list")})
	if err != nil {
		return fmt.Errorf("fetch BIFT: %w", err)
	}
	status, err := mgmt.ParseBiftStatusMsg(enc.NewWireView(data), false)
	if err != nil {
		return fmt.Errorf("parse BIFT: %w", err)
	}
	report.BIFT, err = ndndBIFTFromStatus(status)
	if err != nil {
		return fmt.Errorf("map BIFT: %w", err)
	}
	return nil
}

func ndndBIFTFromStatus(status *mgmt.BiftStatusMsg) (ndndBIFT, error) {
	if status == nil {
		return ndndBIFT{}, errors.New("BIFT status is empty")
	}
	if status.Version != mgmt.BiftStatusVersion {
		return ndndBIFT{}, fmt.Errorf("unsupported BIFT status version %d", status.Version)
	}
	report := ndndBIFT{
		Version:   status.Version,
		Entries:   make([]ndndBIFTEntry, 0, len(status.Entries)),
		Neighbors: make([]ndndBIFTNeighbor, 0, len(status.Neighbors)),
	}
	if bierIndex, ok := status.BierIndex.Get(); ok {
		report.BierIndex = &bierIndex
	}
	for _, entry := range status.Entries {
		report.Entries = append(report.Entries, ndndBIFTEntry{
			BFRID:      entry.BfrId,
			RouterName: entry.RouterName.String(),
			NextHops:   append([]uint64(nil), entry.NextHops...),
			FBMBits:    append([]uint64(nil), entry.FbmBits...),
		})
	}
	for _, neighbor := range status.Neighbors {
		report.Neighbors = append(report.Neighbors, ndndBIFTNeighbor{
			FaceID:  neighbor.FaceId,
			FBMBits: append([]uint64(nil), neighbor.FbmBits...),
		})
	}
	return report, nil
}

func (t *Tool) populatePET(report *ndndStatusReport) error {
	data, err := t.fetchStatusDataset(enc.Name{enc.NewGenericComponent("pet"), enc.NewGenericComponent("list")})
	if err != nil {
		return fmt.Errorf("fetch PET: %w", err)
	}
	status, err := mgmt.ParsePetStatus(enc.NewWireView(data), true)
	if err != nil {
		return fmt.Errorf("parse PET: %w", err)
	}
	for _, item := range status.Entries {
		entry := ndndPETEntry{Prefix: item.Name.String(), Multicast: item.Multicast}
		for _, egress := range item.EgressRecords {
			entry.Egresses = append(entry.Egresses, egress.Name.String())
		}
		for _, nextHop := range item.NextHopRecords {
			entry.NextHops = append(entry.NextHops, ndndNextHop{FaceID: nextHop.FaceId, Cost: nextHop.Cost})
		}
		report.PET.Entries = append(report.PET.Entries, entry)
	}
	return nil
}

func (t *Tool) fetchDVStatus() (*ndndDVStatus, error) {
	name := enc.Name{enc.LOCALHOST, enc.NewGenericComponent("dv"), enc.NewGenericComponent("status")}
	data, err := t.fetchLocalData(name)
	if err != nil {
		return nil, err
	}
	status, err := specDV.ParseStatus(enc.NewWireView(data), false)
	if err != nil {
		return nil, err
	}
	result := &ndndDVStatus{
		Version:    status.Version,
		RIBEntries: status.NRibEntries,
		Neighbors:  status.NNeighbors,
		FIBEntries: status.NFibEntries,
		PSDEntries: status.NPsdEntries,
	}
	if status.NetworkName != nil {
		result.NetworkName = status.NetworkName.Name.String()
	}
	if status.RouterName != nil {
		result.RouterName = status.RouterName.Name.String()
	}
	return result, nil
}

func (t *Tool) populateDVPrefixState(status *ndndDVStatus) error {
	name := enc.Name{
		enc.LOCALHOST,
		enc.NewGenericComponent("dv"),
		enc.NewGenericComponent("prefix"),
		enc.NewGenericComponent("list"),
	}
	data, err := t.fetchLocalData(name)
	if err != nil {
		return err
	}
	prefixStatus, err := specDV.ParsePrefixStateStatus(enc.NewWireView(data), false)
	if err != nil {
		return err
	}
	entries, err := ndndDVPrefixEntriesFromStatus(prefixStatus)
	if err != nil {
		return err
	}
	status.PrefixListState = "available"
	status.Prefixes = entries
	return nil
}

func ndndDVPrefixEntriesFromStatus(prefixStatus *specDV.PrefixStateStatus) ([]ndndDVPrefixEntry, error) {
	if prefixStatus == nil {
		return nil, errors.New("DV prefix-state status is empty")
	}
	if prefixStatus.Version != specDV.PrefixStateStatusVersion {
		return nil, fmt.Errorf("unsupported DV prefix-state version %d", prefixStatus.Version)
	}
	entries := make([]ndndDVPrefixEntry, 0, len(prefixStatus.Entries))
	for _, item := range prefixStatus.Entries {
		entry := ndndDVPrefixEntry{
			Prefix:    item.Name.String(),
			Router:    item.Router.String(),
			Multicast: item.Multicast,
			NextHops:  make([]ndndNextHop, 0, len(item.NextHops)),
		}
		if item.ValidityPeriod != nil {
			entry.Validity = &ndndDVValidity{
				NotBefore: item.ValidityPeriod.NotBefore,
				NotAfter:  item.ValidityPeriod.NotAfter,
			}
		}
		for _, nextHop := range item.NextHops {
			entry.NextHops = append(entry.NextHops, ndndNextHop{FaceID: nextHop.Face, Cost: nextHop.Cost})
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

func (t *Tool) fetchLocalData(name enc.Name) (enc.Wire, error) {
	cfg := &ndn.InterestConfig{
		MustBeFresh: true,
		Lifetime:    optional.Some(time.Second),
		Nonce:       utils.ConvertNonce(t.engine.Timer().Nonce()),
	}
	interest, err := t.engine.Spec().MakeInterest(name, cfg, nil, nil)
	if err != nil {
		return nil, err
	}
	responses := make(chan ndn.ExpressCallbackArgs, 1)
	if err := t.engine.Express(interest, func(args ndn.ExpressCallbackArgs) { responses <- args }); err != nil {
		return nil, err
	}
	select {
	case response := <-responses:
		if response.Result != ndn.InterestResultData {
			return nil, fmt.Errorf("management query %s failed: %s", name, response.Result)
		}
		return response.Data.Content(), nil
	case <-time.After(1200 * time.Millisecond):
		return nil, fmt.Errorf("management query %s timed out", name)
	}
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
