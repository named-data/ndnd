package nfdc

import (
	"fmt"
	"os"
	"strings"
	"time"

	enc "github.com/named-data/ndnd/std/encoding"
	mgmt "github.com/named-data/ndnd/std/ndn/mgmt_2022"
)

func (n *Nfdc) ExecFaceList(args []string) {
	suffix := enc.Name{
		enc.NewStringComponent(enc.TypeGenericNameComponent, "faces"),
		enc.NewStringComponent(enc.TypeGenericNameComponent, "list"),
	}

	data, err := n.fetchStatusDataset(suffix)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error fetching status dataset: %+v\n", err)
		return
	}

	status, err := mgmt.ParseFaceStatusMsg(enc.NewBufferReader(data), true)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing face status: %+v\n", err)
		return
	}

	for _, entry := range status.Vals {
		info := []string{}

		info = append(info, fmt.Sprintf("faceid=%d", entry.FaceId))
		info = append(info, fmt.Sprintf("remote=%s", entry.Uri))
		info = append(info, fmt.Sprintf("local=%s", entry.LocalUri))

		congestion := []string{}
		if entry.BaseCongestionMarkInterval != nil {
			congestion = append(congestion, fmt.Sprintf("base-marking-interval=%s", time.Duration(*entry.BaseCongestionMarkInterval)*time.Nanosecond))
		}
		if entry.DefaultCongestionThreshold != nil {
			congestion = append(congestion, fmt.Sprintf("default-threshold=%dB", *entry.DefaultCongestionThreshold))
		}
		if len(congestion) > 0 {
			info = append(info, fmt.Sprintf("congestion={%s}", strings.Join(congestion, " ")))
		}

		if entry.Mtu != nil {
			info = append(info, fmt.Sprintf("mtu=%dB", *entry.Mtu))
		}

		info = append(info, fmt.Sprintf("counters={in={%di %dd %dn %dB} out={%di %dd %dn %dB}}",
			entry.NInInterests, entry.NInData, entry.NInNacks, entry.NInBytes,
			entry.NOutInterests, entry.NOutData, entry.NOutNacks, entry.NOutBytes))

		flags := []string{}
		flags = append(flags, strings.ToLower(mgmt.Persistency(entry.FacePersistency).String()))
		info = append(info, fmt.Sprintf("flags={%s}", strings.Join(flags, " ")))

		fmt.Printf("%s\n", strings.Join(info, " "))
	}
}
