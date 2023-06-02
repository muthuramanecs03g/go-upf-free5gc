package forwarder

import (
	"fmt"
	"os"

	"github.com/dropbox/goebpf"
	"github.com/vishvananda/netlink"
)

var elf string = "./bin/gtp5g_buf_kern.elf"
var programName string = "gtp5g_buf_prog"

type xdpInfo struct {
	redirectLinkIdx int
	prog            goebpf.Program
	flow_seid       goebpf.Map
	seid_nip        goebpf.Map
	seid_idpkt      goebpf.Map
}

var ifToXdp map[string]xdpInfo

func init() {
	ifToXdp = make(map[string]xdpInfo, 0)
}

func fatalError(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}

func printBpfInfo(bpf goebpf.System) {
	fmt.Println("Maps:")
	for _, item := range bpf.GetMaps() {
		fmt.Printf("\t%s: %v, Fd %v\n", item.GetName(), item.GetType(), item.GetFd())
	}
	fmt.Println("\nPrograms:")
	for _, prog := range bpf.GetPrograms() {
		fmt.Printf("\t%s: %v, size %d, license \"%s\"\n",
			prog.GetName(), prog.GetType(), prog.GetSize(), prog.GetLicense(),
		)

	}
	fmt.Println()
}

func getXdpInfo(ifname string) *xdpInfo {
	xdp, ok := ifToXdp[ifname]
	if ok {
		return &xdp
	}

	return nil
}

func Gtp5gBpfAttach(ifname, redirIfname string) (int, error) {
	if ifname == "" {
		return -1, fmt.Errorf("Empty interface name")
	}
	fmt.Printf("Interfae name: %s\n", ifname)
	bpf := goebpf.NewDefaultEbpfSystem()
	err := bpf.LoadElf(elf)
	if err != nil {
		fatalError("LoadElf() failed: %v", err)
	}
	printBpfInfo(bpf)

	// Find flow_seid eBPF map
	flow_seid := bpf.GetMapByName("flow_seid")
	if flow_seid == nil {
		fatalError("eBPF map 'flow_seid' not found")
	}

	// Find seid_nip eBPF map
	seid_nip := bpf.GetMapByName("seid_nip")
	if seid_nip == nil {
		fatalError("eBPF map 'seid_nip' not found")
	}

	// Find seid_idpkt eBPF map
	seid_idpkt := bpf.GetMapByName("seid_idpkt")
	if seid_idpkt == nil {
		fatalError("eBPF map 'seid_idpkt' not found")
	}

	// Program name matches function name in xdp.c:
	//      int packet_count(struct xdp_md *ctx)
	xdp := bpf.GetProgramByName(programName)
	if xdp == nil {
		fatalError("Program '%s' not found.", programName)
	}

	// Load XDP program into kernel
	err = xdp.Load()
	if err != nil {
		fatalError("xdp.Load(): %v", err)
	}

	// Attach to interface
	err = xdp.Attach(ifname)
	if err != nil {
		fatalError("xdp.Attach(): %v", err)
	}

	ifData, err := netlink.LinkByName(redirIfname)
	if err != nil {
		fmt.Printf("Could not find link %s!\n", redirIfname)
		return -1, err
	}
	redirectLinkIdx := ifData.Attrs().Index

	info := xdpInfo{
		redirectLinkIdx: redirectLinkIdx,
		prog:            xdp,
		flow_seid:       flow_seid,
		seid_nip:        seid_nip,
		seid_idpkt:      seid_idpkt,
	}
	ifToXdp[ifname] = info

	return 0, nil
}

func Gtp5gBpfCreateBar(ifname string, seid, ueip, nip uint32,
	link, pktcount uint16,
) error {
	xdp := getXdpInfo(ifname)
	if xdp == nil {
		return fmt.Errorf("Failed to get xdp info in create bar\n")
	}

	// Fill SEID
	if err := xdp.flow_seid.Insert(ueip, seid); err != nil {
		fmt.Printf("Failed to insert seid %v\n", err)
		return err
	}

	// Fill NVMe IP
	if err := xdp.seid_nip.Insert(seid, nip); err != nil {
		fmt.Printf("Failed to insert NVMe IP %v\n", err)
		return err
	}

	// Fill Re-Direct link index and Packet count
	idpkt := uint32(link)<<16 | uint32(pktcount)
	if err := xdp.seid_idpkt.Insert(seid, idpkt); err != nil {
		fmt.Printf("Failed to insert link index and packet count %v\n", err)
		return err
	}

	return nil
}

func Gtp5gBpfUpdateBar(ifname string, seid, ueip, nip uint32,
	link, pktcount uint16,
) error {
	xdp := getXdpInfo(ifname)
	if xdp == nil {
		return fmt.Errorf("Failed to get xdp info in update bar\n")
	}

	// Fill SEID
	if err := xdp.flow_seid.Update(ueip, seid); err != nil {
		fmt.Printf("Failed to update seid %v\n", err)
		return err
	}

	// Fill NVMe IP
	if err := xdp.seid_nip.Update(seid, nip); err != nil {
		fmt.Printf("Failed to update NVMe IP %v\n", err)
		return err
	}

	// Fill Re-Direct link index and Packet count
	idpkt := uint32(link)<<16 | uint32(pktcount)
	if err := xdp.seid_idpkt.Update(seid, idpkt); err != nil {
		fmt.Printf("Failed to update link index and packet count %v\n", err)
		return err
	}

	return nil
}

func Gtp5gBpfRemoveBar(ifname string, seid, ueip uint32) error {
	xdp := getXdpInfo(ifname)
	if xdp == nil {
		return fmt.Errorf("Failed to get xdp info in remove bar\n")
	}

	if err := xdp.flow_seid.Delete(ueip); err != nil {
		fmt.Printf("Failed to delete seid %v\n", err)
		return err
	}

	if err := xdp.seid_nip.Delete(seid); err != nil {
		fmt.Printf("Failed to delete NVMe IP %v\n", err)
		return err
	}

	if err := xdp.seid_idpkt.Delete(seid); err != nil {
		fmt.Printf("Failed to delete link index and packet count %v\n", err)
		return err
	}

	return nil
}

func Gtp5gBpfGetPktCount(ifname string, seid uint32) (uint16, error) {
	xdp := getXdpInfo(ifname)
	if xdp == nil {
		return 0, fmt.Errorf("Failed to get xdp info in get pkt count\n")
	}

	idpkt, err := xdp.seid_idpkt.LookupInt(seid)
	if err != nil {
		return 0, err
	}

	pktCount := uint32(idpkt) & uint32(0x00ff)
	return uint16(pktCount), nil
}

func Gtp5gBpfDetach(ifname string) (int, error) {
	xdp, ok := ifToXdp[ifname]
	if ok {
		xdp.prog.Detach()
		return 0, nil
	}
	return -1, fmt.Errorf("Invalid ifname")
}
