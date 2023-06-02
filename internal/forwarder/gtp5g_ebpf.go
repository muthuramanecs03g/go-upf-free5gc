package forwarder

import (
	"fmt"
	"os"

	"github.com/dropbox/goebpf"
)

var elf string = "./bin/gtp5g_buf_kern.elf"
var programName string = "gtp5g_buf_prog"

type xdpInfo struct {
	prog       goebpf.Program
	flow_seid  goebpf.Map
	seid_nip   goebpf.Map
	seid_idpkt goebpf.Map
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

func Gtp5gBpfAttach(ifname string) (int, error) {
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

	info := xdpInfo{
		prog:       xdp,
		flow_seid:  flow_seid,
		seid_nip:   seid_nip,
		seid_idpkt: seid_idpkt,
	}
	ifToXdp[ifname] = info

	return 0, nil
}

func Gtp5gBpfDetach(ifname string) (int, error) {
	xdp, ok := ifToXdp[ifname]
	if ok {
		xdp.prog.Detach()
		return 0, nil
	}
	return -1, fmt.Errorf("Invalid ifname")
}
