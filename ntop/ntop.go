package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/olekukonko/tablewriter"
)

var InterruptsPath = "/proc/interrupts"
var SoftIRQPath = "/proc/softirqs"
var NetStatPath = "/proc/net/softnet_stat"
var SysfsPath = "/sys/class/net"
var SnmpPath = "/proc/net/snmp"
var StatPath = "/proc/stat"

type Param struct {
	Name  string
	Value uint64
}

type Interrupt struct {
	Name        string
	Counts      []uint64
	Description string
}

type Interrupts struct {
	CPUs       []string
	Interrupts []Interrupt
	Total      []uint64
}

type SoftIRQ struct {
	CPU   string
	NetRX uint64
	NetTX uint64
}

type NetStat struct {
	CPU          string
	Processed    uint64
	Dropped      uint64
	TimeSqueeze  uint64
	CpuCollision uint64
	ReceivedRps  uint64
}

type SysfsNetStat struct {
	Dev       string
	RXpackets uint64
	RXmbits   uint64
	RXerrors  uint64
	Dropped   uint64
	Missed    uint64
	Fifo      uint64
	Length    uint64
	Overrun   uint64
	CRC       uint64
	Frame     uint64
	TXpackets uint64
	TXmbits   uint64
	TXerrors  uint64
}

type CPUStat struct {
	CPU     string
	User    float64
	Nice    float64
	System  float64
	Idle    float64
	IOwait  float64
	IRQ     float64
	SoftIRQ float64
}

type SNMP struct {
	Protocol string
	Params   []Param
}

const RESET = "\033[0m"

const (
	BLACK = iota
	RED
	GREEN
	YELLOW
	BLUE
	MAGENTA
	CYAN
	WHITE
)

func init() {

}

func getColor(line string, code int) string {
	return fmt.Sprintf("%s%s%s", fmt.Sprintf("\033[3%dm", code), line, RESET)
}

func colorize(value, from uint64) string {
	result := strconv.FormatUint(value, 10)

	if from > 0 && value >= from {
		return getColor(result, RED)
	}

	return result
}

func ReadFile(path string) ([]string, error) {
	data, err := ioutil.ReadFile(path)

	if err != nil {
		return nil, err
	}

	lines := strings.Split(string(data), "\n")

	return lines, nil
}

func uintArr2Str(arr []uint64) []string {
	strArr := make([]string, len(arr))
	for i, v := range arr {
		strArr[i] = strconv.FormatUint(v, 10)
	}

	return strArr
}

func strArr2Uint(fields []string) []uint64 {
	result := make([]uint64, len(fields))
	for i, val := range fields {
		if n, err := strconv.ParseUint(val, 10, 64); err == nil {
			result[i] = n
		} else {
			continue
		}
	}
	return result
}

func uintArrSum(arr []uint64) uint64 {
	var sum uint64
	for i := 0; i < len(arr); i++ {
		sum = sum + arr[i]
	}

	return sum
}

func diffUintArr(a, b []uint64) []uint64 {
	var diff []uint64

	if len(a) == len(b) {
		diff = make([]uint64, len(a))
		for i := 0; i < len(diff); i++ {
			diff[i] = a[i] - b[i]
		}
	} else {
		diff = a
	}

	return diff
}

func CaclPercentage(a []uint64) []float64 {
	result := make([]float64, len(a))
	total := uintArrSum(a)
	if total == 0 {
		return result
	}
	for i, val := range a {
		result[i] = float64(val) / float64(total) * 100
	}
	return result
}

func diffInterrupts(a, b *Interrupts) *Interrupts {
	total := diffUintArr(a.Total, b.Total)
	var interrupts []Interrupt

	if len(a.Interrupts) == len(b.Interrupts) {
		interrupts = make([]Interrupt, 0, len(a.Interrupts))
		for i := 0; i < len(a.Interrupts); i++ {
			if a.Interrupts[i].Name == b.Interrupts[i].Name {
				counts := diffUintArr(a.Interrupts[i].Counts, b.Interrupts[i].Counts)
				if uintArrSum(counts) > 0 || true {
					interrupts = append(interrupts, Interrupt{
						Name:        a.Interrupts[i].Name,
						Counts:      counts,
						Description: a.Interrupts[i].Description,
					})
				}
			} else {
				interrupts = append(interrupts, a.Interrupts[i])
			}
		}
	} else {
		interrupts = a.Interrupts
	}

	return &Interrupts{CPUs: a.CPUs, Interrupts: interrupts, Total: total}
}

func diffSoftIRQ(a, b []SoftIRQ) []SoftIRQ {
	var diff []SoftIRQ

	if len(a) == len(b) {
		diff = make([]SoftIRQ, 0, len(a))
		for i := 0; i < len(a); i++ {
			if a[i].CPU == b[i].CPU {
				diff = append(diff, SoftIRQ{
					CPU:   a[i].CPU,
					NetRX: a[i].NetRX - b[i].NetRX,
					NetTX: a[i].NetTX - b[i].NetTX,
				})
			} else {
				diff = append(diff, a[i])
			}
		}
	} else {
		diff = a
	}

	return diff
}

func diffNetStat(a, b []NetStat) []NetStat {
	var diff []NetStat

	if len(a) == len(b) {
		diff = make([]NetStat, 0, len(a))
		for i := 0; i < len(a); i++ {
			if a[i].CPU == b[i].CPU {
				diff = append(diff, NetStat{
					CPU:          a[i].CPU,
					Processed:    a[i].Processed - b[i].Processed,
					Dropped:      a[i].Dropped - b[i].Dropped,
					TimeSqueeze:  a[i].TimeSqueeze - b[i].TimeSqueeze,
					CpuCollision: a[i].CpuCollision - b[i].CpuCollision,
					ReceivedRps:  a[i].ReceivedRps - b[i].ReceivedRps,
				})
			} else {
				diff = append(diff, a[i])
			}
		}
	} else {
		diff = a
	}

	return diff
}

func diffSysfsNetStat(a, b []SysfsNetStat) []SysfsNetStat {
	var diff []SysfsNetStat

	if len(a) == len(b) {
		diff = make([]SysfsNetStat, 0, len(a))
		for i := 0; i < len(a); i++ {
			if a[i].Dev == b[i].Dev {
				diff = append(diff, SysfsNetStat{
					Dev:       a[i].Dev,
					RXpackets: a[i].RXpackets - b[i].RXpackets,
					RXmbits:   a[i].RXmbits - b[i].RXmbits,
					RXerrors:  a[i].RXerrors - b[i].RXerrors,
					Dropped:   a[i].Dropped - b[i].Dropped,
					Missed:    a[i].Missed - b[i].Missed,
					Fifo:      a[i].Fifo - b[i].Fifo,
					Length:    a[i].Length - b[i].Length,
					Overrun:   a[i].Overrun - b[i].Overrun,
					CRC:       a[i].CRC - b[i].CRC,
					Frame:     a[i].Frame - b[i].Frame,
					TXpackets: a[i].TXpackets - b[i].TXpackets,
					TXmbits:   a[i].TXmbits - b[i].TXmbits,
					TXerrors:  a[i].TXerrors - b[i].TXerrors,
				})
			} else {
				diff = append(diff, a[i])
			}
		}
	} else {
		diff = a
	}

	return diff
}

func ReadInterrupts() (*Interrupts, error) {
	lines, err := ReadFile(InterruptsPath)
	if err != nil {
		return nil, err
	}

	cpus := strings.Fields(lines[0])
	lines = append(lines[:0], lines[1:]...)
	interrupts := make([]Interrupt, 0)
	total := make([]uint64, len(cpus))
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		counts := make([]uint64, 0)
		i := 0
		for ; i < len(cpus); i++ {
			if len(fields) <= i+1 {
				break
			}
			count, err := strconv.ParseUint(fields[i+1], 10, 64)
			if err != nil {
				return nil, err
			}
			total[i] += count
			counts = append(counts, count)
		}
		name := strings.TrimSuffix(fields[0], ":")
		//description := strings.Join(fields[i+1:], " ")
		description := fields[len(fields)-1]
		matched, err := regexp.MatchString("(eth|enp|eno|ens|TxRx)", description)
		if matched && err == nil {
			interrupts = append(interrupts, Interrupt{
				Name:        name,
				Counts:      counts,
				Description: description,
			})
		}
	}
	return &Interrupts{CPUs: cpus, Interrupts: interrupts, Total: total}, nil
}

func ReadSoftIRQ() ([]SoftIRQ, error) {
	lines, err := ReadFile(SoftIRQPath)
	if err != nil {
		return nil, err
	}

	cpus := strings.Fields(lines[0])
	lines = append(lines[:0], lines[1:]...)
	softIRQs := make([]SoftIRQ, 0, len(cpus))
	for i, cpu := range cpus {
		softIRQ := SoftIRQ{
			CPU: cpu,
		}
		for _, line := range lines {
			fields := strings.Fields(line)
			if len(fields) == 0 {
				continue
			}
			count, err := strconv.ParseUint(fields[i+1], 10, 64)
			if err != nil {
				return nil, err
			}
			name := strings.TrimSuffix(fields[0], ":")
			switch name {
			case "NET_RX":
				softIRQ.NetRX = count
			case "NET_TX":
				softIRQ.NetTX = count
			}
		}
		softIRQs = append(softIRQs, softIRQ)
	}
	return softIRQs, nil
}

func ReadNetStat() ([]NetStat, error) {
	lines, err := ReadFile(NetStatPath)
	if err != nil {
		return nil, err
	}

	netStats := make([]NetStat, 0, len(lines))
	for i := 0; i < len(lines); i++ {
		netStat := NetStat{
			CPU: fmt.Sprintf("CPU%d", i),
		}
		fields := strings.Fields(lines[i])
		if len(fields) < 9 {
			continue
		}
		netStat.Processed, err = strconv.ParseUint(fields[0], 16, 64)
		if err != nil {
			return nil, err
		}
		netStat.Dropped, err = strconv.ParseUint(fields[1], 16, 64)
		if err != nil {
			return nil, err
		}
		netStat.TimeSqueeze, err = strconv.ParseUint(fields[2], 16, 64)
		if err != nil {
			return nil, err
		}
		netStat.CpuCollision, err = strconv.ParseUint(fields[8], 16, 64)
		if err != nil {
			return nil, err
		}
		netStat.ReceivedRps, err = strconv.ParseUint(fields[9], 16, 64)
		if err != nil {
			return nil, err
		}
		netStats = append(netStats, netStat)
	}
	return netStats, nil
}

func ReadSysfsNetStat() ([]SysfsNetStat, error) {
	dirs, err := ioutil.ReadDir(SysfsPath)
	if err != nil {
		return nil, err
	}

	sysfsNetStat := make([]SysfsNetStat, 0, len(dirs))

	for _, d := range dirs {
		files, err := ioutil.ReadDir(path.Join(SysfsPath, d.Name(), "statistics"))
		if err != nil {
			continue
		}
		stat := SysfsNetStat{
			Dev: d.Name(),
		}
		for _, f := range files {
			data, err := ioutil.ReadFile(path.Join(SysfsPath, d.Name(), "statistics", f.Name()))
			if err != nil {
				continue
			}

			lines := strings.Split(string(data), "\n")
			count, err := strconv.ParseUint(lines[0], 10, 64)
			if err != nil {
				return nil, err
			}
			switch f.Name() {
			case "rx_packets":
				stat.RXpackets = count
			case "rx_bytes":
				stat.RXmbits = count * 8 / 1024 / 1024
			case "rx_errors":
				stat.RXerrors = count
			case "rx_dropped", "tx_dropped":
				stat.Dropped += count
			case "rx_missed_errors":
				stat.Missed = count
			case "rx_fifo_errors", "tx_fifo_errors":
				stat.Fifo += count
			case "rx_length_errors":
				stat.Length = count
			case "rx_over_errors":
				stat.Overrun = count
			case "rx_crc_errors":
				stat.CRC = count
			case "rx_frame_errors":
				stat.Frame = count
			case "tx_packets":
				stat.TXpackets = count
			case "tx_bytes":
				stat.TXmbits = count * 8 / 1024 / 1024
			case "tx_errors":
				stat.TXerrors = count
			}
		}
		sysfsNetStat = append(sysfsNetStat, stat)
	}

	return sysfsNetStat, nil
}

func ReadCPUStat(old_stat map[string][]uint64) ([]CPUStat, error) {
	lines, err := ReadFile(StatPath)
	if err != nil {
		return nil, err
	}

	stat := make([]CPUStat, 0, len(old_stat))

	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) == 0 || !strings.HasPrefix(line, "cpu") {
			continue
		}
		data_new := strArr2Uint(fields[1:])
		data := diffUintArr(data_new, old_stat[fields[0]])
		old_stat[fields[0]] = data_new
		result := CaclPercentage(data)
		cpuStat := CPUStat{
			CPU:     fields[0],
			User:    result[0],
			Nice:    result[1],
			System:  result[2],
			Idle:    result[3],
			IOwait:  result[4],
			IRQ:     result[5],
			SoftIRQ: result[6],
		}
		stat = append(stat, cpuStat)
	}

	return stat, nil
}

func ReadSnmp() ([]SNMP, error) {
	lines, err := ReadFile(SnmpPath)
	if err != nil {
		return nil, err
	}

	snmps := make([]SNMP, 0)

	for i := 1; i < len(lines); i = i + 2 {
		headers := strings.Fields(lines[i-1][strings.Index(lines[i-1], ":")+1:])
		values := strings.Fields(lines[i][strings.Index(lines[i], ":")+1:])
		protocol := strings.Replace(strings.Fields(lines[i-1])[0], ":", "", -1)
		snmp := SNMP{
			Protocol: protocol,
		}
		for j, header := range headers {
			count, _ := strconv.ParseUint(values[j], 10, 64)
			snmp.Params = append(snmp.Params, Param{Name: header, Value: count})
		}
		snmps = append(snmps, snmp)
	}

	return snmps, nil
}

func ReadConntrack() (uint64, error) {
	data, err := exec.Command("conntrack", "--count").Output()
	if err != nil {
		return 0, err
	}
	lines := strings.Split(string(data), "\n")
	count, err := strconv.ParseUint(lines[0], 10, 64)
	if err != nil {
		return 0, err
	}

	return count, nil
}

func main() {
	intrpts, err := ReadInterrupts()
	if err != nil {
		log.Fatalf("interrupts read fail: %v\n", err)
	}
	softIRQs, err := ReadSoftIRQ()
	if err != nil {
		log.Fatalf("softIRQs read fail: %v\n", err)
	}
	netStats, err := ReadNetStat()
	if err != nil {
		log.Fatalf("netStats read fail: %v\n", err)
	}
	old_cpu_stat := make(map[string][]uint64)
	cpuStat, err := ReadCPUStat(old_cpu_stat)
	if err != nil {
		log.Fatalf("cpuStat read fail: %v\n", err)
	}
	sysfsNetStats, err := ReadSysfsNetStat()
	if err != nil {
		log.Fatalf("netSysfsStats read fail: %v\n", err)
	}
	/**
	  snmp, err := ReadSnmp()
	  if err != nil {
	          log.Fatalf("snmp read fail: %v", err)
	  }
	  **/
	for t := range time.Tick(time.Second) {
		print("\033[H\033[2J")

		conntrack, err := ReadConntrack()
		if err != nil {
			log.Printf("conntrack read fail: %v\n", err)
			continue
		}
		fmt.Printf("%s\nConntrack count: %d\n\n", t.Format(time.RFC3339), conntrack)

		intrpts_temp, err := ReadInterrupts()
		if err != nil {
			log.Printf("interrupts read fail: %v\n", err)
			continue
		}
		intrpts_result := diffInterrupts(intrpts_temp, intrpts)
		intrpts = intrpts_temp

		table := tablewriter.NewWriter(os.Stdout)
		header := append(intrpts_result.CPUs, "Description", "№")
		table.SetHeader(header)
		for _, v := range intrpts_result.Interrupts {
			data := append(uintArr2Str(v.Counts), v.Description, v.Name)
			table.Append(data)
		}
		table.SetCenterSeparator("")
		table.SetColumnSeparator("")
		table.SetRowSeparator("")
		fmt.Printf("# %s\n", InterruptsPath)
		table.Render()

		softIRQs_temp, err := ReadSoftIRQ()
		if err != nil {
			log.Printf("softIRQs read fail: %v\n", err)
			continue
		}
		softIRQs_result := diffSoftIRQ(softIRQs_temp, softIRQs)
		softIRQs = softIRQs_temp

		netStats_temp, err := ReadNetStat()
		if err != nil {
			log.Printf("netStats read fail: %v\n", err)
			continue
		}
		netStats_result := diffNetStat(netStats_temp, netStats)
		netStats = netStats_temp

		cpuStat, err = ReadCPUStat(old_cpu_stat)
		if err != nil {
			log.Printf("cpuStat read fail: %v\n", err)
			continue
		}

		if len(intrpts_result.CPUs) <= len(softIRQs_result) && len(intrpts_result.CPUs) <= len(netStats_result) && len(intrpts_result.CPUs) <= len(cpuStat)+1 {
			table = tablewriter.NewWriter(os.Stdout)
			table.SetHeader([]string{"CPU", "Interrupts", "NET RX", "NET TX", "Processed", "Dropped", "Time Squeeze", "Cpu Collision", "Received Rps", "softirq time", "Idle time"})
			for i := 0; i < len(intrpts_result.CPUs); i++ {
				si := softIRQs_result[i]
				ns := netStats_result[i]
				cs := cpuStat[i+1]
				strArr := uintArr2Str([]uint64{intrpts_result.Total[i], si.NetRX, si.NetTX, ns.Processed, ns.Dropped, ns.TimeSqueeze, ns.CpuCollision, ns.ReceivedRps})
				strArr = append(strArr, fmt.Sprintf("%.2f", cs.SoftIRQ), fmt.Sprintf("%.2f", cs.Idle))
				table.Append(append([]string{intrpts_result.CPUs[i]}, strArr...))
			}
			table.SetCenterSeparator("")
			table.SetColumnSeparator("")
			table.SetRowSeparator("")
			fmt.Printf("# %s && %s && %s \n", SoftIRQPath, NetStatPath, StatPath)
			table.Render()
		}

		sysfsNetStats_temp, err := ReadSysfsNetStat()
		if err != nil {
			log.Printf("softIRQs read fail: %v\n", err)
			continue
		}
		sysfsNetStats_result := diffSysfsNetStat(sysfsNetStats_temp, sysfsNetStats)
		sysfsNetStats = sysfsNetStats_temp

		table = tablewriter.NewWriter(os.Stdout)
		table.SetHeader([]string{"dev", "rx-packets", "rx-mbits", "rx-errors", "dropped", "missed", "fifo", "length", "overrun", "crc", "frame", "tx-packets", "tx-mbits", "tx-errors"})
		for i := 0; i < len(sysfsNetStats_result); i++ {
			ns := sysfsNetStats_result[i]
			strArr := uintArr2Str([]uint64{ns.RXpackets, ns.RXmbits, ns.RXerrors, ns.Dropped, ns.Missed, ns.Fifo, ns.Length, ns.Overrun, ns.CRC, ns.Frame, ns.TXpackets, ns.TXmbits, ns.TXerrors})
			table.Append(append([]string{ns.Dev}, strArr...))
			/**
			  table.Append([]string{ns.Dev, colorize(ns.RXpackets, 0), colorize(ns.RXmbits, 0), colorize(ns.RXerrors, 1),
			          colorize(ns.Dropped, 1), colorize(ns.Missed, 1), colorize(ns.Fifo, 1), colorize(ns.Length, 1),
			          colorize(ns.Overrun, 1), colorize(ns.CRC, 1), colorize(ns.Frame, 1),
			          colorize(ns.TXpackets, 0), colorize(ns.TXmbits, 0), colorize(ns.TXerrors, 1)})
			  **/
		}
		table.SetCenterSeparator("")
		table.SetColumnSeparator("")
		table.SetRowSeparator("")
		fmt.Printf("# %s\n", SysfsPath)
		table.Render()
		/**
		        fmt.Printf("# %s\n", SnmpPath)
		        for i := 0; i < len(snmp); i++ {
		                stat := snmp[i]
		                fmt.Printf("%s\n", stat.Protocol)
		                table = tablewriter.NewWriter(os.Stdout)
		                for _, param := range stat.Params {
		                        table.Append([]string{param.Name, strconv.FormatUint(param.Value, 10)})
		                }
		                table.SetCenterSeparator("")
		                table.SetColumnSeparator("")
		                table.SetRowSeparator("")
		                table.Render()
		        }
		**/
	}
}
