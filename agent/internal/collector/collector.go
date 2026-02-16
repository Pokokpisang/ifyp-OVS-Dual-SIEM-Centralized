package collector

import (
	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/mem"
	"github.com/shirou/gopsutil/v3/net"
	"time"
)

type Metrics struct {
	Timestamp    time.Time `json:"timestamp"`
	Host         string    `json:"host"`
	CPUPercent   float64   `json:"cpu_percent"`
	RAMPercent   float64   `json:"ram_percent"`
	NetInBytes   uint64    `json:"net_in_bytes"`
	NetOutBytes  uint64    `json:"net_out_bytes"`
}

func GetMetrics(host string) (Metrics, error) {
	v, _ := mem.VirtualMemory()
	c, _ := cpu.Percent(0, false)
	n, _ := net.IOCounters(false)
	
	cpuVal := 0.0
	if len(c) > 0 {
		cpuVal = c[0]
	}
	
	netIn := uint64(0)
	netOut := uint64(0)
	if len(n) > 0 {
		netIn = n[0].BytesRecv
		netOut = n[0].BytesSent
	}

	return Metrics{
		Timestamp:   time.Now().UTC(),
		Host:        host,
		CPUPercent:  cpuVal,
		RAMPercent:  v.UsedPercent,
		NetInBytes:  netIn,
		NetOutBytes: netOut,
	}, nil
}
