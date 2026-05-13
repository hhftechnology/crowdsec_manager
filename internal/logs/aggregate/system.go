package aggregate

import (
	"bufio"
	"crowdsec-manager/internal/models"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// GetSystemStats collects basic system resource usage.
// Since we are running in a container, these metrics often reflect
// the host or the container's limits depending on the environment.
func GetSystemStats() *models.SystemStats {
	return &models.SystemStats{
		CPU:    getCPUStats(),
		Memory: getMemoryStats(),
		Disk:   getDiskStats(),
	}
}

func getCPUStats() models.CPUStats {
	cores := runtime.NumCPU()
	usage := 0.0

	// Try to get CPU usage from /proc/stat (Linux)
	if u, err := readCPUUsage(); err == nil {
		usage = u
	}

	model := "Generic CPU"
	if m, err := readCPUModel(); err == nil {
		model = m
	}

	return models.CPUStats{
		UsagePercent: usage,
		Cores:        cores,
		Model:        model,
	}
}

func getMemoryStats() models.MemoryStats {
	var stats models.MemoryStats
	// Try /proc/meminfo
	file, err := os.Open("/proc/meminfo")
	if err != nil {
		return stats
	}
	defer file.Close()

	var memTotal, memFree, memAvailable uint64
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		val, _ := strconv.ParseUint(fields[1], 10, 64)
		val *= 1024 // kB to B

		if strings.HasPrefix(line, "MemTotal:") {
			memTotal = val
		} else if strings.HasPrefix(line, "MemFree:") {
			memFree = val
		} else if strings.HasPrefix(line, "MemAvailable:") {
			memAvailable = val
		}
	}

	if memTotal > 0 {
		if memAvailable == 0 {
			memAvailable = memFree // Fallback for older kernels
		}
		used := memTotal - memAvailable
		stats.Total = memTotal
		stats.Used = used
		stats.Available = memAvailable
		stats.UsedPercent = (float64(used) / float64(memTotal)) * 100
	}

	return stats
}

func getDiskStats() models.DiskStats {
	var stats models.DiskStats
	fs := syscall.Statfs_t{}
	err := syscall.Statfs("/", &fs)
	if err != nil {
		return stats
	}

	total := fs.Blocks * uint64(fs.Bsize)
	free := fs.Bfree * uint64(fs.Bsize)
	used := total - free

	if total > 0 {
		stats.Total = total
		stats.Used = used
		stats.Free = free
		stats.UsedPercent = (float64(used) / float64(total)) * 100
	}

	return stats
}

func readCPUUsage() (float64, error) {
	// First reading
	idle0, total0, err := getCPUTicks()
	if err != nil {
		return 0, err
	}

	time.Sleep(100 * time.Millisecond)

	// Second reading
	idle1, total1, err := getCPUTicks()
	if err != nil {
		return 0, err
	}

	idleDelta := idle1 - idle0
	totalDelta := total1 - total0

	if totalDelta == 0 {
		return 0, nil
	}

	return (1.0 - float64(idleDelta)/float64(totalDelta)) * 100, nil
}

func getCPUTicks() (uint64, uint64, error) {
	file, err := os.Open("/proc/stat")
	if err != nil {
		return 0, 0, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	if scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 5 || fields[0] != "cpu" {
			return 0, 0, fmt.Errorf("invalid /proc/stat format")
		}

		var total uint64
		for i := 1; i < len(fields); i++ {
			val, _ := strconv.ParseUint(fields[i], 10, 64)
			total += val
		}
		idle, _ := strconv.ParseUint(fields[4], 10, 64)
		return idle, total, nil
	}
	return 0, 0, fmt.Errorf("could not read /proc/stat")
}

func readCPUModel() (string, error) {
	file, err := os.Open("/proc/cpuinfo")
	if err != nil {
		return "", err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "model name") || strings.HasPrefix(line, "Model") {
			parts := strings.Split(line, ":")
			if len(parts) > 1 {
				return strings.TrimSpace(parts[1]), nil
			}
		}
	}
	return "Unknown", nil
}
