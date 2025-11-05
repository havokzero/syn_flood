// prober_interactive.go
package main

import (
	"bufio"
	"encoding/csv"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Colors for output
const (
	Red   = "\033[31m"
	Green = "\033[32m"
	Cyan  = "\033[36m"
	Reset = "\033[0m"
	Bold  = "\033[1m"
)

type Result struct {
	Target  string
	Port    int
	Success bool
	RTT     time.Duration
	Time    time.Time
}

func main() {
	reader := bufio.NewReader(os.Stdin)

	fmt.Print(Cyan + "Enter target IP or CIDR (e.g. 10.10.10.5 or 10.10.10.0/24): " + Reset)
	targetInput, _ := reader.ReadString('\n')
	targetInput = strings.TrimSpace(targetInput)

	fmt.Print(Cyan + "Enter target port (1‑65535) [default 80]: " + Reset)
	portLine, _ := reader.ReadString('\n')
	portLine = strings.TrimSpace(portLine)
	port := 80
	if portLine != "" {
		p, err := strconv.Atoi(portLine)
		if err != nil || p < 1 || p > 65535 {
			fmt.Println(Red + "Invalid port. Using default 80." + Reset)
		} else {
			port = p
		}
	}

	fmt.Print(Cyan + "Delay between rounds in ms [default 1000]: " + Reset)
	delayLine, _ := reader.ReadString('\n')
	delayLine = strings.TrimSpace(delayLine)
	delay := 1000
	if delayLine != "" {
		if v, err := strconv.Atoi(delayLine); err == nil && v > 0 {
			delay = v
		}
	}

	fmt.Print(Cyan + "Timeout per probe in ms [default 2000]: " + Reset)
	timeoutLine, _ := reader.ReadString('\n')
	timeoutLine = strings.TrimSpace(timeoutLine)
	timeout := 2000
	if timeoutLine != "" {
		if v, err := strconv.Atoi(timeoutLine); err == nil && v > 0 {
			timeout = v
		}
	}

	fmt.Printf(Cyan+"Max concurrency [default %d]: "+Reset, runtime.NumCPU()*10)
	conLine, _ := reader.ReadString('\n')
	conLine = strings.TrimSpace(conLine)
	concurrency := runtime.NumCPU() * 10
	if conLine != "" {
		if v, err := strconv.Atoi(conLine); err == nil && v > 0 {
			concurrency = v
		}
	}

	fmt.Print(Cyan + "CSV output file (leave blank for none): " + Reset)
	csvLine, _ := reader.ReadString('\n')
	csvLine = strings.TrimSpace(csvLine)

	fmt.Print(Cyan + "Command to run when target goes down (use {target} placeholder, leave blank for none): " + Reset)
	onDownCmd, _ := reader.ReadString('\n')
	onDownCmd = strings.TrimSpace(onDownCmd)

	fmt.Print(Cyan + "Consecutive failure threshold before running command [default 3]: " + Reset)
	threshLine, _ := reader.ReadString('\n')
	threshLine = strings.TrimSpace(threshLine)
	downThreshold := 3
	if threshLine != "" {
		if v, err := strconv.Atoi(threshLine); err == nil && v > 0 {
			downThreshold = v
		}
	}

	fmt.Println(Green + "[*] Launching asynchronous TCP prober..." + Reset)

	// Parse targets
	targets := []string{}
	if strings.Contains(targetInput, "/") {
		ip, ipnet, err := net.ParseCIDR(targetInput)
		if err != nil {
			fmt.Println(Red+"Invalid CIDR:", err, Reset)
			os.Exit(1)
		}
		for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
			targets = append(targets, ip.String())
		}
		if len(targets) > 2 {
			targets = targets[1 : len(targets)-1]
		}
	} else {
		if net.ParseIP(targetInput) == nil {
			fmt.Println(Red + "Invalid IP address." + Reset)
			os.Exit(1)
		}
		targets = append(targets, targetInput)
	}

	// Optional CSV
	var csvWriter *csv.Writer
	if csvLine != "" {
		f, err := os.OpenFile(csvLine, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			fmt.Println(Red+"CSV open error:", err, Reset)
			os.Exit(1)
		}
		defer f.Close()
		csvWriter = csv.NewWriter(f)
		if fi, _ := f.Stat(); fi.Size() == 0 {
			_ = csvWriter.Write([]string{"timestamp", "target", "port", "success", "rtt_ms"})
			csvWriter.Flush()
		}
	}

	delayDur := time.Duration(delay) * time.Millisecond
	timeoutDur := time.Duration(timeout) * time.Millisecond
	sem := make(chan struct{}, concurrency)
	failCount := make(map[string]int)
	var failLock sync.Mutex

	var totalProbes, totalSuccess uint64
	var minRTT int64 = 1<<63 - 1
	var maxRTT int64

	runRound := func(round int) {
		var wg sync.WaitGroup
		for _, host := range targets {
			wg.Add(1)
			sem <- struct{}{}
			go func(host string) {
				defer wg.Done()
				defer func() { <-sem }()

				start := time.Now()
				conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), timeoutDur)
				elapsed := time.Since(start)
				ok := err == nil
				if ok {
					_ = conn.Close()
				}
				atomic.AddUint64(&totalProbes, 1)
				if ok {
					atomic.AddUint64(&totalSuccess, 1)
				}

				if ok {
					rms := elapsed.Microseconds()
					for {
						old := atomic.LoadInt64(&minRTT)
						if rms < old && atomic.CompareAndSwapInt64(&minRTT, old, rms) {
							break
						}
						if rms >= old {
							break
						}
					}
					for {
						old := atomic.LoadInt64(&maxRTT)
						if rms > old && atomic.CompareAndSwapInt64(&maxRTT, old, rms) {
							break
						}
						if rms <= old {
							break
						}
					}
				}

				if ok {
					fmt.Printf("Probing %-21s — %s🟢 Open%s       — time=%.3fms\n",
						fmt.Sprintf("%s:%d/tcp", host, port),
						Green, Reset,
						float64(elapsed.Microseconds())/1000)
				} else {
					fmt.Printf("Probing %-21s — %sNo response%s — time=%.3fms\n",
						fmt.Sprintf("%s:%d/tcp", host, port),
						Red, Reset,
						float64(elapsed.Microseconds())/1000)
				}

				if csvWriter != nil {
					_ = csvWriter.Write([]string{
						time.Now().Format(time.RFC3339Nano),
						host,
						strconv.Itoa(port),
						strconv.FormatBool(ok),
						fmt.Sprintf("%.3f", float64(elapsed.Microseconds())/1000),
					})
					csvWriter.Flush()
				}

				// failure tracking
				failLock.Lock()
				if !ok {
					failCount[host]++
				} else {
					failCount[host] = 0
				}
				trigger := failCount[host] >= downThreshold
				failLock.Unlock()

				if trigger && onDownCmd != "" {
					cmdStr := strings.ReplaceAll(onDownCmd, "{target}", host)
					go runOnDown(cmdStr, host)
				}
			}(host)
		}
		wg.Wait()

		min := atomic.LoadInt64(&minRTT)
		max := atomic.LoadInt64(&maxRTT)
		if min == 1<<63-1 {
			min = 0
		}
		fmt.Printf("%s[round %d]%s probes=%d success=%d min=%.3fms max=%.3fms\n",
			Bold, round, Reset,
			atomic.LoadUint64(&totalProbes),
			atomic.LoadUint64(&totalSuccess),
			float64(min)/1000, float64(max)/1000)
	}

	for round := 1; ; round++ {
		runRound(round)
		time.Sleep(delayDur)
	}
}

func runOnDown(cmdStr, host string) {
	fmt.Printf(Cyan+"[on‑down] %s: %s"+Reset+"\n", host, cmdStr)
	cmd := exec.Command("sh", "-c", cmdStr)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		fmt.Printf(Red+"[on‑down error] %v"+Reset+"\n", err)
	}
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}
