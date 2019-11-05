package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

type Protocol int

const (
	NoProtocol Protocol = iota
	IPv4
	IPv6
	UDPv4
	UDPv6
)

type Config struct {
	TTL      int
	Delay    time.Duration
	OnlyIPv4 bool
	OnlyIPv6 bool
	Rootless bool
}

type ICMPDefs struct {
	ProtocolId       int
	TypeUnreachable  icmp.Type
	TypeEchoReply    icmp.Type
	TypeEchoRequest  icmp.Type
	TypeTimeExceeded icmp.Type
}

var ICMPv4Defs = ICMPDefs{
	ProtocolId:       1,
	TypeUnreachable:  ipv4.ICMPTypeDestinationUnreachable,
	TypeEchoReply:    ipv4.ICMPTypeEchoReply,
	TypeEchoRequest:  ipv4.ICMPTypeEcho,
	TypeTimeExceeded: ipv4.ICMPTypeTimeExceeded,
}

var ICMPv6Defs = ICMPDefs{
	ProtocolId:       58,
	TypeUnreachable:  ipv6.ICMPTypeDestinationUnreachable,
	TypeEchoReply:    ipv6.ICMPTypeEchoReply,
	TypeEchoRequest:  ipv6.ICMPTypeEchoRequest,
	TypeTimeExceeded: ipv6.ICMPTypeTimeExceeded,
}

// At 6 bytes, this brings total packet size to the round number of 48 bytes
var PingPayload = []byte("goping")

func isIPv4(ip net.IP) bool {
	return ip.To4() != nil
}

// Select IP and protocol that best fit user configuration
func selectAddr(ips []net.IP, config *Config) (net.Addr, Protocol, error) {
	var addr net.Addr
	var protocol Protocol
	for _, ip := range ips {
		if isIPv4(ip) {
			if config.OnlyIPv6 {
				continue
			}
			if config.Rootless {
				protocol = UDPv4
			} else {
				protocol = IPv4
			}
		} else {
			if config.OnlyIPv4 {
				continue
			}
			if config.Rootless {
				protocol = UDPv6
			} else {
				protocol = IPv6
			}
		}

		if config.Rootless {
			addr = &net.UDPAddr{IP: ip}
		} else {
			addr = &net.IPAddr{IP: ip}
		}
	}

	if addr == nil {
		return nil, NoProtocol, fmt.Errorf("address family for hostname not supported")
	}

	return addr, protocol, nil
}

// Open an ICMP socket with the given protocol
func connect(protocol Protocol) (*icmp.PacketConn, error) {
	var conn *icmp.PacketConn
	var err error

	// The empty string is equivalent to 0.0.0.0 (ipv4) or :: (ipv6)
	switch protocol {
	case UDPv4:
		conn, err = icmp.ListenPacket("udp4", "")
	case UDPv6:
		conn, err = icmp.ListenPacket("udp6", "")
	case IPv4:
		conn, err = icmp.ListenPacket(fmt.Sprintf("ip4:%d", ICMPv4Defs.ProtocolId), "")
	case IPv6:
		conn, err = icmp.ListenPacket(fmt.Sprintf("ip6:%d", ICMPv6Defs.ProtocolId), "")
	}

	if err != nil {
		return nil, fmt.Errorf("opening connection: %w", err)
	}

	return conn, err
}

// Send echo requests until program termination
func ping(conn *icmp.PacketConn, addr net.Addr, config *Config, defs *ICMPDefs) error {
	var inbytes [128]byte

	body := icmp.Echo{
		// ping does this
		ID:   os.Getpid() & 0xffff,
		Data: PingPayload,
	}
	outmsg := icmp.Message{
		Type: defs.TypeEchoRequest,
		Code: 0,
		Body: &body,
	}

	sent, received := 0, 0
	for {
		body.Seq = sent

		outbytes, err := outmsg.Marshal(nil)
		if err != nil {
			return fmt.Errorf("marshalling message: %w", err)
		}

		sendtime := time.Now()

		_, err = conn.WriteTo(outbytes, addr)
		if err != nil {
			return fmt.Errorf("writing message: %w", err)
		}

		sent += 1

		n, _, err := conn.ReadFrom(inbytes[:])
		if err != nil {
			return fmt.Errorf("reading response: %w", err)
		}

		rtt := time.Since(sendtime)

		inmsg, err := icmp.ParseMessage(defs.ProtocolId, inbytes[:n])
		if err != nil {
			return fmt.Errorf("parsing response: %w", err)
		}

		switch inmsg.Type {
		case defs.TypeEchoReply:
			if reply, ok := inmsg.Body.(*icmp.Echo); ok {
				// Unprivileged ICMP sockets do not preserve ID:
				// instead, it is set to the local port number.
				if (config.Rootless || reply.ID == body.ID) && reply.Seq == body.Seq {
					fmt.Printf("icmp_seq=%d rtt=%s\n", reply.Seq, rtt)
					received += 1
				} else {
					fmt.Printf(
						"id/icmp_seq mismatch: sent %d/%d, got %d/%d\n",
						body.ID, body.Seq, reply.ID, reply.Seq,
					)
				}
			}
		case defs.TypeTimeExceeded:
			fmt.Println("time to live exceeded")
		case defs.TypeUnreachable:
			fmt.Println("destination unreachable")
		default:
			fmt.Println("response not understood")
		}
		percent := (sent - received) * 10000 / sent
		fmt.Printf(
			"%d sent and %d received: %3d.%02d%% lost\n\n",
			sent, received, percent/100, percent%100,
		)
		// Note: Sleep does the right thing when argument is negative
		time.Sleep(config.Delay - rtt)
	}
}

func run(host string, config *Config) error {
	ips, err := net.LookupIP(host)
	if err != nil {
		return fmt.Errorf("resolving: %w", err)
	}

	addr, protocol, err := selectAddr(ips, config)
	if err != nil {
		return err
	}

	conn, err := connect(protocol)
	if err != nil {
		return err
	}
	defer conn.Close()

	if protocol == IPv4 || protocol == UDPv4 {
		conn.IPv4PacketConn().SetTTL(config.TTL)
		err = ping(conn, addr, config, &ICMPv4Defs)
	} else {
		conn.IPv6PacketConn().SetHopLimit(config.TTL)
		err = ping(conn, addr, config, &ICMPv6Defs)
	}

	return err
}

func main() {
	var config Config

	flag.Usage = func() {
		fmt.Fprintln(flag.CommandLine.Output(), "Usage: [ping FLAGS HOST] where FLAGS are")
		flag.PrintDefaults()
	}
	flag.IntVar(&config.TTL, "ttl", 255, "maximum number of hops in transit")
	flag.DurationVar(&config.Delay, "delay", time.Second, "delay between requests")
	flag.BoolVar(&config.OnlyIPv4, "4", false, "use ipv4 or exit with error")
	flag.BoolVar(&config.OnlyIPv6, "6", false, "use ipv6 or exit with error")
	flag.BoolVar(&config.Rootless, "rootless", true, "use an unprivileged socket")
	flag.Parse()

	if flag.NArg() != 1 {
		flag.Usage()
		return
	}

	err := run(flag.Arg(0), &config)
	if err != nil {
		fmt.Printf("%s: %v\n", flag.Arg(0), err)
	}
}
