package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"
	"bufio"
	"errors"
	"net"
	"github.com/miekg/dns"
)

var (
	localDNS = flag.String("local", "192.168.1.1:53", "dns server behind GFW")
	remoteDNS = flag.String("remote", "208.67.222.222:53", "dns outsid GFM")
	zoneFile = flag.String("zone", "cn.zone", "zone file for China IP")
	netRange []*net.IPNet
	logger = log.New(os.Stdout, "logger: ", log.LstdFlags)
)

func main() {
	flag.Parse()
	buildNetRange()
	hold := make(chan int)
	go dnsServer(hold)

	sig := make(chan os.Signal)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
forever:
	for {
		select {
		case s := <-sig:
			fmt.Printf("Signal (%d) received, stopping\n", s)
			break forever
		}
	}

}

func dnsServer(hold chan int) {
	server := &dns.Server{Addr: ":53", Net: "udp"}
	go server.ListenAndServe()
	dns.HandleFunc(".", handleRequest)
}

func handleRequest(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	answers, err := chooseAnswer(r)
	if err == nil {
		for _, answer := range(answers.Answer){
			m.Answer = append(m.Answer, answer)
		}

	} 
	
	w.WriteMsg(m)
}

func chooseAnswer(r *dns.Msg) (m *dns.Msg, err error) {
	var local, remote *dns.Msg
	lch := make(chan *dns.Msg)
	rch := make(chan *dns.Msg)
	go queryLocal(r, lch)
	go queryRemote(r, rch)

	t := time.After(8 * time.Second)

timeout:
	for {
		select {
		case local = <- lch:
			logger.Printf("Receive local resp %q", local)
		case remote = <- rch:
			logger.Printf("Receive remote resp %q", remote)
		case <- t:
			logger.Printf("Timeout")
			break timeout
		}
		if remote != nil && local != nil {
			logger.Printf("Receive both resp")
			break timeout
		}
	}

	if remote == nil && local == nil {
		return nil, errors.New("Got no reponse!")
	}

	err = nil
	if remote == nil {
		m = local
		return
	}

	if local == nil {
		m = remote
		return
	}

	if isForeign(local) {
		m = remote
	} else {
		m = local
	}
	return
}

func queryLocal(r *dns.Msg, ch chan *dns.Msg) {
	c := new(dns.Client)
	in, _, err := c.Exchange(r, *localDNS)
	if err == nil {
		ch <- in
	} else {
		logger.Printf("Failed to query, %q", err)
	}
}

func queryRemote(r *dns.Msg, ch chan *dns.Msg) {
	c := new(dns.Client)
	c.Net = "tcp"
	in, _, err := c.Exchange(r, *remoteDNS)
	if err == nil {
		ch <- in
	} else {
		logger.Printf("Failed to query, %q", err)
	}
}

func buildNetRange() {
	f, err := os.Open(*zoneFile)
	if err != nil {
		logger.Printf("Cannot open zone file")
	}

	netRange = make([]*net.IPNet, 0)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		_, ipNet, err := net.ParseCIDR(scanner.Text())
		if err == nil {
			netRange = append(netRange, ipNet)
		}
	}
	logger.Printf("size of zone: %d", len(netRange))
}

func isForeign(r *dns.Msg) (foreign bool){
	foreign = true
check_ip:
	for _, answer := range(r.Answer) {
		if "A" == dns.Type(answer.Header().Rrtype).String() {
			for _, ipNet := range(netRange) {
				a := answer.(*dns.A).A
				if ipNet.Contains(a) {
					foreign = false
					break check_ip
				}
			}
		}
	}
	return
}
