// Command dnsd runs an authoritative server for zone files, a recursive
// resolver, or does a one-off lookup.
//
//	dnsd -addr 127.0.0.1:5353 -zone example.com.zone        # authoritative
//	dnsd -addr 127.0.0.1:5354 -recursive                    # recursive resolver
//	dnsd -lookup www.example.com -type A                    # resolve and print
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/AbdeldjalilChougui/dns/dnsmsg"
	"github.com/AbdeldjalilChougui/dns/resolver"
	"github.com/AbdeldjalilChougui/dns/server"
	"github.com/AbdeldjalilChougui/dns/zone"
)

type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(v string) error { *m = append(*m, v); return nil }

func main() {
	var zones multi
	addr := flag.String("addr", "127.0.0.1:5353", "UDP+TCP listen address")
	flag.Var(&zones, "zone", "zone file to serve (repeatable)")
	recursive := flag.Bool("recursive", false, "run a recursive resolver instead")
	lookup := flag.String("lookup", "", "resolve this name from the root and exit")
	qtype := flag.String("type", "A", "record type for -lookup")
	flag.Parse()
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))

	if *lookup != "" {
		t, err := dnsmsg.ParseType(*qtype)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		res, err := resolver.New().Resolve(ctx, *lookup, t)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Printf(";; %s\n", res.RCode)
		for _, rr := range res.Answers {
			fmt.Println(rr)
		}
		return
	}

	s := &server.Server{Log: log}
	switch {
	case *recursive:
		s.Handler = resolver.Handler(resolver.New())
	case len(zones) > 0:
		a := &server.Authoritative{}
		for _, p := range zones {
			f, err := os.Open(p)
			if err != nil {
				log.Error("open zone", "err", err)
				os.Exit(1)
			}
			z, err := zone.Parse(f, ".")
			f.Close()
			if err != nil {
				log.Error("parse zone", "file", p, "err", err)
				os.Exit(1)
			}
			log.Info("loaded zone", "origin", z.Origin, "file", p)
			a.Zones = append(a.Zones, z)
		}
		s.Handler = a
	default:
		fmt.Fprintln(os.Stderr, "need -zone FILE, -recursive or -lookup NAME")
		os.Exit(2)
	}
	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
		<-sig
		s.Close()
	}()
	log.Info("listening", "addr", *addr)
	if err := s.ListenAndServe(*addr); err != nil {
		log.Error("serve", "err", err)
		os.Exit(1)
	}
}
