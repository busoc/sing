package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net"
	"os"
	"os/signal"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

const IcmpId = 1

var (
	ErrMissing    = errors.New("missing")
	ErrSkip       = errors.New("skip")
	ErrUnexpected = errors.New("unexpected")
	ErrUnreach    = errors.New("unreachable")
	ErrTime       = errors.New("exceeded")
)

type State struct {
	Elapsed time.Duration
	Prev    int
	Curr    int
}

func (s *State) Missing() int {
	diff := s.Curr - s.Prev
	if diff == 1 {
		return 0
	}
	return diff
}

type random struct{}

func (r random) Read(b []byte) (int, error) {
	rand.Seed(time.Now().Unix())
	for i := range b {
		b[i] = byte(rand.Intn(256))
	}
	return len(b), nil
}

type zero struct{}

func (z zero) Read(b []byte) (int, error) {
	for i := range b {
		b[i] = 0
	}
	return len(b), nil
}

func NewReader(null bool) io.Reader {
	if null {
		return zero{}
	}
	return random{}
}

type Singer struct {
	conn *icmp.PacketConn
	next int
	addr net.Addr
	pid  int

	body  []byte
	inner io.Reader

	buffer []byte
}

func Sing(addr net.Addr, r io.Reader, size int) (*Singer, error) {
	c, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return nil, err
	}
	s := Singer{
		addr:   addr,
		conn:   c,
		pid:    os.Getpid() & 0xFFFF,
		buffer: make([]byte, 4096),
		body:   make([]byte, size),
		inner:  r,
		next:   0,
	}
	return &s, nil
}

func (s *Singer) Sing(wait time.Duration) (State, error) {
	var st State
	if err := s.send(); err != nil {
		return st, err
	}
	reply, e, err := s.recv(wait)
	if err != nil {
		return st, err
	}
	switch b := reply.Body.(type) {
	case *icmp.Echo:
		st.Elapsed = e
		st.Prev = s.next
		st.Curr = b.Seq
	case *icmp.DstUnreach:
		return st, ErrUnreach
	case *icmp.TimeExceeded:
		return st, ErrTime
	default:
		return st, fmt.Errorf("%w: %T", ErrUnexpected, b)
	}
	return st, nil
}

func (s *Singer) Close() error {
	return s.conn.Close()
}

func (s *Singer) send() error {
	m, err := s.prepare()
	if err != nil {
		return err
	}
	wb, err := m.Marshal(nil)
	if err != nil {
		return fmt.Errorf("forging packet: %w", err)
	}
	_, err = s.conn.WriteTo(wb, s.addr)
	return err
}

func (s *Singer) recv(wait time.Duration) (*icmp.Message, time.Duration, error) {
	for {
		now := time.Now()
		if wait > 0 {
			s.conn.SetReadDeadline(now.Add(wait))
		}
		n, peer, err := s.conn.ReadFrom(s.buffer)
		if err != nil {
			return nil, 0, err
		}
		if peer.String() == s.addr.String() {
			wait = time.Since(now)
			reply, err := icmp.ParseMessage(IcmpId, s.buffer[:n])
			return reply, wait, err
		}
	}
}

func (s *Singer) prepare() (*icmp.Message, error) {
	s.next++
	if _, err := io.ReadFull(s.inner, s.body); err != nil {
		return nil, err
	}
	m := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{
			ID:   s.pid,
			Seq:  s.next,
			Data: s.body,
		},
	}
	return &m, nil
}

type Session struct {
	lost  int
	total int
	min   time.Duration
	max   time.Duration
  avg   time.Duration
	now   time.Time
}

func Start() *Session {
	s := Session{now: time.Now()}
	return &s
}

func (s *Session) Update(st State) {
	s.lost += st.Missing()
	s.total++

	if s.min == 0 || st.Elapsed < s.min {
		s.min = st.Elapsed
	}
	if s.max == 0 || st.Elapsed > s.max {
		s.max = st.Elapsed
	}
  s.avg += st.Elapsed
}

func (s *Session) Dump() {
	var percent float64
	if s.total > 0 {
		percent = float64(s.lost) / float64(s.total)
	}
	fmt.Printf("packets: %d\n", s.total)
	fmt.Printf("lost   : %d (%.2f%%)\n", s.lost, percent)
	fmt.Printf("avg    : %s\n", s.avg/time.Duration(s.total))
	fmt.Printf("min    : %s\n", s.min)
	fmt.Printf("max    : %s\n", s.max)
	fmt.Printf("total  : %s\n", time.Since(s.now))
}

func main() {
	var (
		wait    time.Duration
		ttl     time.Duration
		null    bool
		size    int
		count   int
		missing bool
		verbose bool
		exit    bool
	)
	flag.DurationVar(&wait, "w", time.Second, "wait time")
	flag.DurationVar(&ttl, "t", time.Second, "deadline")
	flag.IntVar(&size, "s", 56, "payload length")
	flag.IntVar(&count, "n", count, "count")
	flag.BoolVar(&null, "z", false, "zero")
	flag.BoolVar(&missing, "m", false, "missing")
	flag.BoolVar(&verbose, "v", false, "verbose")
	flag.BoolVar(&exit, "e", exit, "exit on error")
	flag.Parse()

	addr, err := net.ResolveIPAddr("ip4", flag.Arg(0))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	var print func(string, State) = printDefault
	if missing {
		print = printMissing
	}

	sng, err := Sing(addr, NewReader(null), size)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer sng.Close()

	s := Start()
	repeat(count, wait, exit, func() error {
		st, err := sng.Sing(ttl)
		if err == nil {
			s.Update(st)
			if verbose {
				print(flag.Arg(0), st)
			}
		}
		return err
	})
	s.Dump()
}

func repeat(count int, wait time.Duration, exit bool, fn func() error) {
	if wait <= 0 {
		wait = time.Second
	}
	var (
		ticks = time.Tick(wait)
		sig   = make(chan os.Signal, 1)
	)
	go signal.Notify(sig, os.Kill, os.Interrupt)
	for i := 0; count <= 0 || i < count; i++ {
		if err := fn(); err != nil && exit {
			return
		}
		select {
		case <-sig:
			return
		case <-ticks:
		}
	}
}

func printDefault(addr string, st State) {
	fmt.Fprintf(os.Stdout, "%s: seq = %d, time = %s", prolog(addr), st.Curr, st.Elapsed)
	if diff := st.Missing(); diff > 0 {
		fmt.Fprintf(os.Stdout, " (%d missing)", diff)
	}
	fmt.Fprintln(os.Stdout)
}

func printMissing(addr string, st State) {
	diff := st.Missing()
	if diff == 0 {
		return
	}
	fmt.Fprintf(os.Stdout, "%s: last = %d, first = %d, missing = %d", prolog(addr), st.Prev, st.Curr, diff)
	fmt.Fprintln(os.Stdout)
}

func prolog(addr string) string {
  if ns, _ := net.LookupHost(addr); len(ns) > 0 {
    return fmt.Sprintf("%s (%s)", addr, ns[len(ns)-1])
  }
  return addr
}
