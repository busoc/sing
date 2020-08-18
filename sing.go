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
	"strings"
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

type Option func(*Singer) error

func WithReader(r io.Reader) Option {
	return func(s *Singer) error {
		s.inner = r
		return nil
	}
}

func WithSize(z int) Option {
	return func(s *Singer) error {
		s.body = make([]byte, z)
		return nil
	}
}

func WithTimeout(d time.Duration) Option {
	return func(s *Singer) error {
		if d > 0 {
			s.wait = d
		}
		return nil
	}
}

func WithTTL(ttl int) Option {
	return func(s *Singer) error {
		c := s.conn.IPv4PacketConn()
		if c != nil {
			c.SetTTL(ttl)
		}
		return nil
	}
}

const (
	DefaultBodyLen   = 56
	DefaultBufferLen = 4096
)

type Singer struct {
	conn *icmp.PacketConn
	next int
	addr net.Addr
	pid  int

	wait  time.Duration
	body  []byte
	inner io.Reader

	buffer []byte
}

func New(addr string, options ...Option) (*Singer, error) {
	a, err := net.ResolveIPAddr("ip4", addr)
	if err != nil {
		return nil, err
	}
	c, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return nil, err
	}
	s := Singer{
		addr:   a,
		conn:   c,
		wait:   time.Second,
		pid:    os.Getpid() & 0xFFFF,
		buffer: make([]byte, DefaultBufferLen),
	}
	for _, o := range options {
		if err := o(&s); err != nil {
			return nil, err
		}
	}
	if len(s.body) == 0 {
		s.body = make([]byte, DefaultBodyLen)
	}
	return &s, nil
}

func (s *Singer) Sing() (State, error) {
	var st State
	if err := s.send(); err != nil {
		return st, err
	}
	reply, e, err := s.recv()
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

func (s *Singer) recv() (*icmp.Message, time.Duration, error) {
	for {
		now := time.Now()
		if s.wait > 0 {
			s.conn.SetReadDeadline(now.Add(s.wait))
		}
		n, peer, err := s.conn.ReadFrom(s.buffer)
		if err != nil {
			return nil, 0, err
		}
		if peer.String() == s.addr.String() {
			wait := time.Since(now)
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

const help = `sing send ICMP echo request to network hosts

Options:

  -e         exit when an error is encountered
  -h         print this help message and exit
  -m         print info when packets lost is detected
  -n  COUNT  send COUNT echo request to given host and exit
  -s  SIZE   set body of echo request to SIZE bytes
  -r  TIME   abort reading next reply after TIME is elapsed
  -t  TTL    set TTL to future outgoing requests
  -v         print details for each request/reply
  -w  WAIT   wait WAIT seconds before sending the next request
  -z         set body of echo request to null bytes only

Usage: sing [option] <ip|host>
`

func main() {
	flag.Usage = func() {
		fmt.Fprintln(os.Stdout, strings.TrimSpace(help))
		os.Exit(1)
	}
	var (
		wait    time.Duration
		timeout time.Duration
		null    bool
		size    int
		ttl     int
		count   int
		missing bool
		verbose bool
		exit    bool
	)
	flag.DurationVar(&wait, "w", time.Second, "wait time")
	flag.DurationVar(&timeout, "r", time.Second, "timeout")
	flag.IntVar(&ttl, "t", 62, "time to live")
	flag.IntVar(&size, "s", 56, "payload length")
	flag.IntVar(&count, "n", count, "count")
	flag.BoolVar(&null, "z", false, "zero")
	flag.BoolVar(&missing, "m", false, "missing")
	flag.BoolVar(&verbose, "v", false, "verbose")
	flag.BoolVar(&exit, "e", exit, "exit on error")
	flag.Parse()

	var print func(string, int, State) = printDefault
	if missing {
		print = printMissing
	}

	options := []Option{
		WithTimeout(timeout),
		WithTTL(ttl),
		WithSize(size),
		WithReader(NewReader(null)),
	}

	sng, err := New(flag.Arg(0), options...)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer sng.Close()

	s := Start()
	repeat(count, wait, exit, func() error {
		st, err := sng.Sing()
		if err == nil {
			s.Update(st)
			if verbose {
				print(flag.Arg(0), size, st)
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

func printDefault(addr string, size int, st State) {
	fmt.Fprintf(os.Stdout, "%d bytes -> %s: seq = %d, time = %s", size, prolog(addr), st.Curr, st.Elapsed)
	if diff := st.Missing(); diff > 0 {
		fmt.Fprintf(os.Stdout, " (%d missing)", diff)
	}
	fmt.Fprintln(os.Stdout)
}

func printMissing(addr string, size int, st State) {
	diff := st.Missing()
	if diff == 0 {
		return
	}
	n := size * diff
	fmt.Fprintf(os.Stdout, "%s: last = %d, first = %d, missing = %d (% bytes lost)", prolog(addr), st.Prev, st.Curr, diff, n)
	fmt.Fprintln(os.Stdout)
}

func prolog(addr string) string {
	if ns, _ := net.LookupHost(addr); len(ns) > 0 {
		return fmt.Sprintf("%s (%s)", addr, ns[len(ns)-1])
	}
	return addr
}
