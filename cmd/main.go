//go:generate sh -c "cd ../bpf && go generate"

package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"ebpf-ai-agent/bpf"
	"ebpf-ai-agent/pkg/analyzer"
	"ebpf-ai-agent/pkg/config"
	"ebpf-ai-agent/pkg/diagnostics"
	"ebpf-ai-agent/pkg/filter"

	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"

	"github.com/cilium/ebpf/link"
)

const (
	timeWindow    = 10 * time.Second
	checkInterval = 1 * time.Second
	Version       = "1.0.0"
)

var (
	configPath  = flag.String("config", config.DefaultConfigPath(), "path to config file")
	logLevel    = flag.String("log-level", "info", "log level: debug, info, warn, error")
	showVersion = flag.Bool("version", false, "show version and exit")
	dryRun      = flag.Bool("dry-run", false, "dry run mode (no eBPF loading)")
)

var logger *log.Logger

func init() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "ebpf-ai-agent - eBPF Process Security Monitor\n\nUsage: %s [options]\n\nOptions:\n", os.Args[0])
		flag.PrintDefaults()
	}
}

func setupLogger(level string) {
	log.SetFlags(0)
	switch strings.ToLower(level) {
	case "debug":
		log.SetOutput(os.Stdout)
		logger = log.New(os.Stdout, "[DEBUG] ", log.Ldate|log.Ltime|log.Lshortfile)
	case "info":
		log.SetOutput(os.Stdout)
		logger = log.New(os.Stdout, "[INFO] ", log.Ldate|log.Ltime)
	case "warn":
		log.SetOutput(os.Stderr)
		logger = log.New(os.Stderr, "[WARN] ", log.Ldate|log.Ltime)
	case "error":
		log.SetOutput(os.Stderr)
		logger = log.New(os.Stderr, "[ERROR] ", log.Ldate|log.Ltime)
	default:
		log.SetOutput(os.Stdout)
		logger = log.New(os.Stdout, "[INFO] ", log.Ldate|log.Ltime)
	}
}

type BehaviorCache struct {
	mu        sync.RWMutex
	behaviors map[uint32]*analyzer.ProcessBehavior
}

func NewBehaviorCache() *BehaviorCache {
	return &BehaviorCache{
		behaviors: make(map[uint32]*analyzer.ProcessBehavior),
	}
}

func (c *BehaviorCache) AddOrUpdate(pid uint32, filename, argv string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()

	if beh, exists := c.behaviors[pid]; exists {
		beh.LastSeen = now
		if filename != "" {
			beh.Filenames = append(beh.Filenames, filename)
		}
		if argv != "" {
			beh.Argv = argv
		}
		return
	}

	c.behaviors[pid] = &analyzer.ProcessBehavior{
		PID:       pid,
		StartTime: now,
		LastSeen:  now,
		Filenames: []string{filename},
		Argv:      argv,
	}
}

func (c *BehaviorCache) FlushExpired() []*analyzer.ProcessBehavior {
	c.mu.Lock()
	defer c.mu.Unlock()

	expired := make([]*analyzer.ProcessBehavior, 0)
	now := time.Now()
	toDelete := make([]uint32, 0)

	for pid, beh := range c.behaviors {
		if now.Sub(beh.LastSeen) >= timeWindow {
			expired = append(expired, beh)
			toDelete = append(toDelete, pid)
		}
	}

	for _, pid := range toDelete {
		delete(c.behaviors, pid)
	}

	return expired
}

func (c *BehaviorCache) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.behaviors)
}

var (
	analyzerGlobal analyzer.Analyzer
	filterGlobal   *filter.Matcher
)

func runFlushTask(cache *BehaviorCache, done <-chan struct{}) {
	ticker := time.NewTicker(checkInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			expired := cache.FlushExpired()
			for _, beh := range expired {
				// Calculate duration
				duration := beh.LastSeen.Sub(beh.StartTime)

				// Count unique files
				uniqueFiles := make(map[string]bool)
				for _, f := range beh.Filenames {
					uniqueFiles[f] = true
				}

				// Get first and last file
				firstFile := ""
				lastFile := ""
				if len(beh.Filenames) > 0 {
					firstFile = beh.Filenames[0]
					lastFile = beh.Filenames[len(beh.Filenames)-1]
				}

				// Get primary command (first filename without path)
				primaryCmd := ""
				if firstFile != "" {
					parts := strings.Split(firstFile, "/")
					primaryCmd = parts[len(parts)-1]
				}

				fmt.Printf("[AGGREGATED] pid=%d duration=%s cmds=%d unique_files=%d first=%s last=%s argv=%q\n",
					beh.PID,
					duration.Round(time.Second),
					len(beh.Filenames),
					len(uniqueFiles),
					firstFile,
					lastFile,
					beh.Argv)

				// Apply filter before AI analysis
				if filterGlobal != nil {
					filterResult, filterReason := filterGlobal.Match(primaryCmd, beh.Filenames, beh.Argv)
					fmt.Printf("[FILTER] result=%s reason=%s\n", filterResult, filterReason)

					switch filterResult {
					case filter.Whitelisted:
						// Skip AI analysis, clearly safe
						continue
					case filter.Blacklisted:
						// Immediate alert, skip AI
						report := &analyzer.RiskReport{
							PID:        beh.PID,
							RiskLevel:  "critical",
							Reasons:    []string{"blacklisted pattern: " + filterReason},
							Suggestion: "Immediate investigation required",
						}
						data, _ := json.Marshal(report)
						fmt.Printf("[RISK REPORT] %s\n", string(data))
						continue
					}
					// Greylisted: continue to AI analysis
				}

				if analyzerGlobal != nil {
					report, err := analyzerGlobal.Analyze(beh)
					if err != nil {
						logger.Printf("LLM analysis failed for pid %d: %v", beh.PID, err)
						continue
					}
					data, _ := json.Marshal(report)
					fmt.Printf("[RISK REPORT] %s\n", string(data))
				}
			}
		case <-done:
			return
		}
	}
}

func main() {
	flag.Parse()
	setupLogger(*logLevel)

	if *showVersion {
		fmt.Printf("ebpf-ai-agent version %s\n", Version)
		os.Exit(0)
	}

	logger.Println("ebpf-ai-agent starting...")

	// Run diagnostics before loading eBPF
	diagnostics.CheckSystemState(logger)

	// Initialize filter
	filterGlobal = filter.NewMatcher()
	logger.Printf("pattern filter initialized: %s", filterGlobal)

	cfg, err := config.Load(*configPath)
	if err != nil {
		logger.Printf("failed to load config from %s: %v, using defaults", *configPath, err)
	} else {
		warnings := cfg.Validate()
		for _, w := range warnings {
			logger.Printf("config warning: %s", w)
		}

		// Get API key (handles encrypted vs plaintext)
		apiKey, err := cfg.GetAPIKey()
		if err != nil {
			logger.Printf("failed to get API key: %v", err)
		} else if apiKey != "" {
			analyzerGlobal = analyzer.NewMinimaxAnalyzer(apiKey)
			logger.Println("AI analyzer enabled")
		}
	}

	if *dryRun {
		logger.Println("dry-run mode, exiting")
		os.Exit(0)
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		logger.Fatalf("failed to remove memlock rlimit: %v", err)
	}

	// Load BPF objects - try with nil options first, fallback to no-BTF
	var objs bpf.EventObjects
	if err := bpf.LoadEventObjects(&objs, nil); err != nil {
		// If BTF fails, try disabling CO-RE
		logger.Printf("BTF load failed, retrying without CO-RE: %v", err)
		spec, err := bpf.LoadEvent()
		if err != nil {
			logger.Fatalf("failed to load BPF spec: %v", err)
		}
		// Disable CO-RE
		for i := range spec.Programs {
			spec.Programs[i].AttachType = 0
		}
		if err := spec.LoadAndAssign(&objs, nil); err != nil {
			logger.Fatalf("failed to load eBPF objects (non-BTF): %v", err)
		}
	}
	defer objs.Close()

	// Attach tracepoint program
	// For argv capture, we use raw_syscalls:sys_enter which provides pt_regs context
	l, err := link.Tracepoint("raw_syscalls", "sys_enter", objs.HandleSysEnter, nil)
	if err != nil {
		logger.Fatalf("failed to attach tracepoint: %v", err)
	}
	defer l.Close()
	logger.Println("tracepoint attached successfully")

	// Try to use ringbuf first (kernel 6.0+), fall back to perf
	var reader interface {
		Read() ([]byte, error)
		Close() error
	}
	var usingRingbuf bool

	// Check kernel version - ringbuf requires 6.0+
	kernelVersion := runtime.Version()
	logger.Printf("detected kernel version: %s", kernelVersion)

	// Use ringbuf reader for kernel 6.0+
	// Rb map is created by probe_6_0.c (ringbuf)
	if objs.Rb != nil {
		ringReader, err := ringbuf.NewReader(objs.Rb)
		if err != nil {
			logger.Fatalf("failed to open ringbuf reader: %v", err)
		}
		reader = &ringbufWrapper{rd: ringReader}
		usingRingbuf = true
		logger.Println("using ringbuf for event collection (kernel 6.0+)")
	} else {
		logger.Fatalf("no suitable BPF map found (neither ringbuf nor perf)")
	}
	defer reader.Close()

	cache := NewBehaviorCache()
	flushDone := make(chan struct{})

	go runFlushTask(cache, flushDone)

	eventCount := 0
	lostCount := 0

	go func() {
		for {
			data, err := reader.Read()
			if err != nil {
				close(flushDone)
				return
			}

			eventCount++

			// Parse event from raw bytes
			var event bpf.Event
			r := bytes.NewReader(data)
			binary.Read(r, binary.LittleEndian, &event.Pid)
			binary.Read(r, binary.LittleEndian, &event.Ppid)
			r.Read(event.Filename[:])
			r.Read(event.Argv[:])

			// Find actual string length for filename
			filenameLen := 0
			for i, b := range event.Filename {
				if b == 0 {
					filenameLen = i
					break
				}
				if i == len(event.Filename)-1 {
					filenameLen = i + 1
				}
			}
			filename := string(event.Filename[:filenameLen])

			// Find actual string length for argv
			argvLen := 0
			for i, b := range event.Argv {
				if b == 0 {
					argvLen = i
					break
				}
				if i == len(event.Argv)-1 {
					argvLen = i + 1
				}
			}
			argv := string(event.Argv[:argvLen])

			// Log event (rate-limited in debug mode)
			if eventCount%100 == 0 || usingRingbuf {
				logger.Printf("event: pid=%d ppid=%d filename=%s argv=%q (total: %d lost: %d)",
					event.Pid, event.Ppid, filename, argv, eventCount, lostCount)
			}

			// Check for lost samples (ringbuf reports this in data)
			if len(data) < int(unsafe.Sizeof(event)) {
				lostCount++
				if lostCount%100 == 0 {
					logger.Printf("WARNING: detected %d lost events, system may be overwhelmed", lostCount)
				}
			}

			cache.AddOrUpdate(event.Pid, filename, argv)
		}
	}()

	fmt.Println("ebpf-ai-agent started, aggregation window: 10s")
	fmt.Printf("Cache size: %d\n", cache.Size())
	logger.Println("event reader initialized, waiting for events...")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	close(flushDone)
	fmt.Println("shutting down...")
}

// ringbufWrapper wraps cilium/ebpf/ringbuf.Reader for uniform interface
type ringbufWrapper struct {
	rd *ringbuf.Reader
}

func (r *ringbufWrapper) Read() ([]byte, error) {
	record, err := r.rd.Read()
	if err != nil {
		return nil, err
	}
	return record.RawSample, nil
}

func (r *ringbufWrapper) Close() error {
	return r.rd.Close()
}

// perfWrapper wraps cilium/ebpf/perf.Reader for uniform interface
type perfWrapper struct {
	rd *perf.Reader
}

func (p *perfWrapper) Read() ([]byte, error) {
	record, err := p.rd.Read()
	if err != nil {
		return nil, err
	}
	return record.RawSample, nil
}

func (p *perfWrapper) Close() error {
	p.rd.Close()
	return nil
}
