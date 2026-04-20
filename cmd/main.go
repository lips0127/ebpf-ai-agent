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
	"strings"
	"sync"
	"syscall"
	"time"

	"ebpf-ai-agent/bpf"
	"ebpf-ai-agent/pkg/analyzer"
	"ebpf-ai-agent/pkg/config"
	"ebpf-ai-agent/pkg/filter"

	"github.com/cilium/ebpf/perf"
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

func (c *BehaviorCache) AddOrUpdate(pid uint32, filename string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()

	if beh, exists := c.behaviors[pid]; exists {
		beh.LastSeen = now
		beh.Filenames = append(beh.Filenames, filename)
		return
	}

	c.behaviors[pid] = &analyzer.ProcessBehavior{
		PID:       pid,
		StartTime: now,
		LastSeen:  now,
		Filenames: []string{filename},
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

				fmt.Printf("[AGGREGATED] pid=%d duration=%s cmds=%d unique_files=%d first=%s last=%s\n",
					beh.PID,
					duration.Round(time.Second),
					len(beh.Filenames),
					len(uniqueFiles),
					firstFile,
					lastFile)

				// Apply filter before AI analysis
				if filterGlobal != nil {
					filterResult, filterReason := filterGlobal.Match(primaryCmd, beh.Filenames)
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

	// Initialize filter
	filterGlobal = filter.New()
	logger.Printf("pattern filter initialized: %s", filterGlobal)

	cfg, err := config.Load(*configPath)
	if err != nil {
		logger.Printf("failed to load config from %s: %v, using defaults", *configPath, err)
	} else {
		warnings := cfg.Validate()
		for _, w := range warnings {
			logger.Printf("config warning: %w", w)
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

	var objs bpf.EventObjects
	if err := bpf.LoadEventObjects(&objs, nil); err != nil {
		logger.Fatalf("failed to load eBPF objects: %v", err)
	}
	defer objs.Close()

	// Attach tracepoint program
	l, err := link.Tracepoint("sched", "sched_process_exec", objs.HandleSchedProcessExec, nil)
	if err != nil {
		logger.Fatalf("failed to attach tracepoint: %v", err)
	}
	defer l.Close()
	logger.Println("tracepoint attached successfully")

	rd, err := perf.NewReader(objs.Events, 4096)
	if err != nil {
		logger.Fatalf("failed to open perf reader: %v", err)
	}
	defer rd.Close()

	cache := NewBehaviorCache()
	flushDone := make(chan struct{})

	go runFlushTask(cache, flushDone)

	eventCount := 0
	go func() {
		for {
			record, err := rd.Read()
			if err != nil {
				if err == perf.ErrClosed {
					close(flushDone)
					return
				}
				log.Printf("failed to read perf: %v", err)
				continue
			}

			eventCount++
			var event bpf.Event
			r := bytes.NewReader(record.RawSample)
			binary.Read(r, binary.LittleEndian, &event.Pid)
			binary.Read(r, binary.LittleEndian, &event.Ppid)
			r.Read(event.Filename[:])

			// Find actual string length (up to null or end of buffer)
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
			logger.Printf("event: pid=%d ppid=%d filename=%s (total: %d)", event.Pid, event.Ppid, filename, eventCount)

			cache.AddOrUpdate(event.Pid, filename)
		}
	}()

	fmt.Println("ebpf-ai-agent started, aggregation window: 10s")
	fmt.Printf("Cache size: %d\n", cache.Size())
	logger.Println("perf reader initialized, waiting for events...")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	close(flushDone)
	fmt.Println("shutting down...")
}
