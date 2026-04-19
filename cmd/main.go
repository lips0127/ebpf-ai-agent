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
	"sync"
	"syscall"
	"time"

	"ebpf-ai-agent/bpf"
	"ebpf-ai-agent/pkg/analyzer"
	"ebpf-ai-agent/pkg/config"

	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"

	"github.com/cilium/ebpf/link"
)

const (
	timeWindow    = 10 * time.Second
	checkInterval = 1 * time.Second
)

var (
	configPath = flag.String("config", config.DefaultConfigPath(), "path to config file")
)

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

var analyzerGlobal analyzer.Analyzer

func runFlushTask(cache *BehaviorCache, done <-chan struct{}) {
	ticker := time.NewTicker(checkInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			expired := cache.FlushExpired()
			for _, beh := range expired {
				fmt.Printf("[AGGREGATED] pid=%d files=%d\n", beh.PID, len(beh.Filenames))

				if analyzerGlobal != nil {
					report, err := analyzerGlobal.Analyze(beh)
					if err != nil {
						log.Printf("LLM analysis failed for pid %d: %v", beh.PID, err)
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

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Printf("[WARN] failed to load config from %s: %v, using defaults", *configPath, err)
	} else {
		warnings := cfg.Validate()
		for _, w := range warnings {
			log.Printf("[WARN] %s", w)
		}
		if cfg.MinimaxAPIKey != "" {
			analyzerGlobal = analyzer.NewMinimaxAnalyzer(cfg.MinimaxAPIKey)
		}
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("failed to remove memlock rlimit: %v", err)
	}

	var objs bpf.EventObjects
	if err := bpf.LoadEventObjects(&objs, nil); err != nil {
		log.Fatalf("failed to load eBPF objects: %v", err)
	}
	defer objs.Close()

	// Attach tracepoint program
	l, err := link.Tracepoint("sched", "sched_process_exec", objs.HandleSchedProcessExec, nil)
	if err != nil {
		log.Fatalf("failed to attach tracepoint: %v", err)
	}
	defer l.Close()
	log.Printf("[DEBUG] tracepoint attached successfully")

	rd, err := perf.NewReader(objs.Events, 4096)
	if err != nil {
		log.Fatalf("failed to open perf reader: %v", err)
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

			filename := string(event.Filename[:])
			log.Printf("[DEBUG] received event: pid=%d ppid=%d filename=%s (total: %d)", event.Pid, event.Ppid, filename, eventCount)

			cache.AddOrUpdate(event.Pid, filename)
		}
	}()

	fmt.Println("ebpf-ai-agent started, aggregation window: 10s")
	fmt.Printf("Cache size: %d\n", cache.Size())
	log.Printf("[DEBUG] perf reader initialized, waiting for events...")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	close(flushDone)
	fmt.Println("shutting down...")
}
