// Package metrics exposes the platform's own health in Prometheus text format
// (no external dependency).
package metrics

import (
	"fmt"
	"io"
	"math"
	"sort"
	"strings"
	"sync"
)

type histogram struct {
	count int64
	sum   float64
	max   float64
}

// Registry holds counters, gauges and simple summaries.
type Registry struct {
	mu       sync.Mutex
	counters map[string]map[string]float64 // name → label value → count
	gauges   map[string]func() float64
	hists    map[string]*histogram
	help     map[string]string
}

func New() *Registry {
	return &Registry{counters: map[string]map[string]float64{}, gauges: map[string]func() float64{},
		hists: map[string]*histogram{}, help: map[string]string{}}
}

// Help documents a metric.
func (r *Registry) Help(name, text string) {
	r.mu.Lock()
	r.help[name] = text
	r.mu.Unlock()
}

// Inc increments a counter with an optional single "kind" label.
func (r *Registry) Inc(name, label string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.counters[name] == nil {
		r.counters[name] = map[string]float64{}
	}
	r.counters[name][label]++
}

// Observe records a duration/value in a summary.
func (r *Registry) Observe(name string, v float64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	h := r.hists[name]
	if h == nil {
		h = &histogram{}
		r.hists[name] = h
	}
	h.count++
	h.sum += v
	h.max = math.Max(h.max, v)
}

// Gauge registers a callback gauge.
func (r *Registry) Gauge(name string, f func() float64) {
	r.mu.Lock()
	r.gauges[name] = f
	r.mu.Unlock()
}

// Write renders all metrics.
func (r *Registry) Write(w io.Writer) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var names []string
	for n := range r.counters {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		if h := r.help[n]; h != "" {
			fmt.Fprintf(w, "# HELP %s %s\n", n, h)
		}
		fmt.Fprintf(w, "# TYPE %s counter\n", n)
		var labels []string
		for l := range r.counters[n] {
			labels = append(labels, l)
		}
		sort.Strings(labels)
		for _, l := range labels {
			if l == "" {
				fmt.Fprintf(w, "%s %g\n", n, r.counters[n][l])
			} else {
				fmt.Fprintf(w, "%s{kind=%q} %g\n", n, strings.ReplaceAll(l, `"`, ""), r.counters[n][l])
			}
		}
	}
	names = names[:0]
	for n := range r.hists {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		h := r.hists[n]
		fmt.Fprintf(w, "# TYPE %s summary\n%s_count %d\n%s_sum %g\n%s_max %g\n", n, n, h.count, n, h.sum, n, h.max)
	}
	names = names[:0]
	for n := range r.gauges {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		if h := r.help[n]; h != "" {
			fmt.Fprintf(w, "# HELP %s %s\n", n, h)
		}
		fmt.Fprintf(w, "# TYPE %s gauge\n%s %g\n", n, n, r.gauges[n]())
	}
}
