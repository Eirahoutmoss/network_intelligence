package explorer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/anthropics/anthropic-sdk-go/option"

	"github.com/Eirahoutmoss/network_intelligence/backend/internal/model"
)

// Interpreter converts a question into a Query. The LLM interpreter only
// produces filters (structured output); it never sees or invents results.
type Interpreter interface {
	Interpret(ctx context.Context, question string, v Vocabulary) (Query, error)
}

// LLM is an optional Claude-backed interpreter, enabled when an API key is set.
type LLM struct {
	client anthropic.Client
	model  string
}

func NewLLM(apiKey, modelID string) *LLM {
	if modelID == "" {
		modelID = "claude-opus-5"
	}
	return &LLM{client: anthropic.NewClient(option.WithAPIKey(apiKey), option.WithMaxRetries(1)), model: modelID}
}

// llmQuery mirrors Query with every field required (structured outputs);
// empty values mean "no filter".
type llmQuery struct {
	Intent          string   `json:"intent"`
	Subject         string   `json:"subject"`
	Types           []string `json:"types"`
	Vendors         []string `json:"vendors"`
	OS              string   `json:"os"`
	Location        string   `json:"location"`
	Floor           int      `json:"floor"`
	Room            string   `json:"room"`
	Jack            string   `json:"jack"`
	Subnet          string   `json:"subnet"`
	IP              string   `json:"ip"`
	ConnectedTo     string   `json:"connected_to"`
	Downstream      bool     `json:"downstream"`
	Medium          string   `json:"medium"`
	PortChangedDays int      `json:"port_changed_days"`
	NewDays         int      `json:"new_days"`
	Status          string   `json:"status"`
	Text            string   `json:"text"`
	Lang            string   `json:"lang"`
}

func schema() map[string]any {
	str := map[string]any{"type": "string"}
	integer := map[string]any{"type": "integer"}
	props := map[string]any{
		"intent":            map[string]any{"type": "string", "enum": []string{"list", "count"}},
		"subject":           map[string]any{"type": "string", "enum": []string{"devices", "connections", "jack"}},
		"types":             map[string]any{"type": "array", "items": map[string]any{"type": "string", "enum": model.DeviceTypes}},
		"vendors":           map[string]any{"type": "array", "items": str},
		"os":                str,
		"location":          str,
		"floor":             integer,
		"room":              str,
		"jack":              str,
		"subnet":            str,
		"ip":                str,
		"connected_to":      str,
		"downstream":        map[string]any{"type": "boolean"},
		"medium":            map[string]any{"type": "string", "enum": []string{"", "fiber", "copper"}},
		"port_changed_days": integer,
		"new_days":          integer,
		"status":            map[string]any{"type": "string", "enum": []string{"", "up", "down"}},
		"text":              str,
		"lang":              map[string]any{"type": "string", "enum": []string{"tr", "en"}},
	}
	req := make([]string, 0, len(props))
	for k := range props {
		req = append(req, k)
	}
	return map[string]any{"type": "object", "properties": props, "required": req, "additionalProperties": false}
}

const systemPrompt = `You translate questions about a computer network inventory into search filters.
Questions may be Turkish or English. Output only the filter object; never answer the question and never invent devices or numbers.
Rules:
- intent "count" for how-many questions, otherwise "list".
- subject "connections" for questions about links/cables (e.g. fiber links), "jack" for wall-jack/socket questions, otherwise "devices".
- types uses the given enum; vendors uses manufacturer names exactly as listed when possible.
- Leave a field empty ("" / [] / 0 / false) when the question does not constrain it. floor 0 means no floor filter.
- connected_to must be one of the known device names when the question refers to a device; downstream true for "behind/arkasında".
- location is a free-text location name (e.g. "lab" for laboratuvar).
- lang is the language of the question.`

func (l *LLM) Interpret(ctx context.Context, question string, v Vocabulary) (Query, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	vocab := fmt.Sprintf("Known vendors: %s\nKnown device names: %s\nKnown locations: %s\nKnown operating systems: %s",
		strings.Join(limit(v.Vendors, 80), ", "), strings.Join(limit(v.Devices, 200), ", "),
		strings.Join(limit(v.Locations, 100), ", "), strings.Join(limit(v.OSNames, 50), ", "))
	resp, err := l.client.Messages.New(ctx, anthropic.MessageNewParams{
		Model:     anthropic.Model(l.model),
		MaxTokens: 1024,
		System:    []anthropic.TextBlockParam{{Text: systemPrompt + "\n\n" + vocab}},
		Messages:  []anthropic.MessageParam{anthropic.NewUserMessage(anthropic.NewTextBlock(question))},
		OutputConfig: anthropic.OutputConfigParam{
			Effort: anthropic.OutputConfigEffortLow,
			Format: anthropic.JSONOutputFormatParam{Schema: schema()},
		},
	})
	if err != nil {
		return Query{}, err
	}
	if resp.StopReason == anthropic.StopReasonRefusal {
		return Query{}, errors.New("model declined to interpret the question")
	}
	var text string
	for _, b := range resp.Content {
		if t, ok := b.AsAny().(anthropic.TextBlock); ok {
			text += t.Text
		}
	}
	var lq llmQuery
	if err := json.Unmarshal([]byte(text), &lq); err != nil {
		return Query{}, fmt.Errorf("invalid interpreter output: %w", err)
	}
	return lq.toQuery(v), nil
}

func limit(s []string, n int) []string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// toQuery validates LLM output against known values; unknown device names
// are dropped rather than trusted.
func (lq llmQuery) toQuery(v Vocabulary) Query {
	q := Query{Intent: lq.Intent, Subject: lq.Subject, OS: strings.ToLower(lq.OS), Location: lq.Location, Room: lq.Room,
		Jack: lq.Jack, Subnet: lq.Subnet, IP: lq.IP, Downstream: lq.Downstream, Medium: lq.Medium,
		PortChangedDays: lq.PortChangedDays, NewDays: lq.NewDays, Status: lq.Status, Text: lq.Text, Lang: lq.Lang}
	if q.Intent != "count" {
		q.Intent = "list"
	}
	if q.Subject == "" {
		q.Subject = "devices"
	}
	if q.Lang != "tr" {
		q.Lang = "en"
	}
	for _, t := range lq.Types {
		for _, known := range model.DeviceTypes {
			if t == known && t != model.TypeUnknown {
				q.Types = append(q.Types, t)
			}
		}
	}
	q.Vendors = lq.Vendors
	if lq.Floor > 0 {
		f := lq.Floor
		q.Floor = &f
	}
	if lq.ConnectedTo != "" {
		for _, d := range v.Devices {
			if strings.EqualFold(d, lq.ConnectedTo) {
				q.ConnectedTo = d
			}
		}
	}
	return q
}
