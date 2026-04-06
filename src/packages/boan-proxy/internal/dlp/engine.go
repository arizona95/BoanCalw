package dlp

import (
	"context"
	"io"
	"strings"
	"sync/atomic"
)

type Action int

const (
	ActionAllow  Action = iota
	ActionRedact
	ActionBlock
)

func (a Action) String() string {
	switch a {
	case ActionAllow:
		return "pass"
	case ActionRedact:
		return "redact"
	case ActionBlock:
		return "block"
	default:
		return "unknown"
	}
}

type DLPMode int

const (
	ModeOR  DLPMode = iota
	ModeAND
)

type Decision struct {
	Action Action
	Level  SLevel
	Reason string
	Body   string
}

type Stats struct {
	TotalInspected uint64
	TotalBlocked   uint64
	TotalRedacted  uint64
	TotalAllowed   uint64
}

type Engine struct {
	llm  *LLMDetector
	mode DLPMode
	stats struct {
		inspected atomic.Uint64
		blocked   atomic.Uint64
		redacted  atomic.Uint64
		allowed   atomic.Uint64
	}
}

func NewEngine(ollamaURL, model string) *Engine {
	return &Engine{llm: NewLLMDetector(ollamaURL, model), mode: ModeOR}
}

func NewEngineWithMode(ollamaURL, model string, mode DLPMode) *Engine {
	return &Engine{llm: NewLLMDetector(ollamaURL, model), mode: mode}
}

func (e *Engine) RulesCount() int {
	return RulesLoaded()
}

func (e *Engine) GetStats() Stats {
	return Stats{
		TotalInspected: e.stats.inspected.Load(),
		TotalBlocked:   e.stats.blocked.Load(),
		TotalRedacted:  e.stats.redacted.Load(),
		TotalAllowed:   e.stats.allowed.Load(),
	}
}

func (e *Engine) Inspect(ctx context.Context, r io.Reader) (*Decision, error) {
	raw, err := io.ReadAll(io.LimitReader(r, 64*1024))
	if err != nil {
		return nil, err
	}
	text := string(raw)
	e.stats.inspected.Add(1)

	findings := Scan(text)
	ruleLevel := MaxLevel(findings)
	ruleNames := MatchedNames(findings)

	llmLevel := SLevel1
	llmFailed := false
	if ruleLevel <= SLevel2 || e.mode == ModeAND {
		llmLevel, err = e.llm.Classify(ctx, text)
		if err != nil {
			llmFailed = true
			llmLevel = SLevel1
		}
	}

	level := e.resolveLevel(ruleLevel, llmLevel, llmFailed)

	reason := strings.Join(ruleNames, ",")
	if llmLevel >= SLevel2 {
		if reason != "" {
			reason += ",llm:" + llmLevel.String()
		} else {
			reason = "llm:" + llmLevel.String()
		}
	}

	var d *Decision
	switch {
	case level >= SLevel3:
		d = &Decision{Action: ActionBlock, Level: level, Reason: reason, Body: text}
		e.stats.blocked.Add(1)
	case level == SLevel2:
		d = &Decision{Action: ActionRedact, Level: level, Reason: reason, Body: Redact(text)}
		e.stats.redacted.Add(1)
	default:
		d = &Decision{Action: ActionAllow, Level: level, Reason: reason, Body: text}
		e.stats.allowed.Add(1)
	}
	return d, nil
}

func (e *Engine) resolveLevel(ruleLevel, llmLevel SLevel, llmFailed bool) SLevel {
	switch e.mode {
	case ModeAND:
		if llmFailed {
			return ruleLevel
		}
		ruleFlag := ruleLevel >= SLevel2
		llmFlag := llmLevel >= SLevel2
		if ruleFlag && llmFlag {
			if llmLevel > ruleLevel {
				return llmLevel
			}
			return ruleLevel
		}
		return SLevel1
	default:
		if llmLevel > ruleLevel {
			return llmLevel
		}
		return ruleLevel
	}
}
