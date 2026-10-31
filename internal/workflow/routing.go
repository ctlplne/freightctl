package workflow

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/ctlplne/freightctl/internal/store"
)

// A program selects a finite subset/order of the definition's exact delivery
// catalog. It cannot construct a destination, a filename or executable code.
type Program struct {
	Nodes []ProgramNode `json:"nodes"`
}
type ProgramNode struct {
	Kind         string        `json:"kind"`
	Step         string        `json:"step,omitempty"`
	StepVariable string        `json:"step_variable,omitempty"`
	When         *Condition    `json:"when,omitempty"`
	Then         []ProgramNode `json:"then,omitempty"`
	Else         []ProgramNode `json:"else,omitempty"`
	Variable     string        `json:"variable,omitempty"`
	Steps        []string      `json:"steps,omitempty"`
	Body         []ProgramNode `json:"body,omitempty"`
	Reason       string        `json:"reason,omitempty"`
}
type Condition struct {
	Op       string      `json:"op"`
	Field    string      `json:"field,omitempty"`
	Variable string      `json:"variable,omitempty"`
	Text     *string     `json:"text,omitempty"`
	Number   *int64      `json:"number,omitempty,string"`
	All      []Condition `json:"all,omitempty"`
	Any      []Condition `json:"any,omitempty"`
	Not      *Condition  `json:"not,omitempty"`
}
type RoutingSource struct {
	CollectionID string `json:"collection_id"`
	ManifestHash string `json:"manifest_hash"`
	Name         string `json:"name"`
	BatchID      string `json:"batch_id"`
	Count        int    `json:"file_count"`
	Index        int    `json:"index"`
}
type RoutingFacts struct {
	File   store.File     `json:"file"`
	Source *RoutingSource `json:"source,omitempty"`
}
type ProgramDecision struct {
	Path     string   `json:"path"`
	Kind     string   `json:"kind"`
	Matched  *bool    `json:"matched,omitempty"`
	Step     string   `json:"step,omitempty"`
	Variable string   `json:"variable,omitempty"`
	Steps    []string `json:"steps,omitempty"`
	Reason   string   `json:"reason,omitempty"`
}
type ExecutionPlan struct {
	Schema      int               `json:"schema_version"`
	Facts       RoutingFacts      `json:"facts"`
	Steps       []string          `json:"selected_steps"`
	Decisions   []ProgramDecision `json:"decisions"`
	LocalReason string            `json:"local_reason,omitempty"`
}

var ErrRouting = errors.New("exact routing facts and an explicit bounded disposition required")

const maxProgramNodes = 64
const maxProgramDepth = 4
const maxProgramVisits = 256

var routingGlob = regexp.MustCompile(`^[A-Za-z0-9._*?-]{1,128}$`)

func routingFieldKind(field string, source bool) string {
	switch field {
	case "file.id", "file.sha256", "file.policy":
		return "text"
	case "file.size_bytes":
		return "number"
	case "source.name", "source.batch_id":
		if source {
			return "text"
		}
	case "source.file_count", "source.index":
		if source {
			return "number"
		}
	}
	return ""
}
func cleanRoutingText(s string) bool {
	if !utf8.ValidString(s) || len(s) < 1 || len(s) > 128 {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

type programNormalizer struct {
	catalog    map[string]bool
	source     bool
	nodes      int
	conditions int
}

func normalizeProgram(d Definition) (*Program, error) {
	if d.Program == nil || len(d.Program.Nodes) < 1 {
		return nil, ErrInput
	}
	n := programNormalizer{catalog: map[string]bool{}, source: d.Source != nil}
	for _, s := range d.Steps {
		n.catalog[s.ID] = true
	}
	nodes, cost, err := n.sequence(d.Program.Nodes, map[string]bool{}, 0)
	if err != nil || cost > maxProgramVisits {
		return nil, ErrInput
	}
	return &Program{Nodes: nodes}, nil
}
func (n *programNormalizer) sequence(in []ProgramNode, variables map[string]bool, depth int) ([]ProgramNode, int, error) {
	if depth >= maxProgramDepth || len(in) > maxProgramNodes {
		return nil, 0, ErrInput
	}
	out := make([]ProgramNode, 0, len(in))
	cost := 0
	for _, v := range in {
		n.nodes++
		if n.nodes > maxProgramNodes {
			return nil, 0, ErrInput
		}
		cost++
		x := ProgramNode{Kind: v.Kind}
		// Field exclusion matters: a deliver node cannot hide a branch or a second
		// recipient behind a field that its executor would otherwise ignore.
		switch v.Kind {
		case "deliver":
			if (v.Step == "") == (v.StepVariable == "") || v.When != nil || len(v.Then) > 0 || len(v.Else) > 0 || v.Variable != "" || len(v.Steps) > 0 || len(v.Body) > 0 || v.Reason != "" {
				return nil, 0, ErrInput
			}
			if v.Step != "" && !n.catalog[v.Step] || v.StepVariable != "" && !variables[v.StepVariable] {
				return nil, 0, ErrInput
			}
			x.Step = v.Step
			x.StepVariable = v.StepVariable
		case "if":
			if v.When == nil || len(v.Then) < 1 || v.Step != "" || v.StepVariable != "" || v.Variable != "" || len(v.Steps) > 0 || len(v.Body) > 0 || v.Reason != "" {
				return nil, 0, ErrInput
			}
			condition, terms, err := n.condition(*v.When, variables, 0)
			if err != nil {
				return nil, 0, err
			}
			x.When = &condition
			cost += terms
			var a, b int
			x.Then, a, err = n.sequence(v.Then, variables, depth+1)
			if err != nil {
				return nil, 0, err
			}
			if len(v.Else) > 0 {
				x.Else, b, err = n.sequence(v.Else, variables, depth+1)
				if err != nil {
					return nil, 0, err
				}
			}
			// Counting both paths is a conservative work budget, independent of data.
			cost += a + b
		case "for_each":
			if !stepPattern.MatchString(v.Variable) || variables[v.Variable] || len(v.Steps) < 1 || len(v.Steps) > 16 || len(v.Body) < 1 || v.When != nil || len(v.Then) > 0 || len(v.Else) > 0 || v.Step != "" || v.StepVariable != "" || v.Reason != "" {
				return nil, 0, ErrInput
			}
			seen := map[string]bool{}
			for _, id := range v.Steps {
				if !n.catalog[id] || seen[id] {
					return nil, 0, ErrInput
				}
				seen[id] = true
			}
			inner := make(map[string]bool, len(variables)+1)
			for k, v := range variables {
				inner[k] = v
			}
			inner[v.Variable] = true
			body, b, err := n.sequence(v.Body, inner, depth+1)
			if err != nil {
				return nil, 0, err
			}
			x.Variable = v.Variable
			x.Steps = append([]string{}, v.Steps...)
			x.Body = body
			cost += len(v.Steps) * b
		case "keep_local":
			if !stepPattern.MatchString(v.Reason) || v.Step != "" || v.StepVariable != "" || v.When != nil || len(v.Then) > 0 || len(v.Else) > 0 || v.Variable != "" || len(v.Steps) > 0 || len(v.Body) > 0 {
				return nil, 0, ErrInput
			}
			x.Reason = v.Reason
		default:
			return nil, 0, ErrInput
		}
		if cost > maxProgramVisits {
			return nil, 0, ErrInput
		}
		out = append(out, x)
	}
	return out, cost, nil
}
func (n *programNormalizer) condition(v Condition, variables map[string]bool, depth int) (Condition, int, error) {
	n.conditions++
	if depth > 3 || n.conditions > maxProgramNodes {
		return Condition{}, 0, ErrInput
	}
	x := Condition{Op: v.Op}
	cost := 1
	switch v.Op {
	case "all", "any", "not":
		if v.Field != "" || v.Variable != "" || v.Text != nil || v.Number != nil {
			return x, 0, ErrInput
		}
		var inputs []Condition
		if v.Op == "all" {
			if len(v.All) < 1 || len(v.All) > 16 || len(v.Any) > 0 || v.Not != nil {
				return x, 0, ErrInput
			}
			inputs = v.All
		}
		if v.Op == "any" {
			if len(v.Any) < 1 || len(v.Any) > 16 || len(v.All) > 0 || v.Not != nil {
				return x, 0, ErrInput
			}
			inputs = v.Any
		}
		if v.Op == "not" {
			if v.Not == nil || len(v.All) > 0 || len(v.Any) > 0 {
				return x, 0, ErrInput
			}
			inputs = []Condition{*v.Not}
		}
		values := make([]Condition, 0, len(inputs))
		for _, c := range inputs {
			child, k, err := n.condition(c, variables, depth+1)
			if err != nil {
				return x, 0, err
			}
			values = append(values, child)
			cost += k
		}
		switch v.Op {
		case "all":
			x.All = values
		case "any":
			x.Any = values
		case "not":
			x.Not = &values[0]
		}
	default:
		if len(v.All) > 0 || len(v.Any) > 0 || v.Not != nil || (v.Field == "") == (v.Variable == "") {
			return x, 0, ErrInput
		}
		kind := routingFieldKind(v.Field, n.source)
		if v.Variable != "" {
			if !variables[v.Variable] {
				return x, 0, ErrInput
			}
			kind = "text"
		}
		if kind == "" {
			return x, 0, ErrInput
		}
		if kind == "number" {
			if v.Number == nil || *v.Number < 0 || v.Text != nil || !containsRoutingOp(v.Op, "eq", "ne", "lt", "le", "gt", "ge") {
				return x, 0, ErrInput
			}
			value := *v.Number
			x.Number = &value
		} else {
			if v.Text == nil || !cleanRoutingText(*v.Text) || v.Number != nil || !containsRoutingOp(v.Op, "eq", "ne", "prefix", "suffix", "glob") {
				return x, 0, ErrInput
			}
			if v.Op == "glob" && !routingGlob.MatchString(*v.Text) {
				return x, 0, ErrInput
			}
			if v.Field == "file.sha256" && (!containsRoutingOp(v.Op, "eq", "ne") || !hashPattern.MatchString(*v.Text)) {
				return x, 0, ErrInput
			}
			if (v.Field == "file.id" || v.Field == "source.batch_id") && (!containsRoutingOp(v.Op, "eq", "ne") || !store.ValidID(*v.Text)) {
				return x, 0, ErrInput
			}
			value := *v.Text
			x.Text = &value
		}
		x.Field = v.Field
		x.Variable = v.Variable
	}
	return x, cost, nil
}
func containsRoutingOp(value string, options ...string) bool {
	for _, v := range options {
		if v == value {
			return true
		}
	}
	return false
}

func validRoutingFacts(d Definition, f RoutingFacts) bool {
	file := f.File
	if !store.ValidID(file.ID) || !store.ValidID(file.EventID) || file.Size < 0 || file.Size > 1<<30 || !hashPattern.MatchString(file.SHA256) || !cleanRoutingText(file.Policy) {
		return false
	}
	if d.Source == nil {
		return f.Source == nil
	}
	if f.Source == nil {
		return false
	}
	s := f.Source
	return store.ValidID(s.CollectionID) && hashPattern.MatchString(s.ManifestHash) && filenamePattern.MatchString(s.Name) && !strings.HasSuffix(s.Name, ".ready.json") && store.ValidID(s.BatchID) && s.Count > 0 && s.Count <= d.Source.MaxFiles && s.Index >= 0 && s.Index < s.Count && file.Size <= d.Source.MaxFile
}

type programCompiler struct {
	plan    *ExecutionPlan
	visits  int
	emitted map[string]bool
}

func CompileProgram(d Definition, facts RoutingFacts) (*ExecutionPlan, error) {
	d, err := Normalize(d)
	if err != nil {
		return nil, err
	}
	if d.Schema != 2 || d.Program == nil || !validRoutingFacts(d, facts) {
		return nil, ErrRouting
	}
	if facts.Source != nil {
		source := *facts.Source
		facts.Source = &source
	}
	c := programCompiler{plan: &ExecutionPlan{Schema: 1, Facts: facts, Steps: []string{}, Decisions: []ProgramDecision{}}, emitted: map[string]bool{}}
	if err = c.sequence(d.Program.Nodes, map[string]string{}, ""); err != nil {
		return nil, err
	}
	if len(c.plan.Steps) == 0 && c.plan.LocalReason == "" || len(c.plan.Steps) > 0 && c.plan.LocalReason != "" {
		return nil, ErrRouting
	}
	encoded, _, err := digest(c.plan)
	if err != nil {
		return nil, err
	}
	if len(encoded) > 24<<10 {
		return nil, store.ErrLimit
	}
	return c.plan, nil
}
func (c *programCompiler) visit() error {
	c.visits++
	if c.visits > maxProgramVisits {
		return store.ErrLimit
	}
	return nil
}
func (c *programCompiler) sequence(nodes []ProgramNode, vars map[string]string, prefix string) error {
	for i, n := range nodes {
		if err := c.visit(); err != nil {
			return err
		}
		path := fmt.Sprintf("%s%d", prefix, i)
		switch n.Kind {
		case "deliver":
			id := n.Step
			if n.StepVariable != "" {
				id = vars[n.StepVariable]
			}
			if id == "" || c.emitted[id] || c.plan.LocalReason != "" {
				return ErrRouting
			}
			c.emitted[id] = true
			c.plan.Steps = append(c.plan.Steps, id)
			c.plan.Decisions = append(c.plan.Decisions, ProgramDecision{Path: path, Kind: n.Kind, Step: id})
		case "if":
			matched, err := c.condition(*n.When, vars)
			if err != nil {
				return err
			}
			c.plan.Decisions = append(c.plan.Decisions, ProgramDecision{Path: path, Kind: n.Kind, Matched: &matched})
			branch, suffix := n.Else, ".else."
			if matched {
				branch, suffix = n.Then, ".then."
			}
			if err = c.sequence(branch, vars, path+suffix); err != nil {
				return err
			}
		case "for_each":
			c.plan.Decisions = append(c.plan.Decisions, ProgramDecision{Path: path, Kind: n.Kind, Variable: n.Variable, Steps: append([]string{}, n.Steps...)})
			for index, step := range n.Steps {
				inner := make(map[string]string, len(vars)+1)
				for k, v := range vars {
					inner[k] = v
				}
				inner[n.Variable] = step
				if err := c.sequence(n.Body, inner, fmt.Sprintf("%s[%d].body.", path, index)); err != nil {
					return err
				}
			}
		case "keep_local":
			if len(c.plan.Steps) > 0 || c.plan.LocalReason != "" {
				return ErrRouting
			}
			c.plan.LocalReason = n.Reason
			c.plan.Decisions = append(c.plan.Decisions, ProgramDecision{Path: path, Kind: n.Kind, Reason: n.Reason})
		default:
			return ErrRouting
		}
	}
	return nil
}
func (c *programCompiler) condition(v Condition, vars map[string]string) (bool, error) {
	if err := c.visit(); err != nil {
		return false, err
	}
	if v.Op == "not" {
		value, err := c.condition(*v.Not, vars)
		return !value, err
	}
	if v.Op == "all" || v.Op == "any" {
		group := v.All
		if v.Op == "any" {
			group = v.Any
		}
		for _, term := range group {
			value, err := c.condition(term, vars)
			if err != nil {
				return false, err
			}
			if v.Op == "all" && !value {
				return false, nil
			}
			if v.Op == "any" && value {
				return true, nil
			}
		}
		return v.Op == "all", nil
	}
	var text string
	var number int64
	f := c.plan.Facts
	switch v.Field {
	case "file.id":
		text = f.File.ID
	case "file.sha256":
		text = f.File.SHA256
	case "file.policy":
		text = f.File.Policy
	case "file.size_bytes":
		number = f.File.Size
	case "source.name":
		if f.Source == nil {
			return false, ErrRouting
		}
		text = f.Source.Name
	case "source.batch_id":
		if f.Source == nil {
			return false, ErrRouting
		}
		text = f.Source.BatchID
	case "source.file_count":
		if f.Source == nil {
			return false, ErrRouting
		}
		number = int64(f.Source.Count)
	case "source.index":
		if f.Source == nil {
			return false, ErrRouting
		}
		number = int64(f.Source.Index)
	default:
		var ok bool
		text, ok = vars[v.Variable]
		if !ok {
			return false, ErrRouting
		}
	}
	if v.Number != nil {
		rhs := *v.Number
		switch v.Op {
		case "eq":
			return number == rhs, nil
		case "ne":
			return number != rhs, nil
		case "lt":
			return number < rhs, nil
		case "le":
			return number <= rhs, nil
		case "gt":
			return number > rhs, nil
		case "ge":
			return number >= rhs, nil
		}
		return false, ErrRouting
	}
	rhs := *v.Text
	switch v.Op {
	case "eq":
		return text == rhs, nil
	case "ne":
		return text != rhs, nil
	case "prefix":
		return strings.HasPrefix(text, rhs), nil
	case "suffix":
		return strings.HasSuffix(text, rhs), nil
	case "glob":
		pattern := "^"
		for _, ch := range rhs {
			switch ch {
			case '*':
				pattern += ".*"
			case '?':
				pattern += "."
			default:
				pattern += regexp.QuoteMeta(string(ch))
			}
		}
		pattern += "$"
		matched, err := regexp.MatchString(pattern, text)
		if err != nil {
			return false, ErrRouting
		}
		return matched, nil
	}
	return false, ErrRouting
}
