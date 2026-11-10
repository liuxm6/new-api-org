package billingexpr

import (
	"errors"
	"fmt"
	"math"
	"slices"
	"sort"
	"strings"
	"sync"

	"github.com/expr-lang/expr/ast"
)

// Organization cost upper bound (design 4.2.1).
//
// An organization request reserves a true upper bound of its charge before the
// upstream call. For an expression that bound exists when the expression never
// gets cheaper as any token variable grows (checked on a grid of values); the
// bound is then the expression evaluated at the dearest corner of the feasible
// token region. Expressions that fail the check have no bound and need an
// administrator-set max_request_cost.

var (
	// ErrOrgNotMonotone means the expression gets cheaper somewhere as a token
	// variable (or a bounded usage fact) grows, so no corner is the maximum.
	ErrOrgNotMonotone = errors.New("billing expression is not monotone in its token variables")
	// ErrOrgProbeUnbounded means the hour/minute/weekday/month/day probes it
	// reads have more than OrgMaxProbeCombinations combinations, or a timezone
	// that is not a string literal.
	ErrOrgProbeUnbounded = errors.New("billing expression reads too many time probe combinations")
	// ErrOrgNotEvaluable means the expression failed to evaluate at a grid point.
	ErrOrgNotEvaluable = errors.New("billing expression cannot be evaluated for bounding")
	// ErrOrgUsageUnbounded means a task usage fact has no ceiling.
	ErrOrgUsageUnbounded = errors.New("billing expression reads a usage fact without a ceiling")
	// ErrOrgBoundInput means the bound inputs are negative or not finite.
	ErrOrgBoundInput = errors.New("invalid organization bound input")
)

// OrgMaxProbeCombinations is the largest product of probe cardinalities that is
// enumerated; 24 hours times 60 minutes is exactly this many.
const OrgMaxProbeCombinations = 1440

// longCacheWriteWeight bounds how many times an unpriced long-lived cache write
// is counted: OpenAI bills a 12h write at twice the short write price and
// Claude a 1h write at 6/3.75 times (settlement folds them into cc, or p).
const longCacheWriteWeight = 2.0

// OrgBoundInput describes the feasible region of one request.
type OrgBoundInput struct {
	// MaxInput bounds the total input tokens (the context length).
	MaxInput float64
	// MaxOutput bounds the total output tokens, reasoning included.
	MaxOutput float64
	// Request is the frozen request: param()/header() read it as settlement
	// will, and Usage carries the submission-time task facts.
	Request RequestInput
	// UsageCeilings gives the largest value of each numeric task usage fact the
	// request can settle at. A numeric fact it does not list has no bound.
	UsageCeilings map[string]float64
}

var (
	inputTokenVars  = []string{"p", "cr", "cc", "cc1h", "cc12h", "img", "img_cr", "ai"}
	outputTokenVars = []string{"c", "img_o", "ao"}
	tokenVarNames   = append(append([]string{"len"}, inputTokenVars...), outputTokenVars...)
)

type probeSpec struct {
	key    string
	values []int
}

func probeKey(function, timezone string) string {
	return function + "\x00" + strings.TrimSpace(timezone)
}

func probeValues(function string) []int {
	var first, count int
	switch function {
	case "hour":
		first, count = 0, 24
	case "minute":
		first, count = 0, 60
	case "weekday":
		first, count = 0, 7
	case "month":
		first, count = 1, 12
	case "day":
		first, count = 1, 31
	}
	values := make([]int, count)
	for i := range values {
		values[i] = first + i
	}
	return values
}

func collectProbes(node ast.Node) ([]probeSpec, error) {
	var specs []probeSpec
	seen := map[string]bool{}
	var failure error
	ast.Find(node, func(n ast.Node) bool {
		call, ok := n.(*ast.CallNode)
		if !ok {
			return false
		}
		callee, ok := call.Callee.(*ast.IdentifierNode)
		if !ok || len(probeValues(callee.Value)) == 0 {
			return false
		}
		literal, ok := call.Arguments[0].(*ast.StringNode)
		if len(call.Arguments) != 1 || !ok {
			failure = fmt.Errorf("%w: %s reads a timezone that is not a string literal", ErrOrgProbeUnbounded, callee.Value)
			return false
		}
		key := probeKey(callee.Value, literal.Value)
		if !seen[key] {
			seen[key] = true
			specs = append(specs, probeSpec{key: key, values: probeValues(callee.Value)})
		}
		return false
	})
	if failure != nil {
		return nil, failure
	}
	combinations := 1
	for _, spec := range specs {
		combinations *= len(spec.values)
		if combinations > OrgMaxProbeCombinations {
			return nil, fmt.Errorf("%w: more than %d combinations", ErrOrgProbeUnbounded, OrgMaxProbeCombinations)
		}
	}
	return specs, nil
}

// probeAssignments enumerates every probe combination, or only min/mid/max of
// each probe when sample is set.
func probeAssignments(specs []probeSpec, sample bool) []map[string]int {
	assignments := []map[string]int{nil}
	if len(specs) > 0 {
		assignments = []map[string]int{{}}
	}
	for _, spec := range specs {
		values := spec.values
		if sample && len(values) > 3 {
			values = []int{values[0], values[len(values)/2], values[len(values)-1]}
		}
		next := make([]map[string]int, 0, len(assignments)*len(values))
		for _, base := range assignments {
			for _, value := range values {
				assignment := make(map[string]int, len(base)+1)
				for k, v := range base {
					assignment[k] = v
				}
				assignment[spec.key] = value
				next = append(next, assignment)
			}
		}
		assignments = next
	}
	return assignments
}

type orgAnalysis struct {
	entry       *cachedEntry
	probes      []probeSpec
	tokenDims   []string // token variables the expression reads
	usageKeys   []string // literal u("key") facts
	dynamicU    bool     // u() with a non-literal key
	thresholds  []float64
	requestFree bool // result does not depend on param/header/usage
}

func analyzeOrgExpr(expression string) (*orgAnalysis, error) {
	entry, err := compileEntryFromCacheByHash(expression, ExprHashString(expression))
	if err != nil {
		return nil, err
	}
	probes, err := collectProbes(entry.prog.Node())
	if err != nil {
		return nil, err
	}
	analysis := &orgAnalysis{entry: entry, probes: probes}
	for _, name := range tokenVarNames {
		if entry.usedVars[name] {
			analysis.tokenDims = append(analysis.tokenDims, name)
		}
	}
	for key := range entry.usedUsageKeys {
		analysis.usageKeys = append(analysis.usageKeys, key)
	}
	sort.Strings(analysis.usageKeys)
	ast.Find(entry.prog.Node(), func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.CallNode:
			if callee, ok := node.Callee.(*ast.IdentifierNode); ok && callee.Value == "u" && len(node.Arguments) == 1 {
				if _, literal := node.Arguments[0].(*ast.StringNode); !literal {
					analysis.dynamicU = true
				}
			}
		case *ast.BinaryNode:
			switch node.Operator {
			case "<", "<=", ">", ">=", "==", "!=":
				for _, side := range []ast.Node{node.Left, node.Right} {
					if value, ok := requestRuleNumber(side); ok && value >= 0 && value <= 1e12 {
						analysis.thresholds = append(analysis.thresholds, value)
					}
				}
			}
		}
		return false
	})
	analysis.requestFree = !entry.usedVars["param"] && !entry.usedVars["header"] && !entry.usedVars["u"] && !entry.usedVars["has"]
	return analysis, nil
}

// orgEvaluator evaluates the compiled expression at points of the feasible region.
type orgEvaluator struct {
	analysis *orgAnalysis
	request  RequestInput
	frozen   map[string]any
}

func (e *orgEvaluator) eval(vector map[string]float64, probes map[string]int) (float64, error) {
	request := e.request
	request.probes = probes
	if len(e.analysis.usageKeys) > 0 {
		usage := make(map[string]any, len(e.frozen)+len(e.analysis.usageKeys))
		for k, v := range e.frozen {
			usage[k] = v
		}
		for _, key := range e.analysis.usageKeys {
			if value, ok := vector["u:"+key]; ok {
				usage[key] = value
			}
		}
		request.Usage = usage
	}
	params := TokenParams{
		P: vector["p"], C: vector["c"], Len: vector["len"], CR: vector["cr"], CC: vector["cc"],
		CC1h: vector["cc1h"], CC12h: vector["cc12h"], Img: vector["img"], ImgCR: vector["img_cr"],
		ImgO: vector["img_o"], AI: vector["ai"], AO: vector["ao"],
	}
	entry := e.analysis.entry
	out, _, err := runProgram(entry.prog, entry.requestRules, entry.usedVars, params, request)
	if err != nil {
		return 0, fmt.Errorf("%w: %v", ErrOrgNotEvaluable, err)
	}
	if math.IsNaN(out) || math.IsInf(out, 0) {
		return 0, fmt.Errorf("%w: non-finite result", ErrOrgNotEvaluable)
	}
	return out, nil
}

var orgMonotoneBaseGrid = []float64{0, 1, 2, 10, 100, 1000, 10000, 1e5, 1e6, 1e7, 1e8, 1e9}

func (a *orgAnalysis) tokenGrid() []float64 {
	grid := append([]float64(nil), orgMonotoneBaseGrid...)
	for _, threshold := range a.thresholds {
		// Literals may be scaled (len / 1000 > 200), so probe common scales too.
		for _, scale := range []float64{1, 1e3, 1e6} {
			v := threshold * scale
			grid = append(grid, v-1, v, v+1)
		}
	}
	grid = slices.DeleteFunc(grid, func(v float64) bool { return v < 0 || v > 1e12 })
	slices.Sort(grid)
	grid = slices.Compact(grid)
	if len(grid) > 160 {
		thinned := grid[:0:0]
		for i, v := range grid {
			if i%2 == 0 || slices.Contains(a.thresholds, v) {
				thinned = append(thinned, v)
			}
		}
		grid = thinned
	}
	return grid
}

func usageGrid(ceiling float64, thresholds []float64) []float64 {
	grid := []float64{0, ceiling}
	for _, v := range []float64{0.5, 1, 2, 3, 5, 10, 60, 128, 600, 3600} {
		if v < ceiling {
			grid = append(grid, v)
		}
	}
	for _, threshold := range thresholds {
		for _, v := range []float64{threshold - 1, threshold, threshold + 1} {
			if v >= 0 && v <= ceiling {
				grid = append(grid, v)
			}
		}
	}
	slices.Sort(grid)
	return slices.Compact(grid)
}

func (a *orgAnalysis) checkMonotone(request RequestInput, ceilings map[string]float64) error {
	frozen := request.Usage
	evaluator := &orgEvaluator{analysis: a, request: request, frozen: frozen}
	backgrounds := []float64{0, 1000, 1e6, 1e8}
	assignments := probeAssignments(a.probes, true)

	type dimension struct {
		name string
		grid []float64
	}
	var dims []dimension
	grid := a.tokenGrid()
	for _, name := range a.tokenDims {
		dims = append(dims, dimension{name: name, grid: grid})
	}
	for _, key := range a.usageKeys {
		if ceiling, ok := ceilings[key]; ok {
			dims = append(dims, dimension{name: "u:" + key, grid: usageGrid(ceiling, a.thresholds)})
		}
	}
	for _, dim := range dims {
		for _, background := range backgrounds {
			for _, probes := range assignments {
				vector := make(map[string]float64, len(dims))
				for _, other := range dims {
					if strings.HasPrefix(other.name, "u:") {
						vector[other.name] = ceilings[strings.TrimPrefix(other.name, "u:")]
					} else {
						vector[other.name] = background
					}
				}
				previous := math.Inf(-1)
				for _, point := range dim.grid {
					vector[dim.name] = point
					value, err := evaluator.eval(vector, probes)
					if err != nil {
						return err
					}
					if value < previous-1e-9*math.Max(1, math.Abs(previous)) {
						return fmt.Errorf("%w: %s at %g", ErrOrgNotMonotone, strings.TrimPrefix(dim.name, "u:"), point)
					}
					previous = value
				}
			}
		}
	}
	return nil
}

var (
	orgMonotoneCacheMu sync.Mutex
	orgMonotoneCache   = map[string]error{}
)

// CheckOrgBoundable is the save-time check: it reports why an expression has no
// organization cost bound, or nil. Expressions that read task usage facts or
// need a request to evaluate can only be bounded per request with ceilings.
// Optional samples are example requests for param()/header() reads.
func CheckOrgBoundable(expression string, samples ...RequestInput) error {
	analysis, err := analyzeOrgExpr(expression)
	if err != nil {
		return err
	}
	if len(analysis.usageKeys) > 0 || analysis.dynamicU {
		return ErrOrgUsageUnbounded
	}
	if len(samples) == 0 {
		samples = []RequestInput{{}}
	}
	for _, sample := range samples {
		if err := analysis.checkMonotone(sample, nil); err != nil {
			return err
		}
	}
	return nil
}

func validOrgBoundNumber(v float64) bool {
	return v >= 0 && !math.IsNaN(v) && !math.IsInf(v, 0)
}

// OrgUpperBoundCost returns the largest value the expression can evaluate to
// anywhere in the feasible region, in the expression's own units (USD per 1M
// tokens for token expressions, USD for task usage expressions). It errors with
// one of the ErrOrg* values when no bound can be proven.
func OrgUpperBoundCost(expression string, in OrgBoundInput) (float64, error) {
	if !validOrgBoundNumber(in.MaxInput) || !validOrgBoundNumber(in.MaxOutput) {
		return 0, ErrOrgBoundInput
	}
	for _, ceiling := range in.UsageCeilings {
		if !validOrgBoundNumber(ceiling) {
			return 0, ErrOrgBoundInput
		}
	}
	analysis, err := analyzeOrgExpr(expression)
	if err != nil {
		return 0, err
	}
	if analysis.dynamicU {
		return 0, fmt.Errorf("%w: u() with a computed key", ErrOrgUsageUnbounded)
	}
	for _, key := range analysis.usageKeys {
		if _, ok := in.UsageCeilings[key]; ok {
			continue
		}
		// Enum facts keep their frozen value; a numeric fact may be replaced by
		// a measured value at completion and so needs a ceiling.
		if _, enum := in.Request.Usage[key].(string); !enum {
			return 0, fmt.Errorf("%w: %s", ErrOrgUsageUnbounded, key)
		}
	}

	if err := analysis.cachedMonotone(expression, in); err != nil {
		return 0, err
	}

	vertices := analysis.vertices(in)
	evaluator := &orgEvaluator{analysis: analysis, request: in.Request, frozen: in.Request.Usage}
	best := math.Inf(-1)
	for _, probes := range probeAssignments(analysis.probes, false) {
		for _, vertex := range vertices {
			for _, key := range analysis.usageKeys {
				if ceiling, ok := in.UsageCeilings[key]; ok {
					vertex["u:"+key] = ceiling
				}
			}
			value, err := evaluator.eval(vertex, probes)
			if err != nil {
				return 0, err
			}
			best = math.Max(best, value)
		}
	}
	return best, nil
}

func (a *orgAnalysis) cachedMonotone(expression string, in OrgBoundInput) error {
	cacheable := a.requestFree && len(a.usageKeys) == 0
	hash := ExprHashString(expression)
	if cacheable {
		orgMonotoneCacheMu.Lock()
		result, ok := orgMonotoneCache[hash]
		orgMonotoneCacheMu.Unlock()
		if ok {
			return result
		}
	}
	result := a.checkMonotone(in.Request, in.UsageCeilings)
	if cacheable {
		orgMonotoneCacheMu.Lock()
		if len(orgMonotoneCache) >= maxCacheSize {
			orgMonotoneCache = map[string]error{}
		}
		orgMonotoneCache[hash] = result
		orgMonotoneCacheMu.Unlock()
	}
	return result
}

// vertices lists the corners of the feasible token region to evaluate. With a
// shape whose maximum provably sits at a vertex, each input (output) category
// takes the whole budget in turn; otherwise every category is raised to its own
// maximum at once, which a monotone expression cannot undercut.
func (a *orgAnalysis) vertices(in OrgBoundInput) []map[string]float64 {
	used := a.entry.usedVars
	inputs, outputs := []string{}, []string{}
	for _, name := range inputTokenVars {
		if used[name] {
			inputs = append(inputs, name)
		}
	}
	for _, name := range outputTokenVars {
		if used[name] {
			outputs = append(outputs, name)
		}
	}

	if !linearSafe(a.entry.prog.Node()) {
		corner := map[string]float64{"len": in.MaxInput}
		for _, name := range inputs {
			corner[name] = in.MaxInput * longCacheWriteWeight
		}
		for _, name := range outputs {
			corner[name] = in.MaxOutput
		}
		return []map[string]float64{corner}
	}

	// Unpriced long-lived cache writes are folded into cc, or into p, by
	// settlement, so those two can count a token more than once.
	longWriteUnpriced := !used["cc12h"] || !used["cc1h"]
	weight := func(name string) float64 {
		switch {
		case name == "cc" && longWriteUnpriced:
			return longCacheWriteWeight
		case name == "p" && !used["cc"] && longWriteUnpriced:
			return longCacheWriteWeight
		}
		return 1
	}
	inputVertices := []map[string]float64{{}}
	if len(inputs) > 0 {
		inputVertices = nil
		for _, name := range inputs {
			inputVertices = append(inputVertices, map[string]float64{name: in.MaxInput * weight(name)})
		}
	}
	outputVertices := []map[string]float64{{}}
	if len(outputs) > 0 {
		outputVertices = nil
		for _, name := range outputs {
			outputVertices = append(outputVertices, map[string]float64{name: in.MaxOutput})
		}
	}
	vertices := make([]map[string]float64, 0, len(inputVertices)*len(outputVertices))
	for _, input := range inputVertices {
		for _, output := range outputVertices {
			vertex := map[string]float64{"len": in.MaxInput}
			for k, v := range input {
				vertex[k] = v
			}
			for k, v := range output {
				vertex[k] = v
			}
			vertices = append(vertices, vertex)
		}
	}
	return vertices
}

// linearSafe reports whether, for a fixed branch, the expression is a convex
// piecewise-linear function of the token variables with non-negative
// coefficients, so its maximum over a simplex sits at a vertex. Anything it
// cannot prove returns false and the caller falls back to the corner bound.
func linearSafe(node ast.Node) bool {
	_, ok := linearShape(node)
	return ok
}

func isTokenIdentifier(name string) bool {
	return name != "len" && slices.Contains(tokenVarNames, name)
}

// linearShape returns whether the node depends on a token variable and whether
// it keeps the convex, non-negative-coefficient shape.
func linearShape(node ast.Node) (hasVar, ok bool) {
	switch n := node.(type) {
	case *ast.NilNode, *ast.IntegerNode, *ast.FloatNode, *ast.BoolNode, *ast.StringNode, *ast.ConstantNode:
		return false, true
	case *ast.IdentifierNode:
		return isTokenIdentifier(n.Value), true
	case *ast.UnaryNode:
		inner, innerOK := linearShape(n.Node)
		if inner {
			return true, false
		}
		return false, innerOK
	case *ast.BinaryNode:
		return linearBinary(n)
	case *ast.ConditionalNode:
		condVar, condOK := linearShape(n.Cond)
		firstVar, firstOK := linearShape(n.Exp1)
		secondVar, secondOK := linearShape(n.Exp2)
		return condVar || firstVar || secondVar, !condVar && condOK && firstOK && secondOK
	case *ast.CallNode:
		return linearCall(n)
	default:
		return true, false
	}
}

func linearBinary(n *ast.BinaryNode) (hasVar, ok bool) {
	leftVar, leftOK := linearShape(n.Left)
	rightVar, rightOK := linearShape(n.Right)
	both := leftOK && rightOK
	switch n.Operator {
	case "+":
		return leftVar || rightVar, both
	case "-":
		return leftVar || rightVar, both && !rightVar
	case "*":
		switch {
		case leftVar && rightVar:
			return true, false
		case leftVar:
			return true, both && nonNegativeConstant(n.Right)
		case rightVar:
			return true, both && nonNegativeConstant(n.Left)
		}
		return false, both
	case "/":
		switch {
		case rightVar:
			return true, false
		case leftVar:
			return true, both && nonNegativeConstant(n.Right)
		}
		return false, both
	default:
		// Comparisons, logic and anything else are safe only when no token
		// variable reaches them.
		return leftVar || rightVar, both && !leftVar && !rightVar
	}
}

func linearCall(n *ast.CallNode) (hasVar, ok bool) {
	callee, isIdentifier := n.Callee.(*ast.IdentifierNode)
	if !isIdentifier {
		return true, false
	}
	shapes := make([][2]bool, len(n.Arguments))
	for i, argument := range n.Arguments {
		shapes[i][0], shapes[i][1] = linearShape(argument)
	}
	switch callee.Value {
	case "tier":
		if len(shapes) != 2 {
			return true, false
		}
		return shapes[1][0], shapes[1][1] && !shapes[0][0]
	case "_trace", "_trace_int":
		if len(shapes) != 3 {
			return true, false
		}
		return false, !shapes[1][0] && shapes[1][1] && shapes[2][1] && !shapes[2][0]
	case "max":
		for _, shape := range shapes {
			hasVar = hasVar || shape[0]
			ok = shape[1]
			if !ok {
				return true, false
			}
		}
		return hasVar, true
	case "min", "abs", "ceil", "floor":
		for _, shape := range shapes {
			if shape[0] || !shape[1] {
				return true, false
			}
		}
		return false, true
	case "fixed", "header", "param", "u", "has", "hour", "minute", "weekday", "month", "day":
		for _, shape := range shapes {
			if shape[0] || !shape[1] {
				return true, false
			}
		}
		return false, true
	}
	return true, false
}

// nonNegativeConstant reports whether a token-free node can never be negative.
func nonNegativeConstant(node ast.Node) bool {
	switch n := node.(type) {
	case *ast.IntegerNode:
		return n.Value >= 0
	case *ast.FloatNode:
		return n.Value >= 0
	case *ast.IdentifierNode:
		return n.Value == "image_count"
	case *ast.BinaryNode:
		switch n.Operator {
		case "+", "*", "/":
			return nonNegativeConstant(n.Left) && nonNegativeConstant(n.Right)
		}
		return false
	case *ast.ConditionalNode:
		return nonNegativeConstant(n.Exp1) && nonNegativeConstant(n.Exp2)
	case *ast.CallNode:
		callee, ok := n.Callee.(*ast.IdentifierNode)
		if !ok {
			return false
		}
		switch callee.Value {
		case "abs":
			return true
		case "fixed":
			return true
		case "u":
			return true
		case "max", "min", "ceil", "floor", "tier":
			for _, argument := range n.Arguments {
				if _, literal := argument.(*ast.StringNode); literal {
					continue
				}
				if !nonNegativeConstant(argument) {
					return false
				}
			}
			return true
		case "_trace", "_trace_int":
			return len(n.Arguments) == 3 && nonNegativeConstant(n.Arguments[2])
		}
	}
	return false
}

// OrgUpperBoundQuotaBeforeGroup converts the expression bound to quota before
// the group ratio, with the same version-dispatched conversion settlement uses.
func OrgUpperBoundQuotaBeforeGroup(snap *BillingSnapshot, in OrgBoundInput) (float64, error) {
	raw, err := OrgUpperBoundCost(snap.ExprString, in)
	if err != nil {
		return 0, err
	}
	return quotaConversion(raw, snap), nil
}
