package billingexpr

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCheckOrgBoundable(t *testing.T) {
	tests := []struct {
		name    string
		expr    string
		wantErr error
	}{
		{"flat token pricing", `tier("base", p * 2.5 + c * 15 + cr * 0.25)`, nil},
		{"tiers that only get dearer", `len <= 200000 ? tier("a", p * 3 + c * 15) : tier("b", p * 6 + c * 22.5)`, nil},
		{"long context discount is not monotone", `len <= 200000 ? tier("a", p * 3 + c * 15) : tier("b", p * 1 + c * 15)`, ErrOrgNotMonotone},
		{"output credit is not monotone", `tier("x", 100 + p * 1 - c * 0.1)`, ErrOrgNotMonotone},
		{"max of prices", `tier("x", max(p * 3, cr * 2) + c * 4)`, nil},
		{"min of prices stays monotone", `tier("x", min(p * 3 + c * 15, 5000))`, nil},
		{"fixed request price", `tier("request", fixed(0.01))`, nil},
		{"hour discount multiplier", `tier("b", (hour("UTC") >= 22 ? 0.5 : 1) * (p * 2 + c * 8))`, nil},
		{"hour times minute is exactly 1440", `tier("b", (hour("UTC") * 60 + minute("UTC") > 600 ? 2 : 1) * (p * 2 + c * 8))`, nil},
		{"hour minute weekday is too many probes", `tier("b", (hour("UTC") + minute("UTC") + weekday("UTC") > 600 ? 2 : 1) * (p * 2 + c * 8))`, ErrOrgProbeUnbounded},
		{"timezone read from a header", `tier("b", (hour(header("x-tz")) > 5 ? 2 : 1) * (p * 2 + c * 8))`, ErrOrgProbeUnbounded},
		{"request rule multiplier", `tier("b", p * 5 + c * 25) * (param("service_tier") == "priority" ? 2 : 1)`, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := CheckOrgBoundable(tt.expr)
			if tt.wantErr == nil {
				require.NoError(t, err)
				return
			}
			assert.ErrorIs(t, err, tt.wantErr)
		})
	}
}

func TestOrgUpperBoundCost(t *testing.T) {
	priority := RequestInput{Body: []byte(`{"service_tier":"priority"}`)}
	tests := []struct {
		name    string
		expr    string
		in      OrgBoundInput
		want    float64
		wantErr error
	}{
		{
			name: "unpriced long cache writes fold into p at up to twice its count",
			expr: `tier("base", p * 2.5 + c * 15 + cr * 0.25)`,
			in:   OrgBoundInput{MaxInput: 1000, MaxOutput: 100},
			want: 2*1000*2.5 + 1500,
		},
		{
			name: "cache write counts double when the long writes are not priced",
			expr: `tier("s", p * 3 + c * 15 + cr * 0.3 + cc * 3.75 + cc1h * 6)`,
			in:   OrgBoundInput{MaxInput: 1000, MaxOutput: 100},
			want: 2000*3.75 + 1500,
		},
		{
			name: "all cache writes priced separately",
			expr: `tier("s", p * 3 + c * 15 + cc * 3.75 + cc1h * 6 + cc12h * 6)`,
			in:   OrgBoundInput{MaxInput: 1000, MaxOutput: 100},
			want: 6000 + 1500,
		},
		{
			name: "image input and image output categories",
			expr: `tier("b", p * 1 + img * 5 + c * 2 + img_o * 40)`,
			in:   OrgBoundInput{MaxInput: 100, MaxOutput: 10},
			want: 500 + 400,
		},
		{
			name: "context tier takes the top tier at the input bound",
			expr: `len <= 200000 ? tier("a", p * 3 + c * 15) : tier("b", p * 6 + c * 22.5)`,
			in:   OrgBoundInput{MaxInput: 300000, MaxOutput: 1000},
			want: 2*300000*6 + 1000*22.5,
		},
		{
			name: "small input stays in the low tier",
			expr: `len <= 200000 ? tier("a", p * 3 + c * 15) : tier("b", p * 6 + c * 22.5)`,
			in:   OrgBoundInput{MaxInput: 1000, MaxOutput: 1000},
			want: 2*1000*3 + 1000*15,
		},
		{
			name: "time probe takes the dearest hour",
			expr: `tier("b", (hour("UTC") >= 22 ? 2 : 1) * (p * 2 + c * 8))`,
			in:   OrgBoundInput{MaxInput: 100, MaxOutput: 10},
			want: (400 + 80) * 2,
		},
		{
			name: "probes may also make a window cheaper",
			expr: `tier("b", (minute("UTC") < 30 ? 0.5 : 1) * (p * 2 + c * 8))`,
			in:   OrgBoundInput{MaxInput: 100, MaxOutput: 10},
			want: 400 + 80,
		},
		{
			name: "hour times minute is enumerated",
			expr: `tier("b", (hour("UTC") == 3 && minute("UTC") == 7 ? 4 : 1) * (p * 2 + c * 8))`,
			in:   OrgBoundInput{MaxInput: 100, MaxOutput: 10},
			want: 4 * (400 + 80),
		},
		{
			name:    "too many probe combinations",
			expr:    `tier("b", (hour("UTC") + minute("UTC") + weekday("UTC") > 600 ? 2 : 1) * (p * 2 + c * 8))`,
			in:      OrgBoundInput{MaxInput: 100, MaxOutput: 10},
			wantErr: ErrOrgProbeUnbounded,
		},
		{
			name:    "non monotone expression has no bound",
			expr:    `len <= 200000 ? tier("a", p * 3 + c * 15) : tier("b", p * 1 + c * 15)`,
			in:      OrgBoundInput{MaxInput: 300000, MaxOutput: 1000},
			wantErr: ErrOrgNotMonotone,
		},
		{
			name: "fixed price ignores tokens",
			expr: `tier("request", fixed(0.01))`,
			in:   OrgBoundInput{MaxInput: 123456, MaxOutput: 99999},
			want: 10000,
		},
		{
			name: "min is not convex so every input is raised to the corner",
			expr: `tier("x", min(p * 3 + c * 15, 5000))`,
			in:   OrgBoundInput{MaxInput: 1000, MaxOutput: 100},
			want: 5000,
		},
		{
			name: "param read from the frozen request, matched",
			expr: `tier("b", (param("service_tier") == "priority" ? 2 : 1) * (p * 2 + c * 8))`,
			in:   OrgBoundInput{MaxInput: 100, MaxOutput: 10, Request: priority},
			want: 2 * (400 + 80),
		},
		{
			name: "param read from the frozen request, not matched",
			expr: `tier("b", (param("service_tier") == "priority" ? 2 : 1) * (p * 2 + c * 8))`,
			in:   OrgBoundInput{MaxInput: 100, MaxOutput: 10, Request: RequestInput{Body: []byte(`{}`)}},
			want: 400 + 80,
		},
		{
			name: "task usage fact evaluated at its ceiling",
			expr: `tier("base", u("seconds") * 0.4)`,
			in:   OrgBoundInput{Request: RequestInput{Usage: map[string]any{"seconds": 5.0}}, UsageCeilings: map[string]float64{"seconds": 10}},
			want: 4,
		},
		{
			name:    "task usage fact that gets cheaper with size",
			expr:    `u("seconds") > 5 ? tier("a", u("seconds") * 0.1) : tier("b", u("seconds") * 0.4)`,
			in:      OrgBoundInput{Request: RequestInput{Usage: map[string]any{"seconds": 5.0}}, UsageCeilings: map[string]float64{"seconds": 10}},
			wantErr: ErrOrgNotMonotone,
		},
		{
			name:    "negative bounds are rejected",
			expr:    `tier("base", p * 2.5)`,
			in:      OrgBoundInput{MaxInput: -1, MaxOutput: 1},
			wantErr: ErrOrgBoundInput,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := OrgUpperBoundCost(tt.expr, tt.in)
			if tt.wantErr != nil {
				assert.ErrorIs(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			assert.InDelta(t, tt.want, got, 1e-6)
		})
	}
}

func TestOrgUpperBoundCostIsNotBelowSampledCosts(t *testing.T) {
	expressions := []string{
		`tier("base", p * 2.5 + c * 15 + cr * 0.25 + cc * 3.75)`,
		`len <= 200000 ? tier("a", p * 3 + c * 15 + cr * 0.3) : tier("b", p * 6 + c * 22.5 + cr * 0.6)`,
		`tier("x", max(p * 3, cr * 2) + max(c * 4, img_o * 9))`,
		`tier("x", min(p * 3 + c * 15, 5000) + img * 2)`,
	}
	const maxInput, maxOutput = 4000.0, 500.0
	for _, expression := range expressions {
		bound, err := OrgUpperBoundCost(expression, OrgBoundInput{MaxInput: maxInput, MaxOutput: maxOutput})
		require.NoError(t, err, expression)
		for _, split := range []float64{0, 0.25, 0.5, 1} {
			for _, outSplit := range []float64{0, 0.5, 1} {
				params := TokenParams{
					P: maxInput * (1 - split), CR: maxInput * split / 2, CC: maxInput * split / 4, Img: maxInput * split / 4, Len: maxInput,
					C: maxOutput * (1 - outSplit), ImgO: maxOutput * outSplit,
				}
				actual, _, runErr := RunExpr(expression, params)
				require.NoError(t, runErr)
				assert.LessOrEqualf(t, actual, bound+1e-9, "%s split=%v outSplit=%v", expression, split, outSplit)
			}
		}
	}
}

func TestOrgUpperBoundQuotaBeforeGroupUsesSnapshotConversion(t *testing.T) {
	snap := &BillingSnapshot{ExprString: `tier("base", p * 2 + c * 8)`, ExprVersion: 1, QuotaPerUnit: 500000}
	got, err := OrgUpperBoundQuotaBeforeGroup(snap, OrgBoundInput{MaxInput: 1_000_000, MaxOutput: 1_000_000})
	require.NoError(t, err)
	assert.InDelta(t, 12*500000.0, got, 1e-6, "p counts twice (unpriced long cache writes): $4 + $8 at 500000 quota per unit")

	taskSnap := &BillingSnapshot{ExprString: `tier("base", u("seconds") * 0.4)`, ExprVersion: 1, QuotaPerUnit: 500000, TaskUsageBilling: true}
	got, err = OrgUpperBoundQuotaBeforeGroup(taskSnap, OrgBoundInput{Request: RequestInput{Usage: map[string]any{"seconds": 1.0}}, UsageCeilings: map[string]float64{"seconds": 10}})
	require.NoError(t, err)
	assert.InDelta(t, 4*500000.0, got, 1e-6, "task expressions already return USD")
}
