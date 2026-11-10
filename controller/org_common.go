package controller

import (
	"context"
	"io"
	"net/http"
	"slices"
	"strconv"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/middleware"
	"github.com/QuantumNous/new-api/model"
	orgsvc "github.com/QuantumNous/new-api/service/org"
	"github.com/QuantumNous/new-api/types"

	"github.com/gin-gonic/gin"
)

const orgBodyLimit = 64 << 10

// orgContext is the request context with the caller's address attached, so
// audit rows written inside service transactions record where the call came
// from.
func orgContext(c *gin.Context) context.Context {
	return orgsvc.WithClientIP(c.Request.Context(), c.ClientIP())
}

// respondOrgError writes the console response for any organization error.
func respondOrgError(c *gin.Context, err error) {
	response := orgsvc.ConsoleError(err)
	common.ApiErrorStatus(c, response.Status, response.Message, gin.H{"code": response.Code})
}

// decodeOrgFields reads a JSON object body and rejects anything that is not an
// object or that names a field outside allowed, so a client cannot smuggle in
// platform fields (seat_limit, billing_group, status, owner_user_id ...). It
// answers 400 itself and returns false on failure.
func decodeOrgFields(c *gin.Context, allowed ...string) (map[string]common.RawMessage, bool) {
	body, err := io.ReadAll(http.MaxBytesReader(c.Writer, c.Request.Body, orgBodyLimit))
	fields := map[string]common.RawMessage{}
	if err == nil {
		err = common.Unmarshal(body, &fields)
	}
	if err != nil || fields == nil {
		respondOrgError(c, types.NewOrgAccessError(types.OrgErrInvalidInput))
		return nil, false
	}
	for name := range fields {
		if !slices.Contains(allowed, name) {
			respondOrgError(c, types.NewOrgAccessError(types.OrgErrInvalidInput))
			return nil, false
		}
	}
	return fields, true
}

// orgField decodes one field of a body decoded by decodeOrgFields. A missing
// field leaves dst untouched and reports false.
func orgField(fields map[string]common.RawMessage, name string, dst any) (present bool, err error) {
	raw, ok := fields[name]
	if !ok {
		return false, nil
	}
	return true, common.Unmarshal(raw, dst)
}

// orgView is the client representation of an organization. It omits the
// billing wallet id, the invoice counter and platform-only bookkeeping.
type orgView struct {
	Id            int            `json:"id"`
	Slug          string         `json:"slug"`
	Name          string         `json:"name"`
	Plan          string         `json:"plan"`
	SeatLimit     int            `json:"seat_limit"`
	Status        int            `json:"status"`
	OwnerUserId   int            `json:"owner_user_id"`
	Settings      map[string]any `json:"settings"`
	PolicyVersion int64          `json:"policy_version"`
	CreatedAt     int64          `json:"created_at"`
	MyRole        string         `json:"my_role,omitempty"`
}

func newOrgView(org *model.Organization, myRole string) orgView {
	settings := map[string]any{}
	if org.Settings != "" {
		if err := common.UnmarshalJsonStr(org.Settings, &settings); err != nil {
			settings = map[string]any{}
		}
	}
	return orgView{Id: org.Id, Slug: org.Slug, Name: org.Name, Plan: org.Plan, SeatLimit: org.SeatLimit,
		Status: org.Status, OwnerUserId: org.OwnerUserId, Settings: settings, PolicyVersion: org.PolicyVersion,
		CreatedAt: org.CreatedAt, MyRole: myRole}
}

// requestedOrg returns the organization OrgAuth proved for this request.
func requestedOrg(c *gin.Context) (*orgsvc.OrgAccess, bool) {
	access, ok := middleware.OrgAccessFromContext(c)
	if !ok {
		respondOrgError(c, types.NewOrgAccessError(types.OrgErrNotFound))
	}
	return access, ok
}

func pathID(c *gin.Context, name string) (int, bool) {
	id, err := strconv.Atoi(c.Param(name))
	if err != nil || id <= 0 {
		respondOrgError(c, types.NewOrgAccessError(types.OrgErrInvalidInput))
		return 0, false
	}
	return id, true
}
