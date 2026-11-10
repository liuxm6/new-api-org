package org

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

const scimIssuer = "https://idp.example.com"

// scimOrg is a lifecycle organization with a configured IdP and JIT switch.
type scimOrg struct {
	*lifecycleOrg
	provider model.CustomOAuthProvider
}

func newScimOrg(t *testing.T, db *gorm.DB, slug string, jit bool) *scimOrg {
	t.Helper()
	f := newLifecycleOrg(t, db, slug, map[string]string{"admin": types.OrgRoleAdmin, "plain": types.OrgRoleMember})
	issuer, clientID, secret, enabled := scimIssuer+"/"+slug, "client-"+slug, "secret-"+slug, true
	_, err := UpdateSSOConfig(context.Background(), f.users["owner"].Id, f.org.Id, SSOConfigInput{
		Issuer: &issuer, ClientID: &clientID, ClientSecret: &secret, Enabled: &enabled, JITEnabled: &jit})
	require.NoError(t, err)
	require.NoError(t, db.Model(&model.Organization{}).Where("id = ?", f.org.Id).Update("seat_limit", 100).Error)
	var provider model.CustomOAuthProvider
	require.NoError(t, db.Where("org_id = ?", f.org.Id).First(&provider).Error)
	return &scimOrg{lifecycleOrg: f, provider: provider}
}

func (o *scimOrg) create(t *testing.T, in ScimUserInput) (ScimUserView, bool, error) {
	t.Helper()
	if in.Active == false && in.UserName == "" {
		in.Active = true
	}
	return CreateScimUser(context.Background(), o.org.Id, in)
}

func (o *scimOrg) mustCreate(t *testing.T, userName, externalID, sub string) ScimUserView {
	t.Helper()
	view, _, err := CreateScimUser(context.Background(), o.org.Id, ScimUserInput{UserName: userName, ExternalID: externalID, OIDCSub: sub, DisplayName: userName, Active: true})
	require.NoError(t, err)
	return view
}

func (o *scimOrg) login(sub, email string, verified bool) (*SSOLoginResult, error) {
	return ResolveSSOLogin(context.Background(), o.org.Id, o.provider.Id, SSOClaims{Issuer: o.provider.Issuer, Subject: sub, Email: email, EmailVerified: verified, Name: email})
}

// requireScim checks the SCIM answer the controller would give for err.
func requireScim(t *testing.T, err error, status int, scimType string) {
	t.Helper()
	require.Error(t, err)
	scim := AsScimError(err)
	assert.Equal(t, status, scim.Status, "%v", err)
	assert.Equal(t, scimType, scim.ScimType, "%v", err)
}

func countRows(t *testing.T, db *gorm.DB, table any, query string, args ...any) int64 {
	t.Helper()
	var n int64
	require.NoError(t, db.Model(table).Where(query, args...).Count(&n).Error)
	return n
}

func TestOrgSCIMIdentityMapping(t *testing.T) {
	eachDialect(t, func(t *testing.T, db *gorm.DB) {
		ctx := context.Background()
		o := newScimOrg(t, db, "scimmap", false)

		t.Run("a subject mapping is required, and nothing is created without it", func(t *testing.T) {
			users := countRows(t, db, &model.User{}, "1 = 1")
			_, _, err := CreateScimUser(ctx, o.org.Id, ScimUserInput{UserName: "a@corp.example", ExternalID: "ext-a", Active: true})
			requireScim(t, err, http.StatusBadRequest, "invalidValue")
			_, _, err = CreateScimUser(ctx, o.org.Id, ScimUserInput{UserName: "a@corp.example", Active: true})
			requireScim(t, err, http.StatusBadRequest, "invalidValue")
			assert.Equal(t, users, countRows(t, db, &model.User{}, "1 = 1"), "no placeholder for a refused create")
			assert.Zero(t, countRows(t, db, &model.OrgIdentity{}, "org_id = ?", o.org.Id))
		})

		t.Run("an organization without an IdP cannot provision", func(t *testing.T) {
			bare := newLifecycleOrg(t, db, "scimbare", nil)
			_, _, err := CreateScimUser(ctx, bare.org.Id, ScimUserInput{UserName: "x", OIDCSub: "s", Active: true})
			requireScim(t, err, http.StatusBadRequest, "invalidValue")
		})

		var first ScimUserView
		t.Run("the placeholder is a bonus-free human with no global email", func(t *testing.T) {
			first = o.mustCreate(t, "ada@corp.example", "ext-ada", "sub-ada")
			assert.True(t, first.Active)
			identity, err := model.GetOrgIdentityByID(db, o.org.Id, first.ID)
			require.NoError(t, err)
			assert.Equal(t, "sub-ada", identity.Subject)
			assert.Equal(t, scimIssuer+"/scimmap", identity.Issuer)
			assert.Equal(t, "ada@corp.example", identity.ClaimEmail, "the claim lives on the identity only")
			assert.Equal(t, types.OrgIdentitySourceSCIM, identity.Source)
			var user model.User
			require.NoError(t, db.First(&user, identity.UserId).Error)
			assert.Equal(t, types.UserKindHuman, user.Kind)
			assert.Empty(t, user.Email)
			assert.Zero(t, user.Quota)
			assert.NotEmpty(t, user.Password)
			assert.False(t, common.ValidatePasswordAndHash("ada@corp.example", user.Password))
			member, err := model.GetOrganizationMember(db, o.org.Id, user.Id)
			require.NoError(t, err)
			assert.Equal(t, types.OrgMemberStatusActive, member.Status)
			assert.Equal(t, types.OrgMemberSourceSCIM, member.Source)
			assert.Equal(t, "ext-ada", member.ExternalId)
			assert.Zero(t, countRows(t, db, &model.User{}, "email = ?", "ada@corp.example"), "no global account carries the claim email")
		})

		t.Run("a replay returns the same member; a rebind is a 409", func(t *testing.T) {
			users := countRows(t, db, &model.User{}, "1 = 1")
			again, created, err := o.create(t, ScimUserInput{UserName: "ada@corp.example", ExternalID: "ext-ada", OIDCSub: "sub-ada", Active: true})
			require.NoError(t, err)
			assert.False(t, created)
			assert.Equal(t, first.ID, again.ID)
			assert.Equal(t, users, countRows(t, db, &model.User{}, "1 = 1"))
			_, _, err = CreateScimUser(ctx, o.org.Id, ScimUserInput{UserName: "ada2@corp.example", ExternalID: "ext-ada", OIDCSub: "sub-other", Active: true})
			requireScim(t, err, http.StatusConflict, "uniqueness")
			_, _, err = CreateScimUser(ctx, o.org.Id, ScimUserInput{UserName: "ada3@corp.example", ExternalID: "ext-other", OIDCSub: "sub-ada", Active: true})
			requireScim(t, err, http.StatusConflict, "uniqueness")
			_, _, err = CreateScimUser(ctx, o.org.Id, ScimUserInput{UserName: "ada@corp.example", ExternalID: "ext-new", OIDCSub: "sub-new", Active: true})
			requireScim(t, err, http.StatusConflict, "uniqueness")
			ext := "ext-other"
			_, err = PatchScimUser(ctx, o.org.Id, first.ID, ScimUserChanges{ExternalID: &ext})
			requireScim(t, err, http.StatusConflict, "mutability")
		})

		t.Run("externalId is the sub only after the platform confirms it", func(t *testing.T) {
			_, _, err := CreateScimUser(ctx, o.org.Id, ScimUserInput{UserName: "bo@corp.example", ExternalID: "bo-sub", Active: true})
			requireScim(t, err, http.StatusBadRequest, "invalidValue")
			require.NoError(t, ConfirmExternalIDIsSub(ctx, o.org.Id, 1, true))
			view, _, err := CreateScimUser(ctx, o.org.Id, ScimUserInput{UserName: "bo@corp.example", ExternalID: "bo-sub", Active: true})
			require.NoError(t, err)
			identity, _ := model.GetOrgIdentityByID(db, o.org.Id, view.ID)
			assert.Equal(t, "bo-sub", identity.Subject)
			require.NoError(t, ConfirmExternalIDIsSub(ctx, o.org.Id, 1, false))
		})

		t.Run("externalId and subject are isolated by organization and provider", func(t *testing.T) {
			other := newScimOrg(t, db, "scimother", false)
			view := other.mustCreate(t, "ada@corp.example", "ext-ada", "sub-ada")
			assert.NotEqual(t, first.ID, view.ID)
			identity, _ := model.GetOrgIdentityByID(db, other.org.Id, view.ID)
			original, _ := model.GetOrgIdentityByID(db, o.org.Id, first.ID)
			assert.NotEqual(t, original.UserId, identity.UserId, "another organization's identity is another person's placeholder")
			_, err := GetScimUser(ctx, o.org.Id, view.ID)
			requireScim(t, err, http.StatusNotFound, "")
			_, err = model.GetOrgIdentityByExternalID(db, o.org.Id, o.provider.Id, "ext-ada")
			require.NoError(t, err)
			_, err = model.GetOrgIdentityByExternalID(db, o.org.Id, other.provider.Id, "ext-ada")
			assert.ErrorIs(t, err, gorm.ErrRecordNotFound)
		})

		t.Run("an identity without an externalId never collides with another", func(t *testing.T) {
			a := o.mustCreate(t, "n1@corp.example", "", "sub-n1")
			b := o.mustCreate(t, "n2@corp.example", "", "sub-n2")
			assert.NotEqual(t, a.ID, b.ID, "NULL external ids are distinct on every database")
		})

		t.Run("provisioning then the first sign-in lands on the same user", func(t *testing.T) {
			view := o.mustCreate(t, "cy@corp.example", "ext-cy", "sub-cy")
			identity, _ := model.GetOrgIdentityByID(db, o.org.Id, view.ID)
			result, err := o.login("sub-cy", "cy@corp.example", true)
			require.NoError(t, err)
			assert.Equal(t, identity.UserId, result.UserID)
			assert.False(t, result.Joined, "no second account, no second seat")
		})

		t.Run("signing in first, then SCIM takes the same identity over", func(t *testing.T) {
			require.NoError(t, func() error {
				enabled := true
				_, err := UpdateSSOConfig(ctx, o.users["owner"].Id, o.org.Id, SSOConfigInput{JITEnabled: &enabled})
				return err
			}())
			joined, err := o.login("sub-di", "di@corp.example", true)
			require.NoError(t, err)
			require.True(t, joined.Joined)
			view, created, err := o.create(t, ScimUserInput{UserName: "di@corp.example", ExternalID: "ext-di", OIDCSub: "sub-di", Active: true})
			require.NoError(t, err)
			assert.False(t, created)
			identity, _ := model.GetOrgIdentityByID(db, o.org.Id, view.ID)
			assert.Equal(t, joined.UserID, identity.UserId, "takeover keeps the person")
			assert.Equal(t, types.OrgIdentitySourceSCIM, identity.Source)
			assert.Equal(t, "ext-di", *identity.ScimExternalId)
			member, _ := model.GetOrganizationMember(db, o.org.Id, joined.UserID)
			assert.Equal(t, types.OrgMemberSourceSCIM, member.Source)
		})

		t.Run("deactivation refuses the next sign-in; SCIM deletion is not undone by JIT", func(t *testing.T) {
			view := o.mustCreate(t, "ed@corp.example", "ext-ed", "sub-ed")
			off := false
			_, err := PatchScimUser(ctx, o.org.Id, view.ID, ScimUserChanges{Active: &off})
			require.NoError(t, err)
			_, err = o.login("sub-ed", "ed@corp.example", true)
			requireRefusal(t, err, types.OrgErrIdentityDisabled)
			gone := o.mustCreate(t, "fi@corp.example", "ext-fi", "sub-fi")
			require.NoError(t, DeleteScimUser(ctx, o.org.Id, gone.ID))
			_, err = o.login("sub-fi", "fi@corp.example", true)
			requireRefusal(t, err, types.OrgErrIdentityDisabled)
			assert.Equal(t, int64(1), countRows(t, db, &model.OrgIdentity{}, "org_id = ? AND subject = ?", o.org.Id, "sub-fi"))
		})

		t.Run("an unverified email never joins, and email never merges accounts", func(t *testing.T) {
			victim := newUser(t, db, "victim-"+strconv.Itoa(int(common.GetTimestamp())), "victim@corp.example")
			_, err := o.login("sub-gus", "gus@corp.example", false)
			requireRefusal(t, err, types.OrgErrEmailNotVerified)
			result, err := o.login("sub-vic", "victim@corp.example", true)
			require.NoError(t, err)
			assert.NotEqual(t, victim.Id, result.UserID, "the claim email matched a global account and it was not touched")
			_, err = model.GetOrganizationMember(db, o.org.Id, victim.Id)
			assert.ErrorIs(t, err, gorm.ErrRecordNotFound)
			var user model.User
			require.NoError(t, db.First(&user, result.UserID).Error)
			assert.Empty(t, user.Email, "the placeholder carries no global email")
			require.NoError(t, model.ResetUserPasswordByEmail("victim@corp.example", "another-password-1"), "recovery by that address reaches the global owner only")
			var reloaded model.User
			require.NoError(t, db.First(&reloaded, result.UserID).Error)
			assert.Equal(t, user.Password, reloaded.Password, "the placeholder password never changes by recovery")
		})
	})
}

func scimSetup(t *testing.T, db *gorm.DB) (*scimOrg, model.Workspace, model.Workspace) {
	t.Helper()
	o := newScimOrg(t, db, "scimlife", false)
	return o, o.main, o.workspace(t, "extra")
}

func TestOrgSCIMLifecycle(t *testing.T) {
	eachDialect(t, func(t *testing.T, db *gorm.DB) {
		ctx := context.Background()
		o, main, extra := scimSetup(t, db)

		t.Run("create, get, list, filter and paginate", func(t *testing.T) {
			for i := range 5 {
				o.mustCreate(t, "user"+strconv.Itoa(i)+"@corp.example", "ext-"+strconv.Itoa(i), "sub-"+strconv.Itoa(i))
			}
			_, err := GetScimUser(ctx, o.org.Id, 987654)
			requireScim(t, err, http.StatusNotFound, "")
			all, total, err := ListScimUsers(ctx, o.org.Id, "", 1, 100)
			require.NoError(t, err)
			assert.Equal(t, 5, total)
			assert.Len(t, all, 5)
			page, total, err := ListScimUsers(ctx, o.org.Id, "", 2, 2)
			require.NoError(t, err)
			assert.Equal(t, 5, total)
			require.Len(t, page, 2)
			assert.Equal(t, all[1].ID, page[0].ID, "startIndex is 1-based")
			byName, _, err := ListScimUsers(ctx, o.org.Id, `userName eq "user3@corp.example"`, 1, 10)
			require.NoError(t, err)
			require.Len(t, byName, 1)
			assert.Equal(t, "ext-3", byName[0].ExternalID)
			byExt, _, err := ListScimUsers(ctx, o.org.Id, ` externalId EQ "ext-4" `, 1, 10)
			require.NoError(t, err)
			require.Len(t, byExt, 1)
			none, total, err := ListScimUsers(ctx, o.org.Id, `userName eq "ghost"`, 1, 10)
			require.NoError(t, err)
			assert.Zero(t, total)
			assert.Empty(t, none)
			for _, bad := range []string{`userName co "x"`, `active eq true`, `userName eq "a" or userName eq "b"`, `displayName eq "x"`} {
				_, _, err = ListScimUsers(ctx, o.org.Id, bad, 1, 10)
				requireScim(t, err, http.StatusBadRequest, "invalidFilter")
			}
			capped, _, err := ListScimUsers(ctx, o.org.Id, "", 1, 100000)
			require.NoError(t, err)
			assert.LessOrEqual(t, len(capped), ScimPageMax)
		})

		view := o.mustCreate(t, "pat@corp.example", "ext-pat", "sub-pat")
		identity, _ := model.GetOrgIdentityByID(db, o.org.Id, view.ID)
		patUser := identity.UserId

		t.Run("patch: deactivation suspends and ends keys and org sessions; reactivation restores the member only", func(t *testing.T) {
			require.NoError(t, db.Model(&model.OrganizationMember{}).Where("org_id = ? AND user_id = ?", o.org.Id, patUser).Update("role", types.OrgRoleMember).Error)
			key := model.Token{UserId: o.wallet, Key: "scim-key-pat", Name: "pat", Status: common.TokenStatusEnabled, ExpiredTime: -1, UnlimitedQuota: true,
				OrgId: o.org.Id, WorkspaceId: main.Id, CreatedBy: patUser, OwnerType: types.TokenOwnerMember, AccessPrincipalId: "prn-pat"}
			require.NoError(t, db.Create(&key).Error)
			require.NoError(t, db.Create(&model.UserSession{SID: "scim-sess", UserID: patUser, Version: 1, UserAuthVersion: 1, Status: model.UserSessionStatusActive,
				RefreshHash: "h", LoginMethod: "org_sso", ExpiresAt: common.GetTimestamp() + 3600, AuthScope: types.AuthScopeOrg, OrgID: o.org.Id, ProviderID: o.provider.Id}).Error)
			off := false
			updated, err := PatchScimUser(ctx, o.org.Id, view.ID, ScimUserChanges{Active: &off})
			require.NoError(t, err)
			assert.False(t, updated.Active)
			member, _ := model.GetOrganizationMember(db, o.org.Id, patUser)
			assert.Equal(t, types.OrgMemberStatusSuspended, member.Status)
			var reloaded model.Token
			require.NoError(t, db.First(&reloaded, key.Id).Error)
			assert.Equal(t, common.TokenStatusDisabled, reloaded.Status)
			var session model.UserSession
			require.NoError(t, db.Where("sid = ?", "scim-sess").First(&session).Error)
			assert.Equal(t, model.UserSessionStatusRevoked, session.Status)

			on := true
			restored, err := PatchScimUser(ctx, o.org.Id, view.ID, ScimUserChanges{Active: &on})
			require.NoError(t, err)
			assert.True(t, restored.Active)
			require.NoError(t, db.First(&reloaded, key.Id).Error)
			assert.Equal(t, common.TokenStatusDisabled, reloaded.Status, "reactivation never revives a key")
		})

		t.Run("an administrator's suspension or removal is not overruled by the IdP", func(t *testing.T) {
			held := o.mustCreate(t, "held@corp.example", "ext-held", "sub-held")
			heldIdentity, _ := model.GetOrgIdentityByID(db, o.org.Id, held.ID)
			require.NoError(t, SetMemberStatus(ctx, o.users["owner"].Id, o.org.Id, heldIdentity.UserId, types.OrgMemberStatusSuspended))
			on := true
			_, err := PatchScimUser(ctx, o.org.Id, held.ID, ScimUserChanges{Active: &on})
			requireScim(t, err, http.StatusForbidden, "")
			member, _ := model.GetOrganizationMember(db, o.org.Id, heldIdentity.UserId)
			assert.Equal(t, types.OrgMemberStatusSuspended, member.Status)

			require.NoError(t, SetMemberStatus(ctx, o.users["owner"].Id, o.org.Id, heldIdentity.UserId, types.OrgMemberStatusActive))
			require.NoError(t, RemoveMember(ctx, o.users["owner"].Id, o.org.Id, heldIdentity.UserId))
			_, err = PatchScimUser(ctx, o.org.Id, held.ID, ScimUserChanges{Active: &on})
			requireScim(t, err, http.StatusForbidden, "")
			member, _ = model.GetOrganizationMember(db, o.org.Id, heldIdentity.UserId)
			assert.Equal(t, types.OrgMemberStatusRemoved, member.Status)
		})

		t.Run("patch: names, userName and the owner guard", func(t *testing.T) {
			name := "Pat Q"
			renamed, err := PatchScimUser(ctx, o.org.Id, view.ID, ScimUserChanges{DisplayName: &name})
			require.NoError(t, err)
			assert.Equal(t, "Pat Q", renamed.DisplayName)
			taken := "user0@corp.example"
			_, err = PatchScimUser(ctx, o.org.Id, view.ID, ScimUserChanges{UserName: &taken})
			requireScim(t, err, http.StatusConflict, "uniqueness")
			ownerView := o.mustCreate(t, "boss@corp.example", "", "sub-boss")
			ownerIdentity, _ := model.GetOrgIdentityByID(db, o.org.Id, ownerView.ID)
			require.NoError(t, db.Model(&model.OrganizationMember{}).Where("org_id = ? AND user_id = ?", o.org.Id, ownerIdentity.UserId).Update("role", types.OrgRoleOwner).Error)
			off := false
			_, err = PatchScimUser(ctx, o.org.Id, ownerView.ID, ScimUserChanges{Active: &off})
			requireScim(t, err, http.StatusForbidden, "")
			requireScim(t, DeleteScimUser(ctx, o.org.Id, ownerView.ID), http.StatusForbidden, "")
		})

		t.Run("patch parsing accepts the common IdP shapes and refuses the rest", func(t *testing.T) {
			changes, err := ParseScimPatch([]ScimPatchOp{{Op: "Replace", Path: "active", Value: "False"}})
			require.NoError(t, err)
			assert.False(t, *changes.Active)
			changes, err = ParseScimPatch([]ScimPatchOp{{Op: "replace", Value: map[string]any{"active": true, "displayName": "Z"}}})
			require.NoError(t, err)
			assert.True(t, *changes.Active)
			assert.Equal(t, "Z", *changes.DisplayName)
			for _, ops := range [][]ScimPatchOp{
				nil, {{Op: "remove", Path: "active"}}, {{Op: "replace", Path: "roles", Value: "owner"}},
				{{Op: "replace", Path: "active", Value: "maybe"}}, {{Op: "replace", Value: "x"}},
			} {
				_, err := ParseScimPatch(ops)
				require.Error(t, err)
				var scim *ScimError
				require.ErrorAs(t, err, &scim)
				assert.Equal(t, http.StatusBadRequest, scim.Status)
			}
		})

		t.Run("groups: no mapping, no access; the org role is never touched", func(t *testing.T) {
			group, err := CreateScimGroup(ctx, o.org.Id, "engineers", []int{view.ID})
			require.NoError(t, err)
			assert.Empty(t, group.Members, "an unmapped group grants nothing")
			assert.Zero(t, countRows(t, db, &model.WorkspaceMemberGrant{}, "org_id = ? AND source = ?", o.org.Id, model.GrantSourceSCIM))
			_, err = CreateScimGroup(ctx, o.org.Id, "engineers", nil)
			requireScim(t, err, http.StatusConflict, "uniqueness")
			_, err = CreateScimGroup(ctx, o.org.Id, "bad-member", []int{99999})
			requireScim(t, err, http.StatusBadRequest, "invalidValue")

			for _, role := range []string{types.OrgRoleOwner, types.OrgRoleAdmin + "x", types.OrgRoleBilling, ""} {
				_, err := SaveMapping(ctx, o.users["owner"].Id, o.org.Id, "engineers", main.Id, role)
				requireRefusal(t, err, types.OrgErrInvalidInput)
			}
			_, err = SaveMapping(ctx, o.users["plain"].Id, o.org.Id, "engineers", main.Id, types.WorkspaceRoleMember)
			requireRefusal(t, err, types.OrgErrForbidden)
			_, err = SaveMapping(ctx, o.users["owner"].Id, o.org.Id, "engineers", 987654, types.WorkspaceRoleMember)
			requireRefusal(t, err, types.OrgErrWorkspaceNotFound)

			mapping, err := SaveMapping(ctx, o.users["owner"].Id, o.org.Id, "engineers", main.Id, types.WorkspaceRoleAdmin)
			require.NoError(t, err)
			patched, err := PatchScimGroup(ctx, o.org.Id, mapping.Id, []ScimGroupChange{{Op: "add", Members: []int{view.ID}}})
			require.NoError(t, err)
			assert.Equal(t, []int{view.ID}, patched.Members)
			ws, err := model.GetWorkspaceMember(db, main.Id, patUser)
			require.NoError(t, err)
			assert.Equal(t, types.WorkspaceRoleAdmin, ws.Role, "workspace admin through the group")
			member, _ := model.GetOrganizationMember(db, o.org.Id, patUser)
			assert.Equal(t, types.OrgRoleMember, member.Role, "a workspace admin mapping never grants an organization role")
		})

		t.Run("revoking a SCIM source keeps manual and other-group grants", func(t *testing.T) {
			var manual model.WorkspaceMemberGrant
			require.NoError(t, db.Transaction(func(tx *gorm.DB) error {
				_, err := model.UpsertWorkspaceGrantTx(tx, o.org.Id, main.Id, patUser, model.GrantSourceManual, "", types.WorkspaceRoleAuditor)
				return err
			}))
			require.NoError(t, db.Where("org_id = ? AND user_id = ? AND source = ?", o.org.Id, patUser, model.GrantSourceManual).First(&manual).Error)
			second, err := CreateScimGroup(ctx, o.org.Id, "writers", nil)
			require.NoError(t, err)
			_, err = UpdateMapping(ctx, o.users["owner"].Id, o.org.Id, second.ID, main.Id, types.WorkspaceRoleMember)
			require.NoError(t, err)
			_, err = PatchScimGroup(ctx, o.org.Id, second.ID, []ScimGroupChange{{Op: "add", Members: []int{view.ID}}})
			require.NoError(t, err)
			ws, _ := model.GetWorkspaceMember(db, main.Id, patUser)
			assert.Equal(t, types.WorkspaceRoleAdmin, ws.Role, "highest live grant wins")

			engineers, _, err := ListScimGroups(ctx, o.org.Id, `displayName eq "engineers"`, 1, 10)
			require.NoError(t, err)
			require.Len(t, engineers, 1)
			require.NoError(t, DeleteScimGroup(ctx, o.org.Id, engineers[0].ID))
			ws, _ = model.GetWorkspaceMember(db, main.Id, patUser)
			assert.Equal(t, types.WorkspaceRoleMember, ws.Role, "the other group's grant stays")
			assert.Equal(t, int64(1), countRows(t, db, &model.WorkspaceMemberGrant{}, "id = ?", manual.Id), "the manual grant stays")

			_, err = PatchScimGroup(ctx, o.org.Id, second.ID, []ScimGroupChange{{Op: "remove", Members: []int{view.ID}}})
			require.NoError(t, err)
			ws, _ = model.GetWorkspaceMember(db, main.Id, patUser)
			assert.Equal(t, types.WorkspaceRoleAuditor, ws.Role, "only the manual grant is left")
			assert.Equal(t, model.WorkspaceMemberStatusActive, ws.Status)
		})

		t.Run("retargeting a mapping moves its members through grants", func(t *testing.T) {
			group, err := CreateScimGroup(ctx, o.org.Id, "movers", nil)
			require.NoError(t, err)
			_, err = UpdateMapping(ctx, o.users["owner"].Id, o.org.Id, group.ID, extra.Id, types.WorkspaceRoleMember)
			require.NoError(t, err)
			_, err = PatchScimGroup(ctx, o.org.Id, group.ID, []ScimGroupChange{{Op: "add", Members: []int{view.ID}}})
			require.NoError(t, err)
			_, err = model.GetWorkspaceMember(db, extra.Id, patUser)
			require.NoError(t, err)
			_, err = UpdateMapping(ctx, o.users["owner"].Id, o.org.Id, group.ID, main.Id, types.WorkspaceRoleAuditor)
			require.NoError(t, err)
			old, _ := model.GetWorkspaceMember(db, extra.Id, patUser)
			assert.Equal(t, model.WorkspaceMemberStatusRemoved, old.Status, "the old workspace access ended")
			require.NoError(t, DeleteMapping(ctx, o.users["owner"].Id, o.org.Id, group.ID))
			assert.Zero(t, countRows(t, db, &model.WorkspaceMemberGrant{}, "org_id = ? AND source = ? AND source_ref = ?", o.org.Id, model.GrantSourceSCIM, "movers"))
		})

		t.Run("delete removes the membership of this organization only", func(t *testing.T) {
			other := newScimOrg(t, db, "scimkeep", false)
			sharedUser := other.mustCreate(t, "pat@corp.example", "ext-pat", "sub-pat")
			otherIdentity, _ := model.GetOrgIdentityByID(db, other.org.Id, sharedUser.ID)

			require.NoError(t, DeleteScimUser(ctx, o.org.Id, view.ID))
			requireScim(t, DeleteScimUser(ctx, o.org.Id, view.ID), http.StatusNotFound, "")
			_, err := GetScimUser(ctx, o.org.Id, view.ID)
			requireScim(t, err, http.StatusNotFound, "")
			member, _ := model.GetOrganizationMember(db, o.org.Id, patUser)
			assert.Equal(t, types.OrgMemberStatusRemoved, member.Status)
			assert.Zero(t, countRows(t, db, &model.WorkspaceMemberGrant{}, "org_id = ? AND user_id = ?", o.org.Id, patUser), "grants of every source are gone")
			var user model.User
			require.NoError(t, db.First(&user, patUser).Error)
			assert.Equal(t, common.UserStatusEnabled, user.Status, "the global account is untouched")
			// A call that names another organization's id finds nothing.
			requireScim(t, DeleteScimUser(ctx, o.org.Id, sharedUser.ID), http.StatusNotFound, "")
			stillThere, err := model.GetOrgIdentityByID(db, other.org.Id, otherIdentity.Id)
			require.NoError(t, err)
			assert.Equal(t, types.OrgIdentityActive, stillThere.Status)
			// A replayed create restores the same person.
			restored, created, err := o.create(t, ScimUserInput{UserName: "pat@corp.example", ExternalID: "ext-pat", OIDCSub: "sub-pat", Active: true})
			require.NoError(t, err)
			assert.True(t, created)
			assert.Equal(t, view.ID, restored.ID)
			member, _ = model.GetOrganizationMember(db, o.org.Id, patUser)
			assert.Equal(t, types.OrgMemberStatusActive, member.Status)
		})

		t.Run("a suspended organization refuses every write", func(t *testing.T) {
			require.NoError(t, SetOrganizationStatus(ctx, o.org.Id, types.OrgStatusSuspended, 1, "test"))
			_, _, err := o.create(t, ScimUserInput{UserName: "late@corp.example", OIDCSub: "late", Active: true})
			requireScim(t, err, http.StatusForbidden, "")
			_, err = CreateScimGroup(ctx, o.org.Id, "late-group", nil)
			requireScim(t, err, http.StatusForbidden, "")
			require.NoError(t, SetOrganizationStatus(ctx, o.org.Id, types.OrgStatusActive, 1, "test"))
		})

		t.Run("the seat limit is a 409", func(t *testing.T) {
			require.NoError(t, db.Model(&model.Organization{}).Where("id = ?", o.org.Id).Update("seat_limit", 1).Error)
			_, _, err := o.create(t, ScimUserInput{UserName: "full@corp.example", OIDCSub: "full", Active: true})
			requireScim(t, err, http.StatusConflict, "")
		})
	})
}

// TestOrgSCIMWorkspaceMembersOnlyByGrants proves, by reading the source, that
// workspace_members has exactly one writer: the grant projection in
// model/workspace_grant.go. A second writer would let the projection and the
// facts disagree.
func TestOrgSCIMWorkspaceMembersOnlyByGrants(t *testing.T) {
	writes := map[string]bool{"Create": true, "Save": true, "Update": true, "Updates": true, "UpdateColumn": true, "UpdateColumns": true, "Delete": true}
	isMember := func(expr ast.Expr) bool {
		if unary, ok := expr.(*ast.UnaryExpr); ok {
			expr = unary.X
		}
		lit, ok := expr.(*ast.CompositeLit)
		if !ok {
			return false
		}
		switch typed := lit.Type.(type) {
		case *ast.Ident:
			return typed.Name == "WorkspaceMember"
		case *ast.SelectorExpr:
			return typed.Sel.Name == "WorkspaceMember"
		}
		return false
	}
	var offenders []string
	fset := token.NewFileSet()
	for _, dir := range []string{"../../model", "../../service", "../../controller", "../../middleware", "../../router"} {
		require.NoError(t, filepath.WalkDir(dir, func(path string, entry os.DirEntry, err error) error {
			if err != nil || entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") ||
				strings.HasSuffix(filepath.ToSlash(path), "model/workspace_grant.go") {
				return err
			}
			file, parseErr := parser.ParseFile(fset, path, nil, 0)
			if parseErr != nil {
				return parseErr
			}
			ast.Inspect(file, func(node ast.Node) bool {
				call, ok := node.(*ast.CallExpr)
				if !ok {
					return true
				}
				selector, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				name := selector.Sel.Name
				if writes[name] {
					for _, arg := range call.Args {
						if isMember(arg) {
							offenders = append(offenders, path+": "+name+"(WorkspaceMember)")
						}
					}
					// db.Model(&WorkspaceMember{}).Where(...).Updates(...)
					for chain := selector.X; ; {
						inner, ok := chain.(*ast.CallExpr)
						if !ok {
							break
						}
						innerSel, ok := inner.Fun.(*ast.SelectorExpr)
						if !ok {
							break
						}
						if (innerSel.Sel.Name == "Model" || innerSel.Sel.Name == "Table") && len(inner.Args) > 0 && isMember(inner.Args[0]) {
							offenders = append(offenders, path+": Model(WorkspaceMember)."+name)
						}
						chain = innerSel.X
					}
				}
				if name == "Exec" || name == "Raw" {
					for _, arg := range call.Args {
						if lit, ok := arg.(*ast.BasicLit); ok && strings.Contains(strings.ToLower(lit.Value), "workspace_members") {
							offenders = append(offenders, path+": raw SQL on workspace_members")
						}
					}
				}
				return true
			})
			return nil
		}))
	}
	assert.Empty(t, offenders, "only model/workspace_grant.go may write workspace_members")
}
