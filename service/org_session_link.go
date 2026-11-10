package service

import orgsvc "github.com/QuantumNous/new-api/service/org"

// The organization package cannot import this one, so the refresh-time
// standing check of org-restricted sessions is installed here.
func init() { OrgSessionLiveness = orgsvc.SessionLive }
