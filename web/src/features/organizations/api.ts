/*
Copyright (C) 2023-2026 QuantumNous

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program. If not, see <https://www.gnu.org/licenses/>.

For commercial licensing, please contact support@quantumnous.com
*/
import { api } from '@/lib/api'

import type {
  ApiResult,
  BillingOperation,
  Organization,
  Page,
} from './types'

const base = '/api/admin/orgs'

export async function listOrganizations(
  keyword: string,
  page: number,
  pageSize: number
): Promise<ApiResult<Page<Organization>>> {
  const res = await api.get(base, {
    params: { keyword, p: page, page_size: pageSize },
  })
  return res.data
}

export type OrganizationUpdate = {
  status?: number
  billing_group?: string
  seat_limit?: number
  reason: string
}

export async function updateOrganization(
  org: string,
  body: OrganizationUpdate
): Promise<ApiResult<object>> {
  const res = await api.patch(`${base}/${org}`, body)
  return res.data
}

export async function adjustOrganization(
  org: string,
  body: { delta_quota: number; reason: string },
  idempotencyKey: string
): Promise<ApiResult<{ available_quota: number }>> {
  const res = await api.post(`${base}/${org}/adjust`, body, {
    headers: { 'Idempotency-Key': idempotencyKey },
  })
  return res.data
}

export async function listBillingOperations(
  org: string,
  state: string,
  page: number,
  pageSize: number
): Promise<ApiResult<Page<BillingOperation>>> {
  const res = await api.get(`${base}/${org}/billing-operations`, {
    params: { state, p: page, page_size: pageSize },
  })
  return res.data
}

export type OperationResolution = {
  expected_revision: number
  action: 'cancel' | 'settle'
  target_quota: number
  evidence_ref: string
  reason: string
}

export async function resolveBillingOperation(
  org: string,
  operation: string,
  body: OperationResolution
): Promise<ApiResult<{ state: string; captured: number; revision: number }>> {
  const res = await api.post(
    `${base}/${org}/billing-operations/${operation}/resolve`,
    body
  )
  return res.data
}
