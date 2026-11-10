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

export type Organization = {
  id: number
  slug: string
  name: string
  status: number
  seat_limit: number
  billing_group: string
  billing_user_id: number
  quota: number
  created_at: number
}

export type BillingOperation = {
  operation_id: string
  state: string
  source_kind: string
  model_name: string
  bound: number
  captured_quota: number
  revision: number
  settled_by: string
  created_at: number
}

export type Page<T> = { items: T[]; total: number }

export type ApiResult<T> = { success: boolean; message?: string; data?: T }

export const ORG_STATUS = { ACTIVE: 1, SUSPENDED: 2, DELETED: 3 } as const

export const OPERATION_STATES = [
  'recovery_required',
  'reserved',
  'captured',
  'closed',
  'canceled',
] as const
