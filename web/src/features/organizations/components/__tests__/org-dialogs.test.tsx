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
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, describe, expect, test, vi } from 'vitest'

import type { Organization } from '../../types'

const i18n = (await import('i18next')).default
const { initReactI18next } = await import('react-i18next')
const { api } = await import('@/lib/api')
const { AdjustDialog } = await import('../adjust-dialog')
const { EditDialog } = await import('../edit-dialog')

await i18n.use(initReactI18next).init({ lng: 'en', resources: { en: { translation: {} } } })

type Call = { url: string; body: unknown; headers?: Record<string, string> }
const client = api as unknown as {
  post: (url: string, body: unknown, config?: { headers?: Record<string, string> }) => Promise<{ data: unknown }>
  patch: (url: string, body: unknown) => Promise<{ data: unknown }>
}
const originalPost = client.post
const originalPatch = client.patch

const org: Organization = {
  id: 1,
  slug: 'acme',
  name: 'Acme',
  status: 1,
  seat_limit: 10,
  billing_group: 'default',
  billing_user_id: 9,
  quota: 500000,
  created_at: 1,
}

afterEach(() => {
  client.post = originalPost
  client.patch = originalPatch
})

describe('AdjustDialog', () => {
  test('needs an amount and a reason, and replays one idempotency key', async () => {
    const calls: Call[] = []
    let fail = true
    client.post = vi.fn(async (url, body, config) => {
      calls.push({ url, body, headers: config?.headers })
      if (fail) {
        fail = false
        throw new Error('network')
      }
      return { data: { success: true, data: { available_quota: 1 } } }
    })
    render(<AdjustDialog org={org} onClose={() => {}} onDone={() => {}} />)
    const confirm = screen.getByRole('button', { name: 'Confirm adjustment' })
    expect(confirm).toBeDisabled()

    fireEvent.change(screen.getByLabelText('Quota change (negative to deduct)'), { target: { value: '-250' } })
    expect(confirm).toBeDisabled()
    fireEvent.change(screen.getByLabelText('Reason (required)'), { target: { value: '  refund  ' } })
    expect(confirm).toBeEnabled()

    fireEvent.click(confirm)
    await waitFor(() => expect(calls).toHaveLength(1))
    await waitFor(() => expect(confirm).toBeEnabled())
    fireEvent.click(confirm)
    await waitFor(() => expect(calls).toHaveLength(2))

    expect(calls[0].url).toBe('/api/admin/orgs/acme/adjust')
    expect(calls[0].body).toEqual({ delta_quota: -250, reason: 'refund' })
    expect(calls[0].headers?.['Idempotency-Key']).toBeTruthy()
    expect(calls[1].headers?.['Idempotency-Key']).toBe(calls[0].headers?.['Idempotency-Key'])
  })

  test('refuses zero and non-integer amounts', () => {
    render(<AdjustDialog org={org} onClose={() => {}} onDone={() => {}} />)
    fireEvent.change(screen.getByLabelText('Reason (required)'), { target: { value: 'x' } })
    for (const value of ['0', '1.5', 'abc', '']) {
      fireEvent.change(screen.getByLabelText('Quota change (negative to deduct)'), { target: { value } })
      expect(screen.getByRole('button', { name: 'Confirm adjustment' })).toBeDisabled()
    }
  })
})

describe('EditDialog', () => {
  test('sends only what changed, with the reason', async () => {
    const bodies: unknown[] = []
    client.patch = vi.fn(async (_url, body) => {
      bodies.push(body)
      return { data: { success: true } }
    })
    render(<EditDialog org={org} onClose={() => {}} onDone={() => {}} />)
    const save = screen.getByRole('button', { name: 'Save' })
    expect(save).toBeDisabled()

    fireEvent.change(screen.getByLabelText('Seat limit'), { target: { value: '25' } })
    expect(save).toBeDisabled()
    fireEvent.change(screen.getByLabelText('Reason (required)'), { target: { value: 'contract' } })
    expect(save).toBeEnabled()
    fireEvent.click(save)

    await waitFor(() => expect(bodies).toHaveLength(1))
    expect(bodies[0]).toEqual({ seat_limit: 25, reason: 'contract' })
  })

  test('rejects an invalid seat limit', () => {
    render(<EditDialog org={org} onClose={() => {}} onDone={() => {}} />)
    fireEvent.change(screen.getByLabelText('Reason (required)'), { target: { value: 'x' } })
    fireEvent.change(screen.getByLabelText('Seat limit'), { target: { value: '0' } })
    expect(screen.getByRole('button', { name: 'Save' })).toBeDisabled()
  })
})
