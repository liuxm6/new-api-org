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
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, describe, expect, test, vi } from 'vitest'

const i18n = (await import('i18next')).default
const { initReactI18next } = await import('react-i18next')
const { api } = await import('@/lib/api')
const { Organizations } = await import('../index')

await i18n.use(initReactI18next).init({ lng: 'en', resources: { en: { translation: {} } } })

const client = api as unknown as { get: (url: string, config?: unknown) => Promise<{ data: unknown }> }
const originalGet = client.get

const org = {
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
  client.get = originalGet
})

// The dialogs are tested alone in components/__tests__. This renders the whole
// page, because SectionPageLayout mounts only its own slots: a dialog placed
// outside Content passes every isolated test and never appears on screen.
describe('Organizations page', () => {
  test.each([
    ['Edit', 'Edit organization'],
    ['Adjust balance', 'Confirm adjustment'],
    ['Billing operations', 'Billing operations'],
  ])('the %s button opens its dialog', async (button, inDialog) => {
    client.get = vi.fn(async (url: string) => ({
      data: url.includes('billing-operations')
        ? { success: true, data: { items: [], total: 0 } }
        : { success: true, data: { items: [org], total: 1 } },
    }))
    render(
      <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
        <Organizations />
      </QueryClientProvider>
    )
    const open = await screen.findByRole('button', { name: button })
    expect(screen.queryByRole('dialog')).toBeNull()

    fireEvent.click(open)

    const dialog = await waitFor(() => screen.getByRole('dialog'))
    expect(dialog).toHaveTextContent(inDialog)
    expect(dialog).toHaveTextContent('Acme')
  })
})
