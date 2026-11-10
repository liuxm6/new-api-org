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
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'

import { SectionPageLayout } from '@/components/layout'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import { formatQuotaWithCurrency } from '@/lib/currency'
import { handleServerError } from '@/lib/handle-server-error'

import { listOrganizations } from './api'
import { AdjustDialog } from './components/adjust-dialog'
import { EditDialog } from './components/edit-dialog'
import { OperationsDialog } from './components/operations-dialog'
import { ORG_STATUS, type Organization } from './types'

const PAGE_SIZE = 20

type Action = { kind: 'edit' | 'adjust' | 'operations'; org: Organization }

export function Organizations() {
  const { t } = useTranslation()
  const queryClient = useQueryClient()
  const [keyword, setKeyword] = useState('')
  const [search, setSearch] = useState('')
  const [page, setPage] = useState(1)
  const [action, setAction] = useState<Action | null>(null)

  const query = useQuery({
    queryKey: ['admin-orgs', search, page],
    queryFn: async () => {
      const result = await listOrganizations(search, page, PAGE_SIZE)
      if (!result.success || !result.data) {
        handleServerError(result)
        return { items: [], total: 0 }
      }
      return result.data
    },
  })

  const items = query.data?.items ?? []
  const total = query.data?.total ?? 0
  const pages = Math.max(1, Math.ceil(total / PAGE_SIZE))
  const refresh = () =>
    queryClient.invalidateQueries({ queryKey: ['admin-orgs'] })

  return (
    <SectionPageLayout>
      <SectionPageLayout.Title>{t('Organizations')}</SectionPageLayout.Title>
      <SectionPageLayout.Content>
        <form
          className='mb-4 flex gap-2'
          onSubmit={(event) => {
            event.preventDefault()
            setPage(1)
            setSearch(keyword.trim())
          }}
        >
          <Input
            value={keyword}
            placeholder={t('Search by name or slug')}
            onChange={(event) => setKeyword(event.target.value)}
            className='max-w-xs'
          />
          <Button type='submit' variant='outline'>
            {t('Search')}
          </Button>
        </form>

        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>{t('Organization')}</TableHead>
              <TableHead>{t('Status')}</TableHead>
              <TableHead>{t('Billing group')}</TableHead>
              <TableHead>{t('Seat limit')}</TableHead>
              <TableHead>{t('Available balance')}</TableHead>
              <TableHead className='text-right'>{t('Actions')}</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {items.map((org) => (
              <TableRow key={org.id}>
                <TableCell>
                  <div className='font-medium'>{org.name}</div>
                  <div className='text-muted-foreground text-xs'>
                    {org.slug}
                  </div>
                </TableCell>
                <TableCell>
                  <Badge
                    variant={
                      org.status === ORG_STATUS.ACTIVE ? 'secondary' : 'outline'
                    }
                  >
                    {org.status === ORG_STATUS.ACTIVE
                      ? t('Active')
                      : t('Suspended')}
                  </Badge>
                </TableCell>
                <TableCell>{org.billing_group}</TableCell>
                <TableCell>{org.seat_limit}</TableCell>
                <TableCell>{formatQuotaWithCurrency(org.quota)}</TableCell>
                <TableCell className='space-x-2 text-right'>
                  <Button
                    size='sm'
                    variant='outline'
                    onClick={() => setAction({ kind: 'edit', org })}
                  >
                    {t('Edit')}
                  </Button>
                  <Button
                    size='sm'
                    variant='outline'
                    onClick={() => setAction({ kind: 'adjust', org })}
                  >
                    {t('Adjust balance')}
                  </Button>
                  <Button
                    size='sm'
                    variant='outline'
                    onClick={() => setAction({ kind: 'operations', org })}
                  >
                    {t('Billing operations')}
                  </Button>
                </TableCell>
              </TableRow>
            ))}
            {!query.isLoading && items.length === 0 && (
              <TableRow>
                <TableCell
                  colSpan={6}
                  className='text-muted-foreground text-center'
                >
                  {t('No organizations found')}
                </TableCell>
              </TableRow>
            )}
          </TableBody>
        </Table>

        <div className='mt-4 flex items-center justify-end gap-2'>
          <Button
            size='sm'
            variant='outline'
            disabled={page <= 1}
            onClick={() => setPage((value) => value - 1)}
          >
            {t('Previous')}
          </Button>
          <span className='text-sm'>
            {page} / {pages}
          </span>
          <Button
            size='sm'
            variant='outline'
            disabled={page >= pages}
            onClick={() => setPage((value) => value + 1)}
          >
            {t('Next')}
          </Button>
        </div>

        {/* SectionPageLayout renders only its slots: a dialog outside Content is never mounted. */}
        {action?.kind === 'edit' && (
          <EditDialog
            org={action.org}
            onClose={() => setAction(null)}
            onDone={refresh}
          />
        )}
        {action?.kind === 'adjust' && (
          <AdjustDialog
            org={action.org}
            onClose={() => setAction(null)}
            onDone={refresh}
          />
        )}
        {action?.kind === 'operations' && (
          <OperationsDialog org={action.org} onClose={() => setAction(null)} />
        )}
      </SectionPageLayout.Content>
    </SectionPageLayout>
  )
}
