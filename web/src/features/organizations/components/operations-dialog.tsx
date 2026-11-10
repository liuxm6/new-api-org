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
import { useQuery } from '@tanstack/react-query'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'

import { ConfirmDialog } from '@/components/confirm-dialog'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import { formatQuotaWithCurrency } from '@/lib/currency'
import { handleServerError } from '@/lib/handle-server-error'

import { listBillingOperations, resolveBillingOperation } from '../api'
import { OPERATION_STATES, type BillingOperation, type Organization } from '../types'

type Props = { org: Organization; onClose: () => void }

export function OperationsDialog({ org, onClose }: Props) {
  const { t } = useTranslation()
  const [state, setState] = useState<string>('recovery_required')
  const [target, setTarget] = useState<BillingOperation | null>(null)
  const query = useQuery({
    queryKey: ['admin-org-operations', org.slug, state],
    queryFn: async () => {
      const result = await listBillingOperations(org.slug, state, 1, 50)
      if (!result.success || !result.data) {
        handleServerError(result)
        return { items: [], total: 0 }
      }
      return result.data
    },
  })
  const items = query.data?.items ?? []

  return (
    <Dialog open onOpenChange={(open) => !open && onClose()}>
      <DialogContent className='max-w-3xl'>
        <DialogHeader>
          <DialogTitle>{t('Billing operations')}</DialogTitle>
          <DialogDescription>
            {org.name} ({org.slug})
          </DialogDescription>
        </DialogHeader>
        <div className='flex flex-wrap gap-2'>
          {OPERATION_STATES.map((value) => (
            <Button
              key={value}
              size='sm'
              variant={state === value ? 'default' : 'outline'}
              onClick={() => setState(value)}
            >
              {value}
            </Button>
          ))}
        </div>
        <div className='max-h-96 space-y-2 overflow-y-auto'>
          {items.map((op) => (
            <div
              key={op.operation_id}
              className='flex items-center justify-between gap-3 rounded-md border p-3 text-sm'
            >
              <div className='min-w-0'>
                <div className='truncate font-mono text-xs'>
                  {op.operation_id}
                </div>
                <div className='text-muted-foreground'>
                  {op.source_kind} · {op.model_name} · {t('Reserved')}{' '}
                  {formatQuotaWithCurrency(op.bound)} · {t('Charged')}{' '}
                  {formatQuotaWithCurrency(op.captured_quota)}
                </div>
              </div>
              <Badge variant='outline'>{op.state}</Badge>
              {op.state === 'recovery_required' && (
                <Button size='sm' onClick={() => setTarget(op)}>
                  {t('Resolve')}
                </Button>
              )}
            </div>
          ))}
          {!query.isLoading && items.length === 0 && (
            <p className='text-muted-foreground py-6 text-center text-sm'>
              {t('No operations in this state')}
            </p>
          )}
        </div>
      </DialogContent>
      {target && (
        <ResolveDialog
          org={org}
          operation={target}
          onClose={() => setTarget(null)}
          onDone={() => query.refetch()}
        />
      )}
    </Dialog>
  )
}

type ResolveProps = {
  org: Organization
  operation: BillingOperation
  onClose: () => void
  onDone: () => void
}

function ResolveDialog({ org, operation, onClose, onDone }: ResolveProps) {
  const { t } = useTranslation()
  const [action, setAction] = useState<'cancel' | 'settle'>('cancel')
  const [quota, setQuota] = useState('0')
  const [evidence, setEvidence] = useState('')
  const [reason, setReason] = useState('')
  const [busy, setBusy] = useState(false)

  const amount = Number(quota)
  const amountValid =
    action === 'cancel' || (Number.isSafeInteger(amount) && amount >= 0)
  const ready = amountValid && reason.trim() !== '' && evidence.trim() !== ''

  const submit = async () => {
    setBusy(true)
    try {
      const result = await resolveBillingOperation(
        org.slug,
        operation.operation_id,
        {
          expected_revision: operation.revision,
          action,
          target_quota: action === 'settle' ? amount : 0,
          evidence_ref: evidence.trim(),
          reason: reason.trim(),
        }
      )
      if (!result.success) {
        handleServerError(result)
        return
      }
      toast.success(t('Operation resolved'))
      onDone()
      onClose()
    } catch (error) {
      handleServerError(error)
    } finally {
      setBusy(false)
    }
  }

  return (
    <ConfirmDialog
      open
      onOpenChange={(open) => !open && onClose()}
      title={t('Resolve billing operation')}
      desc={t(
        'This settles or cancels held money. It cannot be undone; the decision is recorded in the organization audit trail.'
      )}
      confirmText={t('Confirm')}
      destructive={action === 'settle'}
      disabled={!ready || busy}
      isLoading={busy}
      handleConfirm={submit}
    >
      <div className='space-y-3'>
        <div className='flex gap-2'>
          {(['cancel', 'settle'] as const).map((value) => (
            <Button
              key={value}
              size='sm'
              variant={action === value ? 'default' : 'outline'}
              onClick={() => setAction(value)}
            >
              {value === 'cancel' ? t('Cancel and release') : t('Settle')}
            </Button>
          ))}
        </div>
        {action === 'settle' && (
          <div className='space-y-1'>
            <Label htmlFor='resolve-quota'>{t('Charge (quota)')}</Label>
            <Input
              id='resolve-quota'
              inputMode='numeric'
              value={quota}
              onChange={(event) => setQuota(event.target.value)}
            />
            <p className='text-muted-foreground text-xs'>
              {t('Capped at the reserved amount')}:{' '}
              {formatQuotaWithCurrency(operation.bound)}
            </p>
          </div>
        )}
        <div className='space-y-1'>
          <Label htmlFor='resolve-evidence'>{t('Evidence reference')}</Label>
          <Input
            id='resolve-evidence'
            value={evidence}
            onChange={(event) => setEvidence(event.target.value)}
          />
        </div>
        <div className='space-y-1'>
          <Label htmlFor='resolve-reason'>{t('Reason (required)')}</Label>
          <Textarea
            id='resolve-reason'
            value={reason}
            onChange={(event) => setReason(event.target.value)}
          />
        </div>
      </div>
    </ConfirmDialog>
  )
}
