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
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'

import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import { formatQuotaWithCurrency } from '@/lib/currency'
import { handleServerError } from '@/lib/handle-server-error'

import { adjustOrganization } from '../api'
import type { Organization } from '../types'

type Props = { org: Organization; onClose: () => void; onDone: () => void }

export function AdjustDialog({ org, onClose, onDone }: Props) {
  const { t } = useTranslation()
  const [delta, setDelta] = useState('')
  const [reason, setReason] = useState('')
  const [busy, setBusy] = useState(false)
  // One key per opened dialog: a retry after a lost response replays the same
  // adjustment instead of applying it twice.
  const [idempotencyKey] = useState(() => crypto.randomUUID())

  const amount = Number(delta)
  const amountValid = Number.isSafeInteger(amount) && amount !== 0
  const canSave = amountValid && reason.trim() !== '' && !busy

  const save = async () => {
    setBusy(true)
    try {
      const result = await adjustOrganization(
        org.slug,
        { delta_quota: amount, reason: reason.trim() },
        idempotencyKey
      )
      if (!result.success) {
        handleServerError(result)
        return
      }
      toast.success(t('Balance adjusted'))
      onDone()
      onClose()
    } catch (error) {
      handleServerError(error)
    } finally {
      setBusy(false)
    }
  }

  return (
    <Dialog open onOpenChange={(open) => !open && onClose()}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{t('Adjust balance')}</DialogTitle>
          <DialogDescription>
            {org.name} ({org.slug}) · {t('Available balance')}:{' '}
            {formatQuotaWithCurrency(org.quota)}
          </DialogDescription>
        </DialogHeader>
        <div className='space-y-3'>
          <div className='space-y-1'>
            <Label htmlFor='adjust-delta'>
              {t('Quota change (negative to deduct)')}
            </Label>
            <Input
              id='adjust-delta'
              inputMode='numeric'
              value={delta}
              onChange={(event) => setDelta(event.target.value)}
            />
            {amountValid && (
              <p className='text-muted-foreground text-xs'>
                {formatQuotaWithCurrency(amount)}
              </p>
            )}
          </div>
          <div className='space-y-1'>
            <Label htmlFor='adjust-reason'>{t('Reason (required)')}</Label>
            <Textarea
              id='adjust-reason'
              value={reason}
              onChange={(event) => setReason(event.target.value)}
            />
          </div>
        </div>
        <DialogFooter>
          <Button variant='outline' onClick={onClose}>
            {t('Cancel')}
          </Button>
          <Button disabled={!canSave} onClick={save}>
            {t('Confirm adjustment')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
