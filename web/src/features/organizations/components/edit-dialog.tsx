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
import { handleServerError } from '@/lib/handle-server-error'

import { updateOrganization, type OrganizationUpdate } from '../api'
import { ORG_STATUS, type Organization } from '../types'

type Props = { org: Organization; onClose: () => void; onDone: () => void }

export function EditDialog({ org, onClose, onDone }: Props) {
  const { t } = useTranslation()
  const [suspended, setSuspended] = useState(org.status === ORG_STATUS.SUSPENDED)
  const [group, setGroup] = useState(org.billing_group)
  const [seats, setSeats] = useState(String(org.seat_limit))
  const [reason, setReason] = useState('')
  const [busy, setBusy] = useState(false)

  const seatCount = Number(seats)
  const seatsValid = Number.isInteger(seatCount) && seatCount > 0
  const body: OrganizationUpdate = { reason: reason.trim() }
  const status = suspended ? ORG_STATUS.SUSPENDED : ORG_STATUS.ACTIVE
  if (status !== org.status) body.status = status
  if (group.trim() !== org.billing_group) body.billing_group = group.trim()
  if (seatsValid && seatCount !== org.seat_limit) body.seat_limit = seatCount
  const changed = Object.keys(body).length > 1
  const canSave = changed && seatsValid && body.reason !== '' && !busy

  const save = async () => {
    setBusy(true)
    try {
      const result = await updateOrganization(org.slug, body)
      if (!result.success) {
        handleServerError(result)
        return
      }
      toast.success(t('Organization updated'))
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
          <DialogTitle>{t('Edit organization')}</DialogTitle>
          <DialogDescription>
            {org.name} ({org.slug})
          </DialogDescription>
        </DialogHeader>
        <div className='space-y-3'>
          <label className='flex items-center gap-2 text-sm'>
            <input
              type='checkbox'
              checked={suspended}
              onChange={(event) => setSuspended(event.target.checked)}
            />
            {t('Suspended')}
          </label>
          <div className='space-y-1'>
            <Label htmlFor='org-group'>{t('Billing group')}</Label>
            <Input
              id='org-group'
              value={group}
              onChange={(event) => setGroup(event.target.value)}
            />
          </div>
          <div className='space-y-1'>
            <Label htmlFor='org-seats'>{t('Seat limit')}</Label>
            <Input
              id='org-seats'
              inputMode='numeric'
              value={seats}
              onChange={(event) => setSeats(event.target.value)}
            />
          </div>
          <div className='space-y-1'>
            <Label htmlFor='org-reason'>{t('Reason (required)')}</Label>
            <Textarea
              id='org-reason'
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
            {t('Save')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
