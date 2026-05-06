import { useState } from 'react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Textarea } from '@/components/ui/textarea';
import { Switch } from '@/components/ui/switch';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import type { AddDecisionRequest } from '@/lib/api';

interface AddDecisionFormProps {
  onSubmit: (form: AddDecisionRequest) => Promise<void>;
  loading: boolean;
}

type SelectorMode = 'ip' | 'range' | 'scope';

const defaultForm: AddDecisionRequest = {
  type: 'ban',
  scope: 'ip',
  duration: '4h',
  reason: 'manual mobile action',
  origin: 'cscli',
};

const durationPresets = ['1h', '4h', '24h', '7d', '30d'] as const;

export function AddDecisionForm({ onSubmit, loading }: AddDecisionFormProps) {
  const [form, setForm] = useState<AddDecisionRequest>(defaultForm);
  const [selectorMode, setSelectorMode] = useState<SelectorMode>('ip');
  const [selectorValue, setSelectorValue] = useState('');
  const permanent = form.duration === '0';

  const handleSubmit = async () => {
    const value = selectorValue.trim();
    const payload: AddDecisionRequest = {
      type: form.type,
      duration: form.duration,
      reason: form.reason || undefined,
      origin: form.origin || undefined,
    };

    if (selectorMode === 'ip') {
      payload.ip = value;
    } else if (selectorMode === 'range') {
      payload.range = value;
    } else {
      payload.scope = form.scope || 'ip';
      payload.value = value;
    }

    await onSubmit(payload);
    setForm(defaultForm);
    setSelectorMode('ip');
    setSelectorValue('');
  };

  return (
    <section className="rounded-lg border border-hairline bg-surface-card p-md space-y-sm">
      <h3 className="text-title-sm font-semibold text-ink">Add Decision</h3>

      <div className="space-y-xs">
        <div className="grid grid-cols-2 gap-xs">
          <div className="space-y-xxs">
            <label className="text-caption text-muted">Selector</label>
            <Select value={selectorMode} onValueChange={(val) => setSelectorMode(val as SelectorMode)}>
              <SelectTrigger>
                <SelectValue placeholder="Selector" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="ip">IP</SelectItem>
                <SelectItem value="range">Range</SelectItem>
                <SelectItem value="scope">Scope + value</SelectItem>
              </SelectContent>
            </Select>
          </div>

          <div className="space-y-xxs">
            <label className="text-caption text-muted">Type</label>
            <Select
              value={form.type || 'ban'}
              onValueChange={(val) => setForm((prev) => ({ ...prev, type: val }))}
            >
              <SelectTrigger>
                <SelectValue placeholder="Type" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="ban">Ban</SelectItem>
                <SelectItem value="captcha">Captcha</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </div>

        <Input
          placeholder={selectorMode === 'range' ? '10.0.0.0/24' : '1.2.3.4'}
          value={selectorValue}
          onChange={(e) => setSelectorValue(e.target.value)}
        />

        {selectorMode === 'scope' && (
          <div className="space-y-xxs">
            <label className="text-caption text-muted">Scope</label>
            <Select
              value={form.scope || 'ip'}
              onValueChange={(val) => setForm((prev) => ({ ...prev, scope: val }))}
            >
              <SelectTrigger>
                <SelectValue placeholder="Scope" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="ip">IP</SelectItem>
                <SelectItem value="range">Range</SelectItem>
                <SelectItem value="country">Country</SelectItem>
                <SelectItem value="as">AS</SelectItem>
                <SelectItem value="username">Username</SelectItem>
              </SelectContent>
            </Select>
          </div>
        )}

        <div className="space-y-xxs">
          <div className="flex items-center justify-between gap-sm">
            <label className="text-caption text-muted">Duration</label>
            <div className="flex items-center gap-xs">
              <span className="text-caption text-muted">Permanent</span>
              <Switch
                checked={permanent}
                onCheckedChange={(checked) =>
                  setForm((prev) => ({ ...prev, duration: checked ? '0' : '4h' }))
                }
              />
            </div>
          </div>
          {!permanent && (
            <>
              <div className="flex flex-wrap gap-xxs">
                {durationPresets.map((preset) => (
                  <Button
                    key={preset}
                    type="button"
                    variant={form.duration === preset ? 'default' : 'outline'}
                    size="sm"
                    onClick={() => setForm((prev) => ({ ...prev, duration: preset }))}
                  >
                    {preset}
                  </Button>
                ))}
              </div>
              <Input
                placeholder="e.g. 12h, 3d, 2w"
                value={form.duration || ''}
                onChange={(e) => setForm((prev) => ({ ...prev, duration: e.target.value }))}
              />
            </>
          )}
        </div>

        <Input
          placeholder="Origin"
          value={form.origin || ''}
          onChange={(e) => setForm((prev) => ({ ...prev, origin: e.target.value }))}
        />

        <Textarea
          placeholder="Reason"
          value={form.reason || ''}
          onChange={(e) => setForm((prev) => ({ ...prev, reason: e.target.value }))}
        />
      </div>

      <Button onClick={handleSubmit} disabled={loading || !selectorValue.trim()}>
        Add decision
      </Button>
    </section>
  );
}
