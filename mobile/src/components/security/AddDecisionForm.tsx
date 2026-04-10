import { useState } from 'react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Textarea } from '@/components/ui/textarea';
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

const DURATION_PRESETS = [
  { value: '1h', label: '1 hour' },
  { value: '4h', label: '4 hours' },
  { value: '24h', label: '24 hours' },
  { value: '7d', label: '7 days' },
  { value: '30d', label: '30 days' },
  { value: '-1', label: 'Permanent' },
  { value: 'custom', label: 'Custom...' },
] as const;

const defaultForm: AddDecisionRequest = {
  value: '',
  type: 'ban',
  scope: 'ip',
  duration: '4h',
  reason: 'manual mobile action',
};

export function AddDecisionForm({ onSubmit, loading }: AddDecisionFormProps) {
  const [form, setForm] = useState<AddDecisionRequest>(defaultForm);
  const [durationMode, setDurationMode] = useState<string>('4h');

  const handleDurationChange = (preset: string) => {
    setDurationMode(preset);
    if (preset !== 'custom') {
      setForm((prev) => ({ ...prev, duration: preset }));
    } else {
      setForm((prev) => ({ ...prev, duration: '' }));
    }
  };

  const handleSubmit = async () => {
    await onSubmit(form);
    setForm(defaultForm);
    setDurationMode('4h');
  };

  return (
    <section className="rounded-xl border border-border bg-card p-4 space-y-3">
      <h3 className="text-sm font-semibold">Add Decision</h3>

      <div className="space-y-2">
        <Input
          placeholder="Value (IP/CIDR)"
          value={form.value || ''}
          onChange={(e) => setForm((prev) => ({ ...prev, value: e.target.value }))}
        />

        <div className="grid grid-cols-2 gap-2">
          <div className="space-y-1">
            <label className="text-xs text-muted-foreground">Type</label>
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

          <div className="space-y-1">
            <label className="text-xs text-muted-foreground">Scope</label>
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
              </SelectContent>
            </Select>
          </div>
        </div>

        <div className="space-y-1">
          <label className="text-xs text-muted-foreground">Duration</label>
          <Select value={durationMode} onValueChange={handleDurationChange}>
            <SelectTrigger>
              <SelectValue placeholder="Duration" />
            </SelectTrigger>
            <SelectContent>
              {DURATION_PRESETS.map((preset) => (
                <SelectItem key={preset.value} value={preset.value}>
                  {preset.label}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          {durationMode === 'custom' && (
            <Input
              placeholder="e.g. 12h, 3d, 2w"
              value={form.duration || ''}
              onChange={(e) => setForm((prev) => ({ ...prev, duration: e.target.value }))}
              className="mt-1"
            />
          )}
        </div>

        <Textarea
          placeholder="Reason"
          value={form.reason || ''}
          onChange={(e) => setForm((prev) => ({ ...prev, reason: e.target.value }))}
        />
      </div>

      <Button onClick={handleSubmit} disabled={loading || !form.value}>
        Add decision
      </Button>
    </section>
  );
}
