import { useState } from 'react';
import { Trash2 } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';

interface DeleteDecisionFormProps {
  onDelete: (params: { id?: string; value?: string }) => Promise<void>;
  loading: boolean;
}

type DeleteMode = 'id' | 'value';

export function DeleteDecisionForm({ onDelete, loading }: DeleteDecisionFormProps) {
  const [mode, setMode] = useState<DeleteMode>('id');
  const [input, setInput] = useState('');

  const handleSubmit = async () => {
    const trimmed = input.trim();
    if (!trimmed) return;

    if (mode === 'id') {
      await onDelete({ id: trimmed });
    } else {
      await onDelete({ value: trimmed });
    }
    setInput('');
  };

  return (
    <section className="rounded-xl border border-border bg-card p-4 space-y-3">
      <h3 className="text-sm font-semibold">Delete Decision</h3>

      <div className="space-y-2">
        <div className="space-y-1">
          <label className="text-xs text-muted-foreground">Delete by</label>
          <Select value={mode} onValueChange={(val) => setMode(val as DeleteMode)}>
            <SelectTrigger>
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="id">ID (numeric)</SelectItem>
              <SelectItem value="value">IP/Value</SelectItem>
            </SelectContent>
          </Select>
        </div>

        <Input
          placeholder={mode === 'id' ? 'Decision ID (e.g. 42)' : 'IP or range (e.g. 1.2.3.4)'}
          value={input}
          onChange={(e) => setInput(e.target.value)}
        />
      </div>

      <Button
        variant="destructive"
        disabled={!input.trim() || loading}
        onClick={handleSubmit}
      >
        <Trash2 className="h-4 w-4 mr-1" />
        Delete
      </Button>
    </section>
  );
}
