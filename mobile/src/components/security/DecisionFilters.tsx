import { useState } from 'react';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';

interface DecisionFiltersProps {
  onFiltersChange: (filters: { type?: string; scope?: string; origin?: string }) => void;
}

export function DecisionFilters({ onFiltersChange }: DecisionFiltersProps) {
  const [type, setType] = useState('all');
  const [scope, setScope] = useState('all');
  const [origin, setOrigin] = useState('all');

  const emitChange = (next: { type: string; scope: string; origin: string }) => {
    onFiltersChange({
      type: next.type === 'all' ? undefined : next.type,
      scope: next.scope === 'all' ? undefined : next.scope,
      origin: next.origin === 'all' ? undefined : next.origin,
    });
  };

  return (
    <div className="flex gap-2">
      <div className="flex-1">
        <Select
          value={type}
          onValueChange={(val) => {
            setType(val);
            emitChange({ type: val, scope, origin });
          }}
        >
          <SelectTrigger className="h-8 text-xs">
            <SelectValue placeholder="Type" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All types</SelectItem>
            <SelectItem value="ban">Ban</SelectItem>
            <SelectItem value="captcha">Captcha</SelectItem>
          </SelectContent>
        </Select>
      </div>

      <div className="flex-1">
        <Select
          value={scope}
          onValueChange={(val) => {
            setScope(val);
            emitChange({ type, scope: val, origin });
          }}
        >
          <SelectTrigger className="h-8 text-xs">
            <SelectValue placeholder="Scope" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All scopes</SelectItem>
            <SelectItem value="ip">IP</SelectItem>
            <SelectItem value="range">Range</SelectItem>
          </SelectContent>
        </Select>
      </div>

      <div className="flex-1">
        <Select
          value={origin}
          onValueChange={(val) => {
            setOrigin(val);
            emitChange({ type, scope, origin: val });
          }}
        >
          <SelectTrigger className="h-8 text-xs">
            <SelectValue placeholder="Origin" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All origins</SelectItem>
            <SelectItem value="crowdsec">CrowdSec</SelectItem>
            <SelectItem value="cscli">cscli</SelectItem>
            <SelectItem value="CAPI">CAPI</SelectItem>
          </SelectContent>
        </Select>
      </div>
    </div>
  );
}
