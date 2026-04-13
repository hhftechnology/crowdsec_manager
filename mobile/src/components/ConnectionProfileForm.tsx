import { useState } from 'react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Switch } from '@/components/ui/switch';
import { Tabs, TabsList, TabsTrigger } from '@/components/ui/tabs';
import {
  DEFAULT_PANGOLIN_TOKEN_PARAM,
  type ConnectionMode,
  type ConnectionProfileDraft,
} from '@/lib/connection';

interface ConnectionProfileFormProps {
  value: ConnectionProfileDraft;
  onChange: (next: ConnectionProfileDraft) => void;
  disabled?: boolean;
}

export function ConnectionProfileForm({
  value,
  onChange,
  disabled = false,
}: ConnectionProfileFormProps) {
  const [showAdvanced, setShowAdvanced] = useState(
    value.pangolinTokenParam !== DEFAULT_PANGOLIN_TOKEN_PARAM,
  );
  const shouldShowAdvanced =
    showAdvanced || value.pangolinTokenParam !== DEFAULT_PANGOLIN_TOKEN_PARAM;

  const update = <K extends keyof ConnectionProfileDraft>(
    key: K,
    nextValue: ConnectionProfileDraft[K],
  ) => {
    onChange({
      ...value,
      [key]: nextValue,
    });
  };

  const updateMode = (mode: string) => {
    onChange({
      ...value,
      mode: mode as ConnectionMode,
    });
  };

  const urlPlaceholder =
    value.mode === 'pangolin'
      ? 'pangolin.example.com'
      : value.allowInsecure
        ? '192.168.1.10:8080'
        : 'your-server.example.com';

  return (
    <div className="space-y-4">
      <div className="space-y-2">
        <div className="text-sm font-medium">Connection type</div>
        <Tabs value={value.mode} onValueChange={updateMode} className="w-full">
          <TabsList className="grid w-full grid-cols-3">
            <TabsTrigger value="direct" disabled={disabled}>
              Direct
            </TabsTrigger>
            <TabsTrigger value="proxy-basic" disabled={disabled}>
              Proxy
            </TabsTrigger>
            <TabsTrigger value="pangolin" disabled={disabled}>
              Pangolin
            </TabsTrigger>
          </TabsList>
        </Tabs>
      </div>

      <div className="space-y-2">
        <label htmlFor="connection-url" className="text-sm font-medium">
          {value.mode === 'pangolin' ? 'Pangolin URL' : 'Server URL'}
        </label>
        <Input
          id="connection-url"
          type="text"
          inputMode="url"
          autoCapitalize="none"
          autoCorrect="off"
          spellCheck={false}
          placeholder={urlPlaceholder}
          value={value.baseUrl}
          onChange={(event) => update('baseUrl', event.target.value)}
          className="h-12 rounded-lg bg-card"
          disabled={disabled}
        />
        <p className="text-xs text-muted-foreground">
          Domain, IP, or host:port. Include http:// or https:// only if you want
          to force the scheme.
        </p>
      </div>

      {value.mode === 'proxy-basic' && (
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
          <div className="space-y-2">
            <label htmlFor="proxy-username" className="text-sm font-medium">
              Proxy username
            </label>
            <Input
              id="proxy-username"
              type="text"
              autoCapitalize="none"
              autoCorrect="off"
              spellCheck={false}
              autoComplete="username"
              value={value.proxyUsername}
              onChange={(event) => update('proxyUsername', event.target.value)}
              disabled={disabled}
            />
          </div>
          <div className="space-y-2">
            <label htmlFor="proxy-password" className="text-sm font-medium">
              Proxy password
            </label>
            <Input
              id="proxy-password"
              type="password"
              autoComplete="current-password"
              value={value.proxyPassword}
              onChange={(event) => update('proxyPassword', event.target.value)}
              disabled={disabled}
            />
          </div>
        </div>
      )}

      {value.mode === 'pangolin' && (
        <div className="space-y-3 rounded-lg border border-border bg-card p-3">
          <div className="space-y-2">
            <label htmlFor="pangolin-token" className="text-sm font-medium">
              Pangolin access token
            </label>
            <Input
              id="pangolin-token"
              type="password"
              autoCapitalize="none"
              autoCorrect="off"
              spellCheck={false}
              placeholder="tokenId.tokenSecret"
              value={value.pangolinToken}
              onChange={(event) => update('pangolinToken', event.target.value)}
              disabled={disabled}
            />
            <p className="text-xs text-muted-foreground">
              Use the format <code>tokenId.tokenSecret</code>.
            </p>
          </div>

          <div className="flex items-center justify-between gap-3">
            <div>
              <div className="text-sm font-medium">
                Advanced token parameter
              </div>
              <div className="text-xs text-muted-foreground">
                Default is {DEFAULT_PANGOLIN_TOKEN_PARAM}; WebSockets use this
                query parameter.
              </div>
            </div>
            <Button
              type="button"
              variant="ghost"
              size="sm"
              onClick={() => setShowAdvanced((open) => !open)}
              disabled={disabled}
            >
              {shouldShowAdvanced ? 'Hide' : 'Show'}
            </Button>
          </div>

          {shouldShowAdvanced && (
            <div className="space-y-2">
              <label
                htmlFor="pangolin-token-param"
                className="text-sm font-medium"
              >
                Token query parameter
              </label>
              <Input
                id="pangolin-token-param"
                type="text"
                autoCapitalize="none"
                autoCorrect="off"
                spellCheck={false}
                value={value.pangolinTokenParam}
                onChange={(event) =>
                  update('pangolinTokenParam', event.target.value)
                }
                disabled={disabled}
              />
            </div>
          )}
        </div>
      )}

      <div className="flex items-center justify-between gap-3 rounded-lg border border-border bg-card p-3">
        <div>
          <div className="text-sm font-medium">Insecure/LAN Mode</div>
          <div className="text-xs text-muted-foreground">
            {value.allowInsecure
              ? 'HTTP and LAN URLs allowed'
              : 'HTTPS required unless explicitly enabled'}
          </div>
        </div>
        <Switch
          checked={value.allowInsecure}
          onCheckedChange={(checked) => update('allowInsecure', checked)}
          disabled={disabled}
        />
      </div>
    </div>
  );
}
