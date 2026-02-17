import { useState } from "react";
import { PageHeader } from "@/components/common/PageHeader";
import { StatusBadge } from "@/components/common/StatusBadge";
import { Skeleton } from "@/components/ui/skeleton";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  useCaptchaStatusQuery,
  useSetupCaptchaMutation,
  useDisableCaptchaMutation,
} from "@/lib/api/captcha";
import { useProxyFeatures } from "@/hooks/useProxyFeatures";
import { Lock, RefreshCw, CheckCircle, XCircle, Info } from "lucide-react";

export function CaptchaPage() {
  const { hasFeature, isLoaded: proxyLoaded } = useProxyFeatures();
  const captchaStatus = useCaptchaStatusQuery();
  const setupMutation = useSetupCaptchaMutation();
  const disableMutation = useDisableCaptchaMutation();

  const [provider, setProvider] = useState("recaptcha");
  const [siteKey, setSiteKey] = useState("");
  const [secretKey, setSecretKey] = useState("");

  const captchaSupported = proxyLoaded && hasFeature("captcha");

  function handleSetup() {
    if (!siteKey || !secretKey) return;
    setupMutation.mutate({
      provider,
      site_key: siteKey,
      secret_key: secretKey,
      enabled: true,
    });
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="Captcha"
        description="Configure captcha challenge for suspicious traffic"
      />

      {!proxyLoaded ? (
        <Skeleton className="h-32 w-full" />
      ) : !captchaSupported ? (
        <div className="card-panel flex items-start gap-3 p-5">
          <Info className="mt-0.5 h-5 w-5 shrink-0 text-warning" />
          <div>
            <h2 className="text-sm font-medium text-foreground">
              Feature Not Available
            </h2>
            <p className="mt-1 text-sm text-muted-foreground">
              Captcha integration is not supported with your current proxy
              configuration. This feature requires Traefik with the CrowdSec
              bouncer plugin.
            </p>
          </div>
        </div>
      ) : (
        <>
          {/* Current status */}
          <div className="card-panel p-5">
            <div className="flex items-center gap-2">
              <Lock className="h-5 w-5 text-signal" />
              <h2 className="text-sm font-medium text-foreground">
                Captcha Status
              </h2>
            </div>
            {captchaStatus.isLoading ? (
              <div className="mt-3 space-y-2">
                <Skeleton className="h-5 w-48" />
                <Skeleton className="h-5 w-32" />
              </div>
            ) : captchaStatus.error ? (
              <div className="mt-3">
                <p className="text-sm text-destructive">
                  Failed to load status
                </p>
                <Button
                  variant="outline"
                  size="sm"
                  className="mt-2"
                  onClick={() => { void captchaStatus.refetch(); }}
                >
                  <RefreshCw className="mr-1.5 h-3.5 w-3.5" /> Retry
                </Button>
              </div>
            ) : captchaStatus.data ? (
              <div className="mt-3 space-y-2">
                <div className="flex items-center gap-2">
                  <span className="text-sm text-muted-foreground">
                    Enabled:
                  </span>
                  <StatusBadge
                    status={captchaStatus.data.enabled ? "running" : "stopped"}
                    label={captchaStatus.data.enabled ? "Active" : "Inactive"}
                  />
                </div>
                {captchaStatus.data.provider ? (
                  <p className="text-sm">
                    <span className="text-muted-foreground">Provider:</span>{" "}
                    {captchaStatus.data.provider}
                  </p>
                ) : null}
                <div className="flex items-center gap-2 text-sm">
                  <span className="text-muted-foreground">HTML template:</span>
                  {captchaStatus.data.html_exists ? (
                    <span className="inline-flex items-center gap-1 text-success">
                      <CheckCircle className="h-3.5 w-3.5" /> Present
                    </span>
                  ) : (
                    <span className="inline-flex items-center gap-1 text-destructive">
                      <XCircle className="h-3.5 w-3.5" /> Missing
                    </span>
                  )}
                </div>
                <div className="flex items-center gap-2 text-sm">
                  <span className="text-muted-foreground">Configuration:</span>
                  {captchaStatus.data.config_ok ? (
                    <span className="inline-flex items-center gap-1 text-success">
                      <CheckCircle className="h-3.5 w-3.5" /> Valid
                    </span>
                  ) : (
                    <span className="inline-flex items-center gap-1 text-destructive">
                      <XCircle className="h-3.5 w-3.5" /> Invalid
                    </span>
                  )}
                </div>
                {captchaStatus.data.enabled ? (
                  <Button
                    variant="destructive"
                    size="sm"
                    className="mt-2"
                    onClick={() => { disableMutation.mutate(); }}
                    disabled={disableMutation.isPending}
                  >
                    {disableMutation.isPending
                      ? "Disabling..."
                      : "Disable Captcha"}
                  </Button>
                ) : null}
              </div>
            ) : null}
          </div>

          {/* Setup form */}
          <div className="card-panel p-5">
            <h2 className="mb-4 text-sm font-medium text-foreground">
              Setup Captcha
            </h2>
            <div className="space-y-4">
              <div>
                <label className="mb-1 block text-xs text-muted-foreground">
                  Provider
                </label>
                <select
                  value={provider}
                  onChange={(e) => { setProvider(e.target.value); }}
                  className="flex h-9 w-full rounded-md border border-input bg-transparent px-3 py-1 text-sm shadow-sm focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
                >
                  <option value="recaptcha">Google reCAPTCHA</option>
                  <option value="hcaptcha">hCaptcha</option>
                  <option value="turnstile">Cloudflare Turnstile</option>
                </select>
              </div>
              <div>
                <label className="mb-1 block text-xs text-muted-foreground">
                  Site Key
                </label>
                <Input
                  placeholder="Enter site key"
                  value={siteKey}
                  onChange={(e) => { setSiteKey(e.target.value); }}
                />
              </div>
              <div>
                <label className="mb-1 block text-xs text-muted-foreground">
                  Secret Key
                </label>
                <Input
                  type="password"
                  placeholder="Enter secret key"
                  value={secretKey}
                  onChange={(e) => { setSecretKey(e.target.value); }}
                />
              </div>
              <Button
                onClick={handleSetup}
                disabled={!siteKey || !secretKey || setupMutation.isPending}
              >
                {setupMutation.isPending ? "Setting up..." : "Setup Captcha"}
              </Button>
              {setupMutation.error ? (
                <p className="text-xs text-destructive">
                  {setupMutation.error.message}
                </p>
              ) : null}
              {setupMutation.isSuccess ? (
                <p className="text-xs text-success">
                  Captcha configured successfully
                </p>
              ) : null}
            </div>
          </div>
        </>
      )}
    </div>
  );
}
