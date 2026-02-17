import { useState, useEffect } from "react";
import { PageHeader } from "@/components/common/PageHeader";
import { StatusBadge } from "@/components/common/StatusBadge";
import { Skeleton } from "@/components/ui/skeleton";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  useNotificationStatusQuery,
  useSaveNotificationMutation,
  useTestNotificationMutation,
} from "@/lib/api/notifications";
import { Bell, Send, RefreshCw } from "lucide-react";

type Mode = "simple" | "advanced";

export function NotificationsPage() {
  const status = useNotificationStatusQuery();
  const saveMutation = useSaveNotificationMutation();
  const testMutation = useTestNotificationMutation();

  const [mode, setMode] = useState<Mode>("simple");
  const [webhookUrl, setWebhookUrl] = useState("");
  const [geoapifyKey, setGeoapifyKey] = useState("");
  const [ctiKey, setCtiKey] = useState("");
  const [advancedYaml, setAdvancedYaml] = useState("");

  useEffect(() => {
    if (status.data?.webhook_url) {
      setWebhookUrl(status.data.webhook_url);
    }
  }, [status.data]);

  function handleSave() {
    saveMutation.mutate({
      webhook_url: webhookUrl,
      geoapify_key: geoapifyKey || undefined,
      cti_key: ctiKey || undefined,
      enabled: true,
      mode,
      advanced_yaml: mode === "advanced" ? advancedYaml || undefined : undefined,
    });
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="Notifications"
        description="Configure webhook notifications for CrowdSec alerts"
      >
        <Button
          variant="outline"
          size="sm"
          onClick={() => { testMutation.mutate(); }}
          disabled={testMutation.isPending}
        >
          <Send className="mr-1.5 h-3.5 w-3.5" />
          {testMutation.isPending ? "Sending..." : "Send Test"}
        </Button>
      </PageHeader>

      {/* Current status */}
      <div className="card-panel p-5">
        <div className="flex items-center gap-2">
          <Bell className="h-5 w-5 text-signal" />
          <h2 className="text-sm font-medium text-foreground">
            Notification Status
          </h2>
        </div>
        {status.isLoading ? (
          <div className="mt-3">
            <Skeleton className="h-5 w-48" />
          </div>
        ) : status.error ? (
          <div className="mt-3">
            <p className="text-sm text-destructive">Failed to load status</p>
            <Button
              variant="outline"
              size="sm"
              className="mt-2"
              onClick={() => { void status.refetch(); }}
            >
              <RefreshCw className="mr-1.5 h-3.5 w-3.5" /> Retry
            </Button>
          </div>
        ) : status.data ? (
          <div className="mt-3 space-y-1">
            <div className="flex items-center gap-2">
              <span className="text-sm text-muted-foreground">
                Configured:
              </span>
              <StatusBadge
                status={status.data.configured ? "running" : "stopped"}
                label={status.data.configured ? "Yes" : "No"}
              />
            </div>
            {status.data.source ? (
              <p className="text-sm">
                <span className="text-muted-foreground">Source:</span>{" "}
                {status.data.source}
              </p>
            ) : null}
          </div>
        ) : null}
        {testMutation.isSuccess ? (
          <p className="mt-2 text-xs text-success">
            Test notification sent successfully
          </p>
        ) : null}
        {testMutation.error ? (
          <p className="mt-2 text-xs text-destructive">
            {testMutation.error.message}
          </p>
        ) : null}
      </div>

      {/* Mode selector */}
      <div className="flex gap-1 rounded-lg bg-muted p-1">
        <button
          type="button"
          onClick={() => { setMode("simple"); }}
          className={`rounded-md px-3 py-1.5 text-sm font-medium transition-colors ${
            mode === "simple"
              ? "bg-background text-foreground shadow-sm"
              : "text-muted-foreground hover:text-foreground"
          }`}
        >
          Simple
        </button>
        <button
          type="button"
          onClick={() => { setMode("advanced"); }}
          className={`rounded-md px-3 py-1.5 text-sm font-medium transition-colors ${
            mode === "advanced"
              ? "bg-background text-foreground shadow-sm"
              : "text-muted-foreground hover:text-foreground"
          }`}
        >
          Advanced
        </button>
      </div>

      {/* Configuration form */}
      <div className="card-panel p-5">
        <div className="space-y-4">
          <div>
            <label className="mb-1 block text-xs text-muted-foreground">
              Webhook URL
            </label>
            <Input
              placeholder="https://discord.com/api/webhooks/..."
              value={webhookUrl}
              onChange={(e) => { setWebhookUrl(e.target.value); }}
            />
          </div>

          {mode === "simple" ? (
            <>
              <div>
                <label className="mb-1 block text-xs text-muted-foreground">
                  Geoapify API Key (optional)
                </label>
                <Input
                  placeholder="For IP geolocation enrichment"
                  value={geoapifyKey}
                  onChange={(e) => { setGeoapifyKey(e.target.value); }}
                />
              </div>
              <div>
                <label className="mb-1 block text-xs text-muted-foreground">
                  CrowdSec CTI Key (optional)
                </label>
                <Input
                  placeholder="For threat intelligence enrichment"
                  value={ctiKey}
                  onChange={(e) => { setCtiKey(e.target.value); }}
                />
              </div>
            </>
          ) : (
            <div>
              <label className="mb-1 block text-xs text-muted-foreground">
                Advanced YAML Configuration
              </label>
              <textarea
                className="flex min-h-[200px] w-full rounded-md border border-input bg-transparent px-3 py-2 font-data text-sm shadow-sm focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
                placeholder="# Custom notification YAML configuration..."
                value={advancedYaml}
                onChange={(e) => { setAdvancedYaml(e.target.value); }}
              />
            </div>
          )}

          <Button
            onClick={handleSave}
            disabled={!webhookUrl || saveMutation.isPending}
          >
            {saveMutation.isPending ? "Saving..." : "Save Configuration"}
          </Button>

          {saveMutation.error ? (
            <p className="text-xs text-destructive">
              {saveMutation.error.message}
            </p>
          ) : null}
          {saveMutation.isSuccess ? (
            <p className="text-xs text-success">
              Notification configuration saved successfully
            </p>
          ) : null}
        </div>
      </div>
    </div>
  );
}
