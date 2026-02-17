import { useState, useEffect } from "react";
import { PageHeader } from "@/components/common/PageHeader";
import { Skeleton } from "@/components/ui/skeleton";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  useConfigurationQuery,
  useUpdateConfigurationMutation,
} from "@/lib/api/configuration";
import type { Settings } from "@/types/models";
import { Save, RefreshCw, Plus, Trash2 } from "lucide-react";

export function ConfigurationPage() {
  const { data, isLoading, error, refetch } = useConfigurationQuery();
  const updateMutation = useUpdateConfigurationMutation();

  const [settings, setSettings] = useState<[string, string][]>([]);
  const [newKey, setNewKey] = useState("");
  const [newValue, setNewValue] = useState("");

  useEffect(() => {
    if (data) {
      setSettings(Object.entries(data));
    }
  }, [data]);

  function handleValueChange(index: number, value: string) {
    setSettings((prev) => {
      const next = [...prev];
      const entry = next[index];
      if (entry) {
        next[index] = [entry[0], value];
      }
      return next;
    });
  }

  function handleRemove(index: number) {
    setSettings((prev) => prev.filter((_, i) => i !== index));
  }

  function handleAdd() {
    if (!newKey) return;
    setSettings((prev) => [...prev, [newKey, newValue]]);
    setNewKey("");
    setNewValue("");
  }

  function handleSave() {
    const settingsObj: Settings = {};
    for (const [key, value] of settings) {
      settingsObj[key] = value;
    }
    updateMutation.mutate(settingsObj);
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="Configuration"
        description="Manage application settings and environment variables"
      >
        <Button
          variant="outline"
          size="sm"
          onClick={() => { void refetch(); }}
          disabled={isLoading}
        >
          <RefreshCw className="mr-1.5 h-3.5 w-3.5" /> Refresh
        </Button>
      </PageHeader>

      {isLoading ? (
        <div className="space-y-3">
          <Skeleton className="h-12 w-full" />
          <Skeleton className="h-12 w-full" />
          <Skeleton className="h-12 w-full" />
        </div>
      ) : error ? (
        <div className="card-panel p-6 text-center">
          <p className="text-sm text-destructive">
            Failed to load configuration
          </p>
          <Button
            variant="outline"
            size="sm"
            className="mt-3"
            onClick={() => { void refetch(); }}
          >
            <RefreshCw className="mr-1.5 h-3.5 w-3.5" /> Retry
          </Button>
        </div>
      ) : (
        <div className="space-y-4">
          <div className="card-panel overflow-hidden">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border bg-muted/50">
                  <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-muted-foreground">
                    Key
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-muted-foreground">
                    Value
                  </th>
                  <th className="w-12 px-4 py-3" />
                </tr>
              </thead>
              <tbody>
                {settings.length === 0 ? (
                  <tr>
                    <td
                      colSpan={3}
                      className="px-4 py-8 text-center text-sm text-muted-foreground"
                    >
                      No configuration settings found
                    </td>
                  </tr>
                ) : (
                  settings.map(([key, value], index) => (
                    <tr
                      key={key}
                      className="border-b border-border last:border-0"
                    >
                      <td className="px-4 py-2">
                        <span className="font-data font-medium text-foreground">
                          {key}
                        </span>
                      </td>
                      <td className="px-4 py-2">
                        <Input
                          value={value}
                          onChange={(e) => {
                            handleValueChange(index, e.target.value);
                          }}
                          className="h-8"
                        />
                      </td>
                      <td className="px-4 py-2">
                        <Button
                          variant="ghost"
                          size="icon"
                          onClick={() => { handleRemove(index); }}
                        >
                          <Trash2 className="h-4 w-4 text-destructive" />
                        </Button>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>

          {/* Add new setting */}
          <div className="card-panel p-4">
            <h3 className="mb-3 text-sm font-medium text-foreground">
              Add Setting
            </h3>
            <div className="flex flex-wrap items-end gap-3">
              <div className="flex-1">
                <label className="mb-1 block text-xs text-muted-foreground">
                  Key
                </label>
                <Input
                  placeholder="SETTING_NAME"
                  value={newKey}
                  onChange={(e) => { setNewKey(e.target.value); }}
                />
              </div>
              <div className="flex-1">
                <label className="mb-1 block text-xs text-muted-foreground">
                  Value
                </label>
                <Input
                  placeholder="value"
                  value={newValue}
                  onChange={(e) => { setNewValue(e.target.value); }}
                />
              </div>
              <Button size="sm" onClick={handleAdd} disabled={!newKey}>
                <Plus className="mr-1.5 h-3.5 w-3.5" /> Add
              </Button>
            </div>
          </div>

          {/* Save button */}
          <div className="flex items-center gap-3">
            <Button
              onClick={handleSave}
              disabled={updateMutation.isPending}
            >
              <Save className="mr-1.5 h-3.5 w-3.5" />
              {updateMutation.isPending ? "Saving..." : "Save Configuration"}
            </Button>
            {updateMutation.error ? (
              <p className="text-xs text-destructive">
                {updateMutation.error.message}
              </p>
            ) : null}
            {updateMutation.isSuccess ? (
              <p className="text-xs text-success">
                Configuration saved successfully
              </p>
            ) : null}
          </div>
        </div>
      )}
    </div>
  );
}
