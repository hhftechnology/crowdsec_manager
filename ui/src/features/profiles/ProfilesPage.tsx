import { useState, useEffect } from "react";
import { PageHeader } from "@/components/common/PageHeader";
import { Skeleton } from "@/components/ui/skeleton";
import { Button } from "@/components/ui/button";
import {
  useProfilesQuery,
  useUpdateProfilesMutation,
} from "@/lib/api/profiles";
import type { Profile } from "@/types/models";
import { RefreshCw, Save, FileText } from "lucide-react";

function ProfileCard({ profile }: { profile: Profile }) {
  return (
    <div className="card-panel p-4">
      <div className="flex items-center gap-2">
        <FileText className="h-4 w-4 text-signal" />
        <h3 className="text-sm font-medium text-foreground">
          {profile.name}
        </h3>
      </div>
      <div className="mt-3 space-y-2">
        <div>
          <p className="text-xs font-medium uppercase tracking-wider text-muted-foreground">
            Filters
          </p>
          <div className="mt-1 space-y-0.5">
            {profile.filters.map((filter) => (
              <p key={filter} className="font-data text-sm text-foreground">
                {filter}
              </p>
            ))}
          </div>
        </div>
        <div>
          <p className="text-xs font-medium uppercase tracking-wider text-muted-foreground">
            Decisions
          </p>
          <div className="mt-1 space-y-0.5">
            {profile.decisions.map((d) => (
              <p
                key={`${d.type}-${d.duration}`}
                className="font-data text-sm text-foreground"
              >
                {d.type} - {d.duration}
              </p>
            ))}
          </div>
        </div>
        {profile.notifications.length > 0 ? (
          <div>
            <p className="text-xs font-medium uppercase tracking-wider text-muted-foreground">
              Notifications
            </p>
            <div className="mt-1 flex flex-wrap gap-1">
              {profile.notifications.map((n) => (
                <span
                  key={n}
                  className="badge-signal rounded-full px-2 py-0.5 text-xs font-medium"
                >
                  {n}
                </span>
              ))}
            </div>
          </div>
        ) : null}
        <p className="text-xs text-muted-foreground">
          On success: {profile.on_success}
        </p>
      </div>
    </div>
  );
}

export function ProfilesPage() {
  const { data, isLoading, error, refetch } = useProfilesQuery();
  const updateMutation = useUpdateProfilesMutation();

  const [yamlContent, setYamlContent] = useState("");
  const [editing, setEditing] = useState(false);

  useEffect(() => {
    // When we start editing we need seed content but we don't have raw YAML from the API
    // The YAML editor will be for advanced users sending raw updates
  }, [data]);

  return (
    <div className="space-y-6">
      <PageHeader
        title="Profiles"
        description="Manage CrowdSec profiles that define how alerts are processed"
      >
        <Button
          variant="outline"
          size="sm"
          onClick={() => { void refetch(); }}
          disabled={isLoading}
        >
          <RefreshCw className="mr-1.5 h-3.5 w-3.5" /> Refresh
        </Button>
        <Button
          variant={editing ? "default" : "outline"}
          size="sm"
          onClick={() => { setEditing(!editing); }}
        >
          {editing ? "View Profiles" : "Edit YAML"}
        </Button>
      </PageHeader>

      {!editing ? (
        <>
          {isLoading ? (
            <div className="grid gap-4 sm:grid-cols-2">
              <Skeleton className="h-40" />
              <Skeleton className="h-40" />
            </div>
          ) : error ? (
            <div className="card-panel p-6 text-center">
              <p className="text-sm text-destructive">
                Failed to load profiles
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
          ) : (data ?? []).length === 0 ? (
            <div className="card-panel p-6 text-center">
              <p className="text-sm text-muted-foreground">
                No profiles found
              </p>
            </div>
          ) : (
            <div className="grid gap-4 sm:grid-cols-2">
              {(data ?? []).map((profile) => (
                <ProfileCard key={profile.name} profile={profile} />
              ))}
            </div>
          )}
        </>
      ) : (
        <div className="space-y-4">
          <div className="card-panel p-5">
            <label className="mb-2 block text-xs text-muted-foreground">
              Profiles YAML
            </label>
            <textarea
              className="flex min-h-[400px] w-full rounded-md border border-input bg-transparent px-3 py-2 font-data text-sm shadow-sm focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
              placeholder="# Paste your profiles.yaml content here..."
              value={yamlContent}
              onChange={(e) => { setYamlContent(e.target.value); }}
            />
            <div className="mt-3 flex items-center gap-2">
              <Button
                onClick={() => { updateMutation.mutate(yamlContent); }}
                disabled={!yamlContent || updateMutation.isPending}
              >
                <Save className="mr-1.5 h-3.5 w-3.5" />
                {updateMutation.isPending ? "Saving..." : "Save Profiles"}
              </Button>
              {updateMutation.error ? (
                <p className="text-xs text-destructive">
                  {updateMutation.error.message}
                </p>
              ) : null}
              {updateMutation.isSuccess ? (
                <p className="text-xs text-success">Profiles updated</p>
              ) : null}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
