import { useState } from "react";
import { PageHeader } from "@/components/common/PageHeader";
import { Skeleton } from "@/components/ui/skeleton";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  usePublicIPQuery,
  useCheckBlockedMutation,
  useSecurityCheckMutation,
  useUnbanMutation,
} from "@/lib/api/ip";
import { Globe, Search, ShieldCheck, Unlock } from "lucide-react";

export function IPManagementPage() {
  const publicIP = usePublicIPQuery();
  const checkBlocked = useCheckBlockedMutation();
  const securityCheck = useSecurityCheckMutation();
  const unban = useUnbanMutation();

  const [checkIp, setCheckIp] = useState("");
  const [securityIp, setSecurityIp] = useState("");
  const [unbanIp, setUnbanIp] = useState("");

  return (
    <div className="space-y-6">
      <PageHeader
        title="IP Management"
        description="Check your public IP, verify blocked status, and manage bans"
      />

      {/* Public IP */}
      <div className="card-panel p-5">
        <div className="flex items-center gap-2">
          <Globe className="h-5 w-5 text-signal" />
          <h2 className="text-sm font-medium text-foreground">
            Your Public IP
          </h2>
        </div>
        <div className="mt-3">
          {publicIP.isLoading ? (
            <Skeleton className="h-8 w-48" />
          ) : publicIP.error ? (
            <p className="text-sm text-destructive">
              Failed to fetch public IP
            </p>
          ) : (
            <p className="font-data text-xl text-foreground">
              {publicIP.data?.ip ?? "Unknown"}
            </p>
          )}
        </div>
      </div>

      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
        {/* Check Blocked */}
        <div className="card-panel p-5">
          <div className="flex items-center gap-2">
            <Search className="h-5 w-5 text-muted-foreground" />
            <h2 className="text-sm font-medium text-foreground">
              Check if Blocked
            </h2>
          </div>
          <div className="mt-3 space-y-3">
            <Input
              placeholder="Enter IP address"
              value={checkIp}
              onChange={(e) => { setCheckIp(e.target.value); }}
            />
            <Button
              size="sm"
              className="w-full"
              onClick={() => { checkBlocked.mutate(checkIp); }}
              disabled={!checkIp || checkBlocked.isPending}
            >
              {checkBlocked.isPending ? "Checking..." : "Check"}
            </Button>
            {checkBlocked.data ? (
              <div className="rounded-md bg-muted p-3">
                <p className="font-data text-sm">
                  <span className="text-muted-foreground">IP:</span>{" "}
                  {checkBlocked.data.ip}
                </p>
                <p className="mt-1 text-sm">
                  <span className="text-muted-foreground">Blocked:</span>{" "}
                  <span
                    className={
                      checkBlocked.data.blocked
                        ? "text-destructive"
                        : "text-success"
                    }
                  >
                    {checkBlocked.data.blocked ? "Yes" : "No"}
                  </span>
                </p>
                {checkBlocked.data.reason ? (
                  <p className="mt-1 text-sm text-muted-foreground">
                    {checkBlocked.data.reason}
                  </p>
                ) : null}
              </div>
            ) : null}
            {checkBlocked.error ? (
              <p className="text-xs text-destructive">
                {checkBlocked.error.message}
              </p>
            ) : null}
          </div>
        </div>

        {/* Security Check */}
        <div className="card-panel p-5">
          <div className="flex items-center gap-2">
            <ShieldCheck className="h-5 w-5 text-muted-foreground" />
            <h2 className="text-sm font-medium text-foreground">
              Security Check
            </h2>
          </div>
          <div className="mt-3 space-y-3">
            <Input
              placeholder="Enter IP address"
              value={securityIp}
              onChange={(e) => { setSecurityIp(e.target.value); }}
            />
            <Button
              size="sm"
              className="w-full"
              onClick={() => { securityCheck.mutate(securityIp); }}
              disabled={!securityIp || securityCheck.isPending}
            >
              {securityCheck.isPending ? "Checking..." : "Analyze"}
            </Button>
            {securityCheck.data ? (
              <div className="rounded-md bg-muted p-3 space-y-1">
                <p className="font-data text-sm">
                  <span className="text-muted-foreground">IP:</span>{" "}
                  {securityCheck.data.ip}
                </p>
                <p className="text-sm">
                  <span className="text-muted-foreground">Reputation:</span>{" "}
                  {securityCheck.data.reputation}
                </p>
                {securityCheck.data.country ? (
                  <p className="text-sm">
                    <span className="text-muted-foreground">Country:</span>{" "}
                    {securityCheck.data.country}
                  </p>
                ) : null}
                <p className="text-sm">
                  <span className="text-muted-foreground">Reports:</span>{" "}
                  {String(securityCheck.data.reports)}
                </p>
              </div>
            ) : null}
            {securityCheck.error ? (
              <p className="text-xs text-destructive">
                {securityCheck.error.message}
              </p>
            ) : null}
          </div>
        </div>

        {/* Unban IP */}
        <div className="card-panel p-5">
          <div className="flex items-center gap-2">
            <Unlock className="h-5 w-5 text-muted-foreground" />
            <h2 className="text-sm font-medium text-foreground">Unban IP</h2>
          </div>
          <div className="mt-3 space-y-3">
            <Input
              placeholder="Enter IP address"
              value={unbanIp}
              onChange={(e) => { setUnbanIp(e.target.value); }}
            />
            <Button
              size="sm"
              variant="destructive"
              className="w-full"
              onClick={() => {
                unban.mutate(unbanIp, {
                  onSuccess: () => { setUnbanIp(""); },
                });
              }}
              disabled={!unbanIp || unban.isPending}
            >
              {unban.isPending ? "Unbanning..." : "Unban"}
            </Button>
            {unban.isSuccess ? (
              <p className="text-xs text-success">IP unbanned successfully</p>
            ) : null}
            {unban.error ? (
              <p className="text-xs text-destructive">
                {unban.error.message}
              </p>
            ) : null}
          </div>
        </div>
      </div>
    </div>
  );
}
