"use client";

import * as React from "react";

import { RefreshCwIcon, ShieldAlertIcon, ShieldCheckIcon } from "lucide-react";
import { toast } from "sonner";

import { AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent, AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle, AlertDialogTrigger } from "@/components/ui/alert-dialog";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { t } from "@/i18n";
import { api } from "@/lib/api";
import type { Task } from "@/lib/types";

type ProgramPolicyStatus = Awaited<ReturnType<typeof api.programPolicyStatus>>;

export function TaskProgramPolicyPanel({ task }: { task: Task }) {
  const [status, setStatus] = React.useState<ProgramPolicyStatus | null>(null);
  const [loading, setLoading] = React.useState(false);
  const [revoking, setRevoking] = React.useState(false);
  const [dialogOpen, setDialogOpen] = React.useState(false);
  const [reason, setReason] = React.useState("");

  const refresh = React.useCallback(async () => {
    setLoading(true);
    try {
      setStatus(await api.programPolicyStatus(task.id));
    } catch (error) {
      setStatus(null);
      toast.error(t("Could not load ProgramPolicy status: {error}", { error: (error as Error).message }));
    } finally {
      setLoading(false);
    }
  }, [task.id]);

  React.useEffect(() => {
    void refresh();
  }, [refresh]);

  const revoke = async () => {
    const trimmed = reason.trim();
    if (!trimmed || revoking) return;
    setRevoking(true);
    try {
      await api.revokeProgramPolicy(task.id, trimmed);
      toast.success(t("ProgramPolicy source revoked. All tasks using this exact source are blocked."));
      setDialogOpen(false);
      setReason("");
      await refresh();
    } catch (error) {
      toast.error(t("ProgramPolicy revocation failed: {error}", { error: (error as Error).message }));
    } finally {
      setRevoking(false);
    }
  };

  const state = status?.revoked
    ? "revoked"
    : status?.expired
      ? "expired"
      : status?.active
        ? "active"
        : "unknown";
  const badgeVariant = state === "active" ? "outline" : "destructive";

  return (
    <div className="flex flex-wrap items-center gap-2 rounded-md border bg-muted/20 px-3 py-2">
      <Badge variant={badgeVariant}>
        {state === "active" ? <ShieldCheckIcon data-icon="inline-start" /> : <ShieldAlertIcon data-icon="inline-start" />}
        {t("ProgramPolicy")}: {state === "active" ? t("Active") : state === "revoked" ? t("Revoked") : state === "expired" ? t("Expired") : t("Status unavailable")}
      </Badge>
      {status && (
        <span className="text-xs text-muted-foreground">
          {status.program_id} · {t("Expires")} {new Date(status.expires_at).toLocaleString()}
          {status.revocation?.revoked_by ? ` · ${t("Revoked by")} ${status.revocation.revoked_by}` : ""}
        </span>
      )}
      <div className="ml-auto flex items-center gap-2">
        <Button type="button" size="sm" variant="ghost" onClick={() => void refresh()} disabled={loading}>
          <RefreshCwIcon className={loading ? "animate-spin" : ""} />
          {t("Refresh")}
        </Button>
        <AlertDialog open={dialogOpen} onOpenChange={setDialogOpen}>
          <AlertDialogTrigger asChild>
            <Button type="button" size="sm" variant="destructive" disabled={!status?.active || loading || revoking}>
              {t("Revoke policy")}
            </Button>
          </AlertDialogTrigger>
          <AlertDialogContent>
            <AlertDialogHeader>
              <AlertDialogTitle>{t("Permanently revoke this ProgramPolicy source?")}</AlertDialogTitle>
              <AlertDialogDescription>
                {t("This is irreversible. Every task using program {programId} with this exact source digest will be blocked. Create a new reviewed policy snapshot to resume testing.", { programId: status?.program_id ?? task.id })}
              </AlertDialogDescription>
            </AlertDialogHeader>
            <Textarea
              value={reason}
              onChange={(event) => setReason(event.target.value)}
              placeholder={t("Required reason for revocation")}
              rows={3}
              maxLength={2048}
            />
            <AlertDialogFooter>
              <AlertDialogCancel disabled={revoking}>{t("Cancel")}</AlertDialogCancel>
              <AlertDialogAction
                disabled={!reason.trim() || revoking}
                onClick={(event) => {
                  event.preventDefault();
                  void revoke();
                }}
              >
                {revoking ? t("Revoking…") : t("Confirm revoke")}
              </AlertDialogAction>
            </AlertDialogFooter>
          </AlertDialogContent>
        </AlertDialog>
      </div>
    </div>
  );
}
