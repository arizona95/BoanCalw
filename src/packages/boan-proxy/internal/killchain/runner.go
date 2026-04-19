package killchain

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/samsung-sds/boanclaw/boan-proxy/internal/userstore"
	"github.com/samsung-sds/boanclaw/boan-proxy/internal/workstation"
)

// Runner executes the kill chain sequence against a single VM. Each step
// updates the incident record so the UI can stream progress via polling.
//
// Sequence:
//  1. isolate-network      — add boan-quarantine tag (egress deny).
//  2. ram-dump              — (best-effort) skipped in v1; logs as "skipped".
//  3. forensic-disk-snapshot — GCP Custom Image.
//  4. stop-instance         — VM STOP (RAM truly evaporates).
//  5. delete-instance       — VM DELETE.
//
// If any step fails, the incident is marked "partial" and subsequent steps
// continue (delete still happens even if snapshot fails — we prioritize
// containment over forensics).
type Runner struct {
	Store *Store
	Prov  workstation.Provisioner
}

// Run — kicks off the sequence in the background. Returns the incident
// immediately so the UI can navigate to its detail page.
func (r *Runner) Run(ctx context.Context, inc Incident, ws *userstore.Workstation) (Incident, error) {
	if ws == nil {
		return Incident{}, fmt.Errorf("no workstation to run kill chain against")
	}
	inc.TargetVM = instanceName(ws)
	created, err := r.Store.CreateIncident(inc)
	if err != nil {
		return Incident{}, err
	}
	go r.execute(context.Background(), created.ID, ws)
	return created, nil
}

func (r *Runner) execute(ctx context.Context, incidentID string, ws *userstore.Workstation) {
	log.Printf("[killchain] starting incident=%s target=%s", incidentID, instanceName(ws))
	failures := 0

	// 1) isolate network
	r.runStep(ctx, incidentID, "isolate-network", func(ctx context.Context) (string, error) {
		if err := r.Prov.IsolateNetwork(ctx, ws); err != nil {
			return "", err
		}
		return fmt.Sprintf("tagged VM with boan-quarantine + ensured deny-all egress firewall"), nil
	}, &failures)

	// 2) RAM dump — v1: skipped. winpmem integration 은 후속 작업.
	//    skipped 상태로 기록해 향후 확장 여지를 명확히 남긴다.
	_ = r.Store.AppendStep(incidentID, IncidentStep{
		Name:      "ram-dump",
		StartedAt: time.Now().UTC(),
		Status:    "skipped",
		Detail:    "v1: winpmem integration 미구현. 골든이미지에 winpmem 포함 + PowerShell Remote 실행 후 GCS 업로드 로드맵.",
	})

	// 3) forensic disk snapshot
	r.runStep(ctx, incidentID, "forensic-disk-snapshot", func(ctx context.Context) (string, error) {
		uri, err := r.Prov.ForensicDiskSnapshot(ctx, ws, incidentID)
		if err != nil {
			return "", err
		}
		return "image=" + uri, nil
	}, &failures)

	// 4) stop instance (RAM gone)
	r.runStep(ctx, incidentID, "stop-instance", func(ctx context.Context) (string, error) {
		if err := r.Prov.StopInstance(ctx, ws); err != nil {
			return "", err
		}
		return "VM stopped — RAM cleared", nil
	}, &failures)

	// 5) delete instance
	r.runStep(ctx, incidentID, "delete-instance", func(ctx context.Context) (string, error) {
		if err := r.Prov.Delete(ctx, "", "", ws); err != nil {
			return "", err
		}
		return "VM deleted", nil
	}, &failures)

	// finalize incident status
	final := "success"
	if failures > 0 {
		final = "partial"
		if failures >= 3 {
			final = "failed"
		}
	}
	_ = r.Store.UpdateIncident(incidentID, func(inc *Incident) {
		inc.Status = final
	})
	log.Printf("[killchain] incident=%s finished status=%s failures=%d", incidentID, final, failures)
}

func (r *Runner) runStep(
	ctx context.Context,
	incidentID, name string,
	fn func(ctx context.Context) (string, error),
	failures *int,
) {
	_ = r.Store.AppendStep(incidentID, IncidentStep{
		Name:      name,
		StartedAt: time.Now().UTC(),
		Status:    "running",
	})
	artifact, err := fn(ctx)
	if err != nil {
		*failures++
		_ = r.Store.FinishStep(incidentID, name, "failed", err.Error(), "")
		log.Printf("[killchain] incident=%s step=%s FAILED: %v", incidentID, name, err)
		return
	}
	detail := ""
	art := ""
	// detail 과 artifact 를 분리 — "image=..." 형식이면 artifact 로 옮김.
	if strings.HasPrefix(artifact, "image=") {
		art = strings.TrimPrefix(artifact, "image=")
		detail = "disk snapshot created"
	} else {
		detail = artifact
	}
	_ = r.Store.FinishStep(incidentID, name, "success", detail, art)
	log.Printf("[killchain] incident=%s step=%s OK", incidentID, name)
}

func instanceName(ws *userstore.Workstation) string {
	if ws == nil {
		return ""
	}
	id := strings.TrimSpace(ws.InstanceID)
	if id == "" {
		return ""
	}
	// InstanceID 는 "projects/.../zones/.../instances/{name}" 전체 URI 거나 bare name
	if idx := strings.LastIndex(id, "/instances/"); idx >= 0 {
		return id[idx+len("/instances/"):]
	}
	return id
}
