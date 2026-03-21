{{/*
Expand the name of the chart.
*/}}
{{- define "crowdsec-manager.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully-qualified app name, truncated to 63 chars.
*/}}
{{- define "crowdsec-manager.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Chart label.
*/}}
{{- define "crowdsec-manager.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels applied to every resource.
*/}}
{{- define "crowdsec-manager.labels" -}}
helm.sh/chart: {{ include "crowdsec-manager.chart" . }}
{{ include "crowdsec-manager.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels used by Services and Deployments.
*/}}
{{- define "crowdsec-manager.selectorLabels" -}}
app.kubernetes.io/name: {{ include "crowdsec-manager.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Tailscale Secret name — either the user's existing secret or the chart-managed one.
*/}}
{{- define "crowdsec-manager.tailscaleSecretName" -}}
{{- if .Values.tailscaleSecret.existingSecret }}
{{- .Values.tailscaleSecret.existingSecret }}
{{- else }}
{{- printf "%s-tailscale" (include "crowdsec-manager.fullname" .) }}
{{- end }}
{{- end }}

{{/*
NATS Secret name.
*/}}
{{- define "crowdsec-manager.natsSecretName" -}}
{{- if .Values.natsSecret.existingSecret }}
{{- .Values.natsSecret.existingSecret }}
{{- else }}
{{- printf "%s-nats" (include "crowdsec-manager.fullname" .) }}
{{- end }}
{{- end }}

{{/*
PVC name helper.
Usage: include "crowdsec-manager.pvcName" (dict "root" . "key" "data")
Returns existingClaim if set, otherwise the chart-generated name.
*/}}
{{- define "crowdsec-manager.pvcName" -}}
{{- $pvc := index .root.Values.persistence .key }}
{{- if $pvc.existingClaim }}
{{- $pvc.existingClaim }}
{{- else }}
{{- printf "%s-%s" (include "crowdsec-manager.fullname" .root) .key | lower }}
{{- end }}
{{- end }}
