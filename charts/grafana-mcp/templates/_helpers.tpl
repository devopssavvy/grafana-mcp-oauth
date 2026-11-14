{{/* vim: set filetype=mustache: */}}
{{/*
Expand the name of the chart.
*/}}
{{- define "grafana-mcp.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this.
If release name contains chart name it will be used as a full name.
*/}}
{{- define "grafana-mcp.fullname" -}}
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
Create chart name and version as used by the chart label.
*/}}
{{- define "grafana-mcp.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create the name of the service account
*/}}
{{- define "grafana-mcp.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "grafana-mcp.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Allow the release namespace to be overridden
*/}}
{{- define "grafana-mcp.namespace" -}}
{{- if .Values.namespaceOverride }}
{{- .Values.namespaceOverride }}
{{- else }}
{{- .Release.Namespace }}
{{- end }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "grafana-mcp.labels" -}}
helm.sh/chart: {{ include "grafana-mcp.chart" . }}
{{ include "grafana-mcp.selectorLabels" . }}
{{- if or .Chart.AppVersion .Values.image.tag }}
app.kubernetes.io/version: {{ .Values.image.tag | default .Chart.AppVersion | trunc 63 | trimSuffix "-" | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- with .Values.extraLabels }}
{{ toYaml . }}
{{- end }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "grafana-mcp.selectorLabels" -}}
app.kubernetes.io/name: {{ include "grafana-mcp.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Valkey / Redis host address helper
*/}}
{{- define "grafana-mcp.redisAddr" -}}
{{- if .Values.valkey.enabled -}}
{{- printf "%s-valkey:6379" .Release.Name -}}
{{- else -}}
{{- .Values.redis.addr -}}
{{- end -}}
{{- end }}

{{/*
Valkey / Redis secret name helper
*/}}
{{- define "grafana-mcp.redisSecretName" -}}
{{- if .Values.redis.existingSecret -}}
{{- .Values.redis.existingSecret -}}
{{- else if and .Values.valkey.enabled .Values.valkey.auth.usersExistingSecret -}}
{{- tpl .Values.valkey.auth.usersExistingSecret . -}}
{{- else -}}
{{- printf "%s-valkey-auth" (include "grafana-mcp.fullname" .) -}}
{{- end -}}
{{- end }}

{{/*
Valkey / Redis TLS secret name helper
*/}}
{{- define "grafana-mcp.tlsSecretName" -}}
{{- if .Values.redis.tls.existingSecret -}}
{{- .Values.redis.tls.existingSecret -}}
{{- else if and .Values.valkey.enabled .Values.valkey.tls.existingSecret -}}
{{- tpl .Values.valkey.tls.existingSecret . -}}
{{- else -}}
{{- printf "%s-valkey-tls" (include "grafana-mcp.fullname" .) -}}
{{- end -}}
{{- end }}

{{/*
Valkey auth password lookup or generation
*/}}
{{- define "grafana-mcp.valkeyPassword" -}}
{{- if .Values.redis.password -}}
{{- .Values.redis.password -}}
{{- else -}}
{{- $secret := (lookup "v1" "Secret" (include "grafana-mcp.namespace" .) (include "grafana-mcp.redisSecretName" .)) -}}
{{- if and $secret (hasKey $secret.data "password") -}}
{{- index $secret.data "password" | b64dec -}}
{{- else -}}
{{- randAlphaNum 32 -}}
{{- end -}}
{{- end -}}
{{- end }}
