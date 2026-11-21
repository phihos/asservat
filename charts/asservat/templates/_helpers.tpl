{{- define "asservat.image" -}}
{{ .Values.image.repository }}:{{ .Values.image.tag | default .Chart.AppVersion }}
{{- end }}

{{- define "asservat.labels" -}}
app.kubernetes.io/name: asservat
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/* A generated secret value that stays the same across upgrades. */}}
{{- define "asservat.kept" -}}
{{- $secret := lookup "v1" "Secret" .root.Release.Namespace .name -}}
{{- if and $secret (hasKey $secret.data .key) -}}
{{ index $secret.data .key }}
{{- else -}}
{{ .value | b64enc }}
{{- end -}}
{{- end }}

{{- define "asservat.agentSecret" -}}
{{ .Values.agent.existingSecret | default (printf "%s-agent" .Release.Name) }}
{{- end }}
