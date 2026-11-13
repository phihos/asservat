{{/* Shared names of the connector, collector and download-worker templates. */}}
{{- define "asservat.region.name" -}}
{{- .Values.installation.name | default "asservat" -}}
{{- end -}}

{{- define "asservat.region.image" -}}
{{- $i := .Values.image -}}
{{- if or (not (regexMatch "^[a-z0-9][a-z0-9./:_-]{0,383}$" ($i.repository | default ""))) (not (regexMatch "^sha256:[a-f0-9]{64}$" ($i.digest | default ""))) -}}
{{- fail "image.repository and image.digest (sha256:...) are required" -}}
{{- end -}}
{{- printf "%s@%s" $i.repository $i.digest -}}
{{- end -}}

{{- define "asservat.region.pullSecrets" -}}
{{- with .Values.image.pullSecrets }}
imagePullSecrets:
{{- range . }}
  - name: {{ . | quote }}
{{- end }}
{{- end }}
{{- end -}}

{{- define "asservat.region.labels" -}}
app.kubernetes.io/part-of: asservat
app.kubernetes.io/instance: {{ .Release.Name | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service | quote }}
{{- end -}}

{{- define "asservat.region.uuid" -}}
{{- if not (regexMatch "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$" .value) -}}
{{- fail (printf "%s must be the UUID from the console's cluster bootstrap receipt" .field) -}}
{{- end -}}
{{- .value -}}
{{- end -}}
