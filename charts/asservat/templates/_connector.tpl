{{/* Region-specific checks of the connector and collector templates. */}}
{{- define "asservat.region.uuid" -}}
{{- if not (regexMatch "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$" .value) -}}
{{- fail (printf "%s must be the UUID from the console's cluster bootstrap receipt" .field) -}}
{{- end -}}
{{- .value -}}
{{- end -}}
