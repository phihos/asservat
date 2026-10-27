{{/* Static public input only; no lookup, random IDs, tokens or private values. */}}
{{- define "asservat.bootstrap.input" -}}
{{- $b := .Values.bootstrap -}}
{{- $v := dict "format" "asservat-bootstrap-input/v1" "name" $b.name "bootstrapNamespace" .Release.Namespace "targetNamespace" $b.targetNamespace "runnerAccount" (printf "%s-bootstrap-runner" $b.name) "image" $b.image "kubernetes" $b.kubernetes "postgres" $b.postgres "auditStore" $b.auditStore "keyService" $b.keyService "fleet" $b.fleet "providers" $b.providers -}}
{{- if $b.probeAudience }}{{ $_ := set $v "probeAudience" $b.probeAudience }}{{ end -}}
{{- if $b.registrySecret }}{{ $_ := set $v "registryAuthentication" "dockerconfigjson/v1" }}{{ end -}}
{{/* Preserve omitempty semantics required by the closed public wire. */}}
{{- $k := dict "endpoint" $b.kubernetes.endpoint -}}
{{- if $b.kubernetes.rootsPEM }}{{ $_ := set $k "rootsPEM" $b.kubernetes.rootsPEM }}{{ end -}}
{{- $_ := set $v "kubernetes" $k -}}
{{- toJson $v -}}
{{- end -}}

{{- define "asservat.bootstrap.runner" -}}
{{- $b := .Values.bootstrap -}}
{{- $v := dict "format" "asservat-bootstrap-runner/v1" "producerSecret" $b.secrets.producer "schemaSecret" $b.secrets.schema "retirementSecret" $b.secrets.retirement -}}
{{- if $b.registrySecret }}{{ $_ := set $v "registrySecret" $b.registrySecret }}{{ end -}}
{{- if $b.continuation.enabled }}{{ $_ := set $v "continuationDigest" (include "asservat.bootstrap.continuation" . | sha256sum) }}{{ end -}}
{{- toJson $v -}}
{{- end -}}

{{- define "asservat.bootstrap.validate" -}}
{{- if .Values.bootstrap.enabled -}}
{{- $b := .Values.bootstrap -}}
{{- if eq .Values.mode "cluster" }}{{ fail "bootstrap requires the hub or combined release; it cannot enroll a workload cluster" }}{{ end -}}
{{- if or (eq .Release.Namespace "default") (hasPrefix "kube-" .Release.Namespace) (eq .Release.Namespace $b.targetNamespace) }}{{ fail "bootstrap requires a dedicated trusted Restricted namespace distinct from targetNamespace" }}{{ end -}}
{{- if or (gt (len $b.name) 30) (not (regexMatch "^[a-z0-9]([-a-z0-9]*[a-z0-9])?$" $b.name)) }}{{ fail "bootstrap.name must be a stable DNS label of at most 30 characters" }}{{ end -}}
{{- if not (regexMatch "^[a-z0-9][a-z0-9./:_-]{0,383}@sha256:[a-f0-9]{64}$" $b.image) }}{{ fail "bootstrap.image requires the exact verified product repository@sha256 digest" }}{{ end -}}
{{- range $n := list $b.secrets.producer $b.secrets.schema $b.secrets.retirement -}}
{{- if or (eq $n "") (gt (len $n) 253) (not (regexMatch "^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$" $n)) }}{{ fail "bootstrap requires the existing producer, schema and retirement Secret references" }}{{ end -}}
{{- end -}}
{{- if gt (len (include "asservat.bootstrap.input" .)) 49152 }}{{ fail "complete bootstrap public input exceeds 48 KiB" }}{{ end -}}
{{- end -}}
{{- end -}}

{{- define "asservat.bootstrap.security" -}}
allowPrivilegeEscalation: false
readOnlyRootFilesystem: true
capabilities:
  drop: [ALL]
{{- end -}}

{{- define "asservat.bootstrap.resources" -}}
requests:
  cpu: 20m
  memory: 32Mi
limits:
  cpu: "1"
  memory: 256Mi
{{- end -}}

{{- define "asservat.bootstrap.commonProjection" -}}
- configMap:
    name: {{ include "asservat.bootstrap.inputName" . }}
    optional: false
    items:
      - key: bootstrap.json
        path: bootstrap.json
- serviceAccountToken:
    path: administrator-token
    expirationSeconds: 600
    {{- if .Values.bootstrap.probeAudience }}
    audience: {{ .Values.bootstrap.probeAudience | quote }}
    {{- end }}
- configMap:
    name: kube-root-ca.crt
    optional: true
    items:
      - key: ca.crt
        path: kube-ca.crt
{{- end -}}

{{- define "asservat.bootstrap.inputDigest" -}}
{{- printf "%s\n%s" (include "asservat.bootstrap.input" .) (include "asservat.bootstrap.runner" .) | sha256sum -}}
{{- end -}}

{{- define "asservat.bootstrap.inputName" -}}
{{- $digest := include "asservat.bootstrap.inputDigest" . -}}
{{- printf "%s-bootstrap-input.%s.%s" .Values.bootstrap.name (substr 0 32 $digest) (substr 32 64 $digest) -}}
{{- end -}}

{{- define "asservat.bootstrap.continuation" -}}
{{- $c := .Values.bootstrap.continuation -}}
{{- $v := dict "format" "asservat-installer-continuation/v1" "namespace" .Release.Namespace "workerProvider" $c.workerProvider "ownerProvider" $c.ownerProvider "ownerIssuerRootsPEM" $c.ownerIssuerRootsPEM "ownerPKIMount" $c.ownerPKIMount "ownerConnections" (int $c.ownerConnections) "ownerConcurrency" (int $c.ownerConcurrency) -}}
{{- if and $c.public.permissionDelegations (not $c.public.origin) }}{{ fail "bootstrap.continuation.public.permissionDelegations requires public.origin" }}{{ end -}}
{{- if $c.public.origin -}}
{{- $p := $c.public -}}
{{- $clients := list -}}
{{- range $p.clients }}{{ $clients = append $clients (dict "id" .id "kind" .kind "classQualified" true) }}{{ end -}}
{{- $_ := set $v "public" (dict "origin" $p.origin "issuer" $p.issuer "clientID" $p.clientID "maxLifetimeSeconds" (int $p.maxLifetimeSeconds) "maxLogins" (int $p.maxLogins) "maxSessions" (int $p.maxSessions) "maxLogoutEvents" (int $p.maxLogoutEvents) "clients" $clients "eligibleSubjects" $p.eligibleSubjects "eligibleGroups" $p.eligibleGroups "groupMaxAgeSeconds" (int $p.groupMaxAgeSeconds)) -}}
{{- if $p.permissionDelegations }}{{ $_ := set (get $v "public") "permissionDelegations" $p.permissionDelegations }}{{ end -}}
{{- end -}}
{{- toJson $v -}}
{{- end -}}
