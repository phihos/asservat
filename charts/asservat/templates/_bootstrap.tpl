{{/* Static public input only; no lookup, random IDs, tokens or private values. */}}
{{- define "asservat.bootstrap.input" -}}
{{- $b := .Values.bootstrap -}}
{{- $v := dict "format" "asservat-bootstrap-input/v1" "name" $b.name "bootstrapNamespace" .Release.Namespace "targetNamespace" $b.targetNamespace "runnerAccount" (printf "%s-bootstrap-runner" $b.name) "image" $b.image "kubernetes" $b.kubernetes "postgres" $b.postgres "auditStore" $b.auditStore "keyService" $b.keyService "fleet" $b.fleet "providers" $b.providers -}}
{{- $services := default dict .Values.services -}}
{{- if eq (dig "postgres" "provider" "external" $services) "bundled" -}}
{{- $_ := set $v "postgres" (dict "host" (printf "%s-postgres.%s.svc" $b.name .Release.Namespace) "port" 5432 "database" "asservat" "maxConnections" 2 "rootsPEM" "" "rootsSource" "bundledPostgres") -}}
{{- end -}}
{{- if eq (dig "objectStore" "provider" "external" $services) "seaweedfs" -}}
{{- $_ := set $v "auditStore" (dict "endpoint" (printf "https://%s-objectstore.%s.svc:8333" $b.name .Release.Namespace) "region" (default "us-east-1" $b.auditStore.region) "bucket" (default (printf "%s-audit" $b.name) $b.auditStore.bucket) "rootsPEM" "" "rootsSource" "bundledSeaweed") -}}
{{- end -}}
{{- if eq (dig "keyService" "provider" "external" $services) "openbao" -}}
{{- $_ := set $v "keyService" (dict "endpoint" (printf "https://%s-openbao.%s.svc:8200" $b.name .Release.Namespace) "auditMount" "asservat-audit" "auditKey" "audit" "rootsPEM" "" "rootsSource" "bundledOpenBao") -}}
{{- end -}}
{{- if eq (dig "identity" "provider" "external" $services) "keycloak" -}}
{{- $k := .Values.services.identity.keycloak -}}
{{- $f := deepCopy $b.fleet -}}
{{- $client := default "asservat-console" $b.continuation.public.clientID -}}
{{- $clients := $f.clients -}}
{{- if not (has $client $clients) }}{{ $clients = append $clients $client }}{{ end -}}
{{- if and $k.mcpRedirectURIs (not (has "asservat-mcp" $clients)) }}{{ $clients = append $clients "asservat-mcp" }}{{ end -}}
{{- $_ := set $f "issuer" (printf "%s/realms/%s" $k.hostname $k.realm) -}}
{{- $_ := set $f "clients" $clients -}}
{{- $_ := set $v "fleet" $f -}}
{{- $_ := set $v "identitySource" "bundledKeycloak" -}}
{{- end -}}
{{- if hasKey $b "administrators" }}{{ $_ := set $v "administrators" $b.administrators }}{{ end -}}
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
{{- $services := default dict .Values.services -}}
{{- if and (eq $b.secrets.producer "") (eq (dig "postgres" "provider" "external" $services) "bundled") (eq (dig "objectStore" "provider" "external" $services) "seaweedfs") (eq (dig "keyService" "provider" "external" $services) "openbao") -}}
{{/* All private input is generated; the phase still selects only named keys. */}}
{{- $_ := set $v "producerSecret" (printf "%s-postgres-state" $b.name) -}}
{{- end -}}
{{- if eq (dig "postgres" "provider" "external" $services) "bundled" -}}
{{- $pg := printf "%s-postgres-state" $b.name -}}
{{- $_ := set $v "postgresSecret" $pg -}}
{{- $_ := set $v "schemaSecret" $pg -}}
{{- $_ := set $v "retirementSecret" $pg -}}
{{- end -}}
{{- if eq (dig "identity" "provider" "external" $services) "keycloak" }}{{ $_ := set $v "keycloakSecret" (printf "%s-keycloak-state" $b.name) }}{{ end -}}
{{- if eq (dig "objectStore" "provider" "external" $services) "seaweedfs" }}{{ $_ := set $v "objectStoreSecret" (printf "%s-objectstore-state" $b.name) }}{{ end -}}
{{- if eq (dig "keyService" "provider" "external" $services) "openbao" }}{{ $_ := set $v "keyServiceSecret" (printf "%s-openbao-state" $b.name) }}{{ end -}}
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
{{- $refs := fromJson (include "asservat.bootstrap.runner" .) -}}
{{- range $n := list $refs.producerSecret $refs.schemaSecret $refs.retirementSecret -}}
{{- if or (eq $n "") (gt (len $n) 253) (not (regexMatch "^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$" $n)) }}{{ fail "bootstrap requires the existing producer, schema and retirement Secret references" }}{{ end -}}
{{- end -}}
{{- if and $b.continuation.enabled $b.continuation.public.capacity $b.continuation.public.federation -}}
{{- $p := $b.continuation.public -}}
{{- if $p.federation.connector -}}
{{- $c := $p.federation.connector -}}
{{- $backup := $p.capacity.backup -}}
{{- $minimumRetained := add (int64 $c.validSeconds) (mul 2 (int64 $backup.horizonSeconds)) (mul 3 (int64 $backup.cleanupBudgetSeconds)) (int64 $backup.proofWindowSeconds) 60 -}}
{{- if lt (int64 $c.retainedSeconds) $minimumRetained }}{{ fail "bootstrap.continuation.public.federation.connector.retainedSeconds must cover validSeconds + 2*capacity.backup.horizonSeconds + 3*capacity.backup.cleanupBudgetSeconds + capacity.backup.proofWindowSeconds + 60 for original retirement backing" }}{{ end -}}
{{- end -}}
{{- end -}}
{{- if gt (len (include "asservat.bootstrap.input" .)) 49152 }}{{ fail "complete bootstrap public input exceeds 48 KiB" }}{{ end -}}
{{- if and $b.continuation.enabled (gt (len (include "asservat.bootstrap.continuation" .)) 65536) }}{{ fail "complete continuation public input exceeds 64 KiB" }}{{ end -}}
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
{{- $services := default dict .Values.services -}}
{{- if eq (dig "postgres" "provider" "external" $services) "bundled" }}
- secret:
    name: {{ printf "%s-postgres-state" .Values.bootstrap.name | quote }}
    optional: false
    items:
      - key: ca.crt
        path: postgres-ca.crt
{{- end }}
{{- if eq (dig "identity" "provider" "external" $services) "keycloak" }}
- secret:
    name: {{ printf "%s-keycloak-state" .Values.bootstrap.name | quote }}
    optional: false
    items:
      - key: settings.json
        path: keycloak-settings.json
      - key: users-group-id
        path: users-group-id
{{- end }}
{{- if eq (dig "objectStore" "provider" "external" $services) "seaweedfs" }}
- secret:
    name: {{ printf "%s-objectstore-state" .Values.bootstrap.name | quote }}
    optional: false
    items:
      - key: ca.crt
        path: objectstore-ca.crt
      - key: plan.json
        path: objectstore-plan.json
{{- end }}
{{- if eq (dig "keyService" "provider" "external" $services) "openbao" }}
- secret:
    name: {{ printf "%s-openbao-state" .Values.bootstrap.name | quote }}
    optional: false
    items:
      - key: plan.json
        path: openbao-plan.json
      - key: ca.crt
        path: openbao-ca.crt
      - key: backend-id
        path: openbao-backend-id
{{- end }}
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
{{- if $c.materialSecretName }}{{ $_ := set $v "materialSecretName" $c.materialSecretName }}{{ end -}}
{{- if eq .Values.services.objectStore.provider "seaweedfs" }}{{ $_ := set $v "objectStoreSource" "bundledSeaweed" }}{{ end -}}
{{- if eq .Values.services.keyService.provider "openbao" }}{{ $_ := set $v "keyServiceSource" "bundledOpenBao" }}{{ end -}}
{{- if and (hasKey $c.public "processors") (not $c.public.origin) }}{{ fail "bootstrap.continuation.public.processors requires public.origin" }}{{ end -}}
{{- if and (hasKey $c.public "captureHistory") (not $c.public.origin) }}{{ fail "bootstrap.continuation.public.captureHistory requires public.origin" }}{{ end -}}
{{- if and $c.public.permissionDelegations (not $c.public.origin) }}{{ fail "bootstrap.continuation.public.permissionDelegations requires public.origin" }}{{ end -}}
{{- range $field := list "capacity" "processingOperators" "federation" "promotion" "retentionBaseline" -}}
{{- if and (hasKey $c.public $field) (not $c.public.origin) }}{{ fail (printf "bootstrap.continuation.public.%s requires public.origin" $field) }}{{ end -}}
{{- end -}}
{{- if $c.public.origin -}}
{{- $p := $c.public -}}
{{- $clients := list -}}
{{- range $p.clients }}{{ $clients = append $clients (dict "id" .id "kind" .kind "classQualified" true) }}{{ end -}}
{{- $_ := set $v "public" (dict "origin" $p.origin "issuer" $p.issuer "clientID" $p.clientID "maxLifetimeSeconds" (int $p.maxLifetimeSeconds) "maxLogins" (int $p.maxLogins) "maxSessions" (int $p.maxSessions) "maxLogoutEvents" (int $p.maxLogoutEvents) "clients" $clients "eligibleSubjects" $p.eligibleSubjects "eligibleGroups" $p.eligibleGroups "groupMaxAgeSeconds" (int $p.groupMaxAgeSeconds)) -}}
{{- if eq .Values.services.identity.provider "keycloak" -}}
{{- $k := .Values.services.identity.keycloak -}}
{{- $public := get $v "public" -}}
{{- $client := default "asservat-console" $p.clientID -}}
{{- $_ := set $public "issuer" (printf "%s/realms/%s" $k.hostname $k.realm) -}}
{{- $_ := set $public "clientID" $client -}}
{{- $known := dict -}}
{{- range $clients }}{{ $_ := set $known .id true }}{{ end -}}
{{- if not (hasKey $known $client) }}{{ $clients = append $clients (dict "id" $client "kind" "human" "classQualified" true) }}{{ end -}}
{{- if and $k.mcpRedirectURIs (not (hasKey $known "asservat-mcp")) }}{{ $clients = append $clients (dict "id" "asservat-mcp" "kind" "human" "classQualified" true) }}{{ end -}}
{{- $_ := set $public "clients" $clients -}}
{{- $_ := set $v "identitySource" "bundledKeycloak" -}}
{{- end -}}
{{- range $field := list "processingOperators" "federation" "promotion" "retentionBaseline" -}}
{{- if hasKey $p $field }}{{ $_ := set (get $v "public") $field (get $p $field) }}{{ end -}}
{{- end -}}
{{- if and (eq .Values.services.keyService.provider "openbao") $p.federation -}}
{{- $f := deepCopy (get (get $v "public") "federation") -}}
{{/* Closed DTO fields stay explicit until the original provider resolves them. */}}
{{- range $field := list "connectorPKIMount" "connectorIssuerRootsPEM" -}}
{{- if not (hasKey $f $field) }}{{ $_ := set $f $field "" }}{{ end -}}
{{- end -}}
{{- $_ := set (get $v "public") "federation" $f -}}
{{- end -}}
{{- if and (eq .Values.services.objectStore.provider "seaweedfs") $p.federation (hasKey $p.federation "evidenceStore") -}}
{{- $b := .Values.bootstrap -}}
{{- $f := deepCopy (get (get $v "public") "federation") -}}
{{- $e := get $f "evidenceStore" -}}
{{- $region := default "us-east-1" $b.auditStore.region -}}
{{- $bucket := default (printf "%s-audit" $b.name) $b.auditStore.bucket -}}
{{- if or (and $e.region (ne $e.region $region)) (and $e.bucket (ne $e.bucket $bucket)) }}{{ fail "bundled object storage uses one owned audit/evidence bucket and region" }}{{ end -}}
{{- $_ := set $e "endpoint" (printf "https://%s-objectstore.%s.svc:8333" $b.name .Release.Namespace) -}}
{{- $_ := set $e "rootsPEM" "" -}}
{{- $_ := set $e "region" $region -}}
{{- $_ := set $e "bucket" $bucket -}}
{{- $_ := set (get $v "public") "federation" $f -}}
{{- end -}}
{{- if hasKey $p "capacity" -}}
{{- $capacity := deepCopy $p.capacity -}}
{{- if hasKey $capacity "policySpec" -}}
{{- $scope := get $capacity.policySpec "scope" -}}
{{- if not (hasKey $scope "clusterID") }}{{ $_ := set $scope "clusterID" "" }}{{ end -}}
{{- end -}}
{{- $_ := set (get $v "public") "capacity" $capacity -}}
{{- end -}}
{{- if hasKey $p "processors" }}{{ $_ := set (get $v "public") "processors" $p.processors }}{{ end -}}
{{- if hasKey $p "approvals" }}{{ $_ := set (get $v "public") "approvals" $p.approvals }}{{ end -}}
{{- if hasKey $p "captureHistory" }}{{ $_ := set (get $v "public") "captureHistory" $p.captureHistory }}{{ end -}}
{{- if $p.permissionDelegations }}{{ $_ := set (get $v "public") "permissionDelegations" $p.permissionDelegations }}{{ end -}}
{{- end -}}
{{- toJson $v -}}
{{- end -}}
