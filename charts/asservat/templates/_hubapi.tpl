{{/* Minimal hub-api helpers (Helm-native installation). Replace with the
shared _helpers.tpl names once the chart stream adds them. */}}
{{- define "asservat.hubApi.prefix" -}}{{ .Values.installation.name }}{{- end }}
{{- define "asservat.hubApi.name" -}}{{ printf "%s-hub-api" .Values.installation.name }}{{- end }}
{{- define "asservat.hubApi.labels" -}}
app.kubernetes.io/name: asservat
app.kubernetes.io/instance: {{ .Release.Name | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service | quote }}
app.kubernetes.io/part-of: asservat
app.kubernetes.io/component: hub-api
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | quote }}
{{- end }}
{{- define "asservat.hubApi.selector" -}}
asservat.io/private-role: hub-api
asservat.io/workload: {{ include "asservat.hubApi.name" . }}
{{- end }}
{{- define "asservat.hubApi.image" -}}
{{- if or (not .Values.image.repository) (not (regexMatch "^sha256:[a-f0-9]{64}$" .Values.image.digest)) }}
{{- fail "hub.hubApi requires image.repository and image.digest (sha256:...)" }}
{{- end }}
{{- printf "%s@%s" .Values.image.repository .Values.image.digest }}
{{- end }}
{{- define "asservat.hubApi.workerNamespaces" -}}
{{- $p := include "asservat.hubApi.prefix" . }}
{{- $n := .Values.hub.hubApi.workerNamespaces | default (list (printf "%s-downloads" $p)) }}
{{- toJson $n }}
{{- end }}
{{/* The hub-api config.json (contracts.HubAPIConfig). Only render-time values. */}}
{{- define "asservat.hubApi.config" -}}
{{- $p := include "asservat.hubApi.prefix" . }}
{{- $b := .Values.bootstrap.name }}
{{- $ns := .Release.Namespace }}
{{- $h := .Values.hub.hubApi }}
{{- $pg := $h.postgres }}
{{- $c := dict "format" "asservat-hub-api-config/v1" "namespace" $ns "deployment" (include "asservat.hubApi.name" .) "serviceAccount" (include "asservat.hubApi.name" .) "ownerConfiguration" (printf "%s-owner-source" $p) "auditCredentials" (printf "%s-s3-hub-api" $p) "providerAuthMount" $h.providerAuthMount "connections" $h.connections "concurrency" $h.concurrency }}
{{- $_ := set $c "postgres" (dict "host" ($pg.host | default (printf "%s-postgres.%s.svc" $b $ns)) "port" $pg.port "database" $pg.database "maxConnections" $pg.maxConnections) }}
{{- $_ := set $c "auditStore" (dict "endpoint" ($h.auditStore.endpoint | default (printf "https://%s-objectstore.%s.svc:8333" $b $ns)) "region" $h.auditStore.region "bucket" $h.auditStore.bucket) }}
{{- $k := $h.keyService }}
{{- $_ := set $c "keyService" (dict "endpoint" ($k.endpoint | default (printf "https://%s-openbao.%s.svc:8200" $b $ns)) "auditMount" $k.auditMount "auditKey" $k.auditKey "pkiMount" $k.pkiMount "serverRole" (printf "%s-owner-server" $p) "clientRole" (printf "%s-owner-client" $p)) }}
{{- $obs := dict }}
{{- if $h.peers }}{{- $_ := set $obs "peers" $h.peers }}{{- end }}
{{- with .Values.capacity }}{{- if .keys }}
{{- $lc := dict "keys" (sortAlpha .keys) "callerAccount" (printf "%s-hub-worker" $p) "callerDeployment" (printf "%s-hub-worker" $p) }}
{{- if .labelKeys }}{{- $_ := set $lc "labelKeys" .labelKeys }}{{- end }}
{{- if .annotationKeys }}{{- $_ := set $lc "annotationKeys" .annotationKeys }}{{- end }}
{{- $_ := set $obs "localCapacity" $lc }}
{{- end }}{{- end }}
{{- $_ := set $c "observation" $obs }}
{{- $workers := list }}
{{- range (include "asservat.hubApi.workerNamespaces" . | fromJsonArray) }}{{- $workers = append $workers (dict "namespace" .) }}{{- end }}
{{- $_ := set $c "native" (dict "connectorPKIMount" $h.connectorPKIMount "workerAPIs" $workers "retentionTopologies" $h.retentionTopologies "connections" $h.connections "concurrency" $h.concurrency) }}
{{- if .Values.origin }}
{{- $u := $h.public }}
{{- $pub := dict "origin" .Values.origin "browserAudience" .Values.identity.browserAudience "browserSettings" (printf "%s-browser-settings" $p) "identitySettings" (printf "%s-identity-settings" $p) "sessionTransit" (dict "mount" $u.transitMount "key" (printf "%s-browser-sessions" $p)) "clusterCatalog" (printf "%s-cluster-catalog" $p) "workSigning" (dict "mount" $u.transitMount "name" (printf "%s-work-signing" $p)) "workerConfiguration" (printf "%s-worker-profile" $p) "workerPKI" (dict "mount" $u.workerPKIMount "role" (printf "%s-download-worker" $p)) "downloadEnvironment" (printf "%s-download-environment" $p) "artifactKeyID" (printf "%s-artifact" $p) }}
{{- range $key := list "standby" "captures" "previewSeconds" "operationConcurrency" "mcpPerIdentity" "downloadConcurrency" "downloadsPerIdentity" "downloadMaxSeconds" "operationAudit" "downloadPlan" }}{{- $_ := set $pub $key (index $u $key) }}{{- end }}
{{- if $u.processing }}{{- $_ := set $pub "processing" (printf "%s-processing-source" $p) }}{{- end }}
{{- if $u.permissionDelegations }}{{- $_ := set $pub "permissionDelegations" $u.permissionDelegations }}{{- end }}
{{- if $u.captureHistory }}{{- $_ := set $pub "captureHistory" $u.captureHistory }}{{- end }}
{{- if eq .Values.exposure.tls "proxy" }}{{- $_ := set $pub "proxyTLS" true }}{{- end }}
{{- $_ := set $pub "port" 9445 }}
{{- $_ := set $pub "version" (.Chart.AppVersion | default .Chart.Version) }}
{{- if .Values.fleet.enabled }}{{- $_ := set $pub "fleet" (dict "settings" .Values.fleet.settings "channelMount" .Values.fleet.channelMount "deliveryProfile" .Values.fleet.deliveryProfile) }}{{- end }}
{{- $_ := set $c "public" $pub }}
{{- end }}
{{- toJson $c }}
{{- end }}
