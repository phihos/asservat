{{/* hub-api-specific helpers; shared names, labels and providers are in
     _helpers.tpl. */}}

{{/* Download-worker namespaces in the hub cluster (JSON list). */}}
{{- define "asservat.hubApi.workerNamespaces" -}}
{{- $h := index .Values.hub "hub-api" -}}
{{- $d := default dict (index .Values.hub "download-worker") -}}
{{- $default := list -}}
{{- if dig "enabled" true $d }}{{ $default = list (printf "%s-downloads" (include "asservat.name" .)) }}{{ end -}}
{{- toJson (default $default $h.workerNamespaces) -}}
{{- end -}}

{{/* Browser identity: issuer and console client (JSON). Bundled Keycloak
     derives both from services.identity.keycloak. */}}
{{- define "asservat.hubApi.identity" -}}
{{- $i := .Values.identity -}}
{{- $out := dict "issuer" $i.issuer "clientID" $i.clientID -}}
{{- if eq .Values.services.identity.provider "keycloak" -}}
{{- $k := .Values.services.identity.keycloak -}}
{{- $_ := set $out "issuer" (default (printf "%s/realms/%s" $k.hostname $k.realm) $i.issuer) -}}
{{- $_ := set $out "clientID" (default "asservat-console" $i.clientID) -}}
{{- end -}}
{{- $_ := set $out "browserAudience" (default $out.clientID $i.browserAudience) -}}
{{- toJson $out -}}
{{- end -}}

{{/* The OIDC client secret: identity.clientSecret.existingSecret, or the
     bundled Keycloak's `<name>-keycloak-state` (console-client-secret). */}}
{{- define "asservat.hubApi.clientSecret" -}}
{{- $c := .Values.identity.clientSecret -}}
{{- if $c.existingSecret -}}
{{- toJson (dict "name" $c.existingSecret "key" (default "client-secret" $c.key)) -}}
{{- else if eq .Values.services.identity.provider "keycloak" -}}
{{- toJson (dict "name" (printf "%s-keycloak-state" (include "asservat.name" .)) "key" "console-client-secret") -}}
{{- else -}}
{{- fail "identity.clientSecret.existingSecret is required with an external identity provider" -}}
{{- end -}}
{{- end -}}

{{/* fleet.deliveryProfiles (JSON list). mode=combined and clusters default
     to ["local"]: the hub-api issues the local connector's and the remote
     clusters' bootstraps itself through the fleet issuance with the first
     profile. */}}
{{- define "asservat.hubApi.deliveryProfiles" -}}
{{- $default := list -}}
{{- if include "asservat.hubApi.offer" . }}{{ $default = list "local" }}{{ end -}}
{{- toJson (default $default .Values.fleet.deliveryProfiles) -}}
{{- end -}}

{{/* True when the regional connector shares this release (mode=combined). */}}
{{- define "asservat.hubApi.combined" -}}
{{- if eq .Values.mode "combined" }}true{{ end -}}
{{- end -}}

{{/* True when the hub publishes its regional offer: mode=combined or
     remote clusters joined with mode=cluster (values clusters). */}}
{{- define "asservat.hubApi.offer" -}}
{{- if or (include "asservat.hubApi.combined" .) (and (include "asservat.hub" .) .Values.clusters) }}true{{ end -}}
{{- end -}}

{{/* The joined remote clusters (contracts.RemoteCluster, JSON list). */}}
{{- define "asservat.hubApi.clusters" -}}
{{- $root := . -}}
{{- $out := list -}}
{{- range .Values.clusters -}}
{{- if not (regexMatch "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$" (toString .clusterID)) }}{{ fail (printf "clusters[%s].clusterID must be a lowercase UUID (uuidgen)" (toString .name)) }}{{ end -}}
{{- $out = append $out (dict "name" (required "clusters[].name is required" .name) "clusterID" .clusterID "namespace" (default $root.Release.Namespace .namespace) "standby" (int (default 2 .standby)) "captures" (int (default 1 .captures))) -}}
{{- end -}}
{{- toJson $out -}}
{{- end -}}

{{/* The hub-api config.json (contracts.HubAPIConfig): render-time values
     only. Object, key and role names derive from name in Go. */}}
{{- define "asservat.hubApi.config" -}}
{{- $h := index .Values.hub "hub-api" -}}
{{- $c := fromJson (include "asservat.providers" .) -}}
{{- $_ := set $c "format" "asservat-hub-api-config/v1" -}}
{{- $_ := set $c "name" (include "asservat.name" .) -}}
{{- $_ := set $c "namespace" .Release.Namespace -}}
{{- $_ := set $c "connections" (int $h.connections) -}}
{{- $_ := set $c "concurrency" (int $h.concurrency) -}}
{{- $obs := dict -}}
{{- with $h.peers }}{{ $_ := set $obs "peers" . }}{{ end -}}
{{- with .Values.capacity -}}
{{- $lc := dict "keys" (sortAlpha (required "capacity.namespaceKeys is required" .namespaceKeys)) -}}
{{- with .workloadKeys -}}
{{- with .labels }}{{ $_ := set $lc "labelKeys" . }}{{ end -}}
{{- with .annotations }}{{ $_ := set $lc "annotationKeys" . }}{{ end -}}
{{- end -}}
{{- $_ := set $obs "localCapacity" $lc -}}
{{- end -}}
{{- $_ := set $c "observation" $obs -}}
{{- $_ := set $c "native" (dict "workerNamespaces" (include "asservat.hubApi.workerNamespaces" . | fromJsonArray) "retentionTopologies" (default list $h.retentionTopologies)) -}}
{{- if .Values.origin -}}
{{- $u := $h.public -}}
{{- $id := fromJson (include "asservat.hubApi.identity" .) -}}
{{- $pub := dict "origin" .Values.origin "browserAudience" $id.browserAudience "version" (.Chart.AppVersion | default .Chart.Version) -}}
{{- range $key := list "standby" "captures" "previewSeconds" "operationConcurrency" "mcpPerIdentity" "downloadConcurrency" "downloadsPerIdentity" "downloadMaxSeconds" "operationAudit" "downloadPlan" -}}
{{- $_ := set $pub $key (index $u $key) -}}
{{- end -}}
{{- if or $u.processing .Values.capacity }}{{ $_ := set $pub "processing" true }}{{ end -}}
{{- with .Values.captureHistory }}{{ $_ := set $pub "captureHistory" . }}{{ end -}}
{{- if eq .Values.exposure.tls.mode "proxy" }}{{ $_ := set $pub "proxyTLS" true }}{{ end -}}
{{- if or .Values.fleet.issuer (include "asservat.hubApi.offer" .) -}}
{{- $profiles := include "asservat.hubApi.deliveryProfiles" . | fromJsonArray -}}
{{- if not $profiles }}{{ fail "fleet.deliveryProfiles needs at least one profile when fleet.issuer is set" }}{{ end -}}
{{- $_ := set $pub "fleet" (dict "deliveryProfile" (first $profiles)) -}}
{{- end -}}
{{- if include "asservat.hubApi.offer" . -}}
{{- $fed := include "asservat.fullname" (list . "federation") -}}
{{- $connector := required "mode=combined and clusters require federation.connector (the regional offer's connector limits)" (dig "connector" nil (default dict .Values.federation)) -}}
{{- $backup := required "mode=combined and clusters require capacity.backup (the regional offer's backup profile)" (dig "backup" nil (default dict .Values.capacity)) -}}
{{- $connectors := len (default list .Values.clusters) -}}
{{- if include "asservat.hubApi.combined" . }}{{ $connectors = add1 $connectors }}{{ end -}}
{{- if lt (int64 $connector.profiles) (int64 $connectors) }}{{ fail (printf "federation.connector.profiles must cover every connector (%d: the combined-mode one plus clusters); it is fixed at the first install" $connectors) }}{{ end -}}
{{- $offer := dict "federation" (printf "https://%s.%s.svc:9446" $fed .Release.Namespace) "serverName" (printf "%s.%s.svc" $fed .Release.Namespace) "image" (include "asservat.image" .) "connector" $connector "backup" $backup -}}
{{- if not (include "asservat.hubApi.combined" .) }}{{ $_ := set $offer "hubOnly" true }}{{ end -}}
{{- if .Values.clusters -}}
{{- $r := .Values.remote -}}
{{- $_ := set $offer "remote" (dict "federation" (required "clusters require remote.federation" $r.federation) "owners" (required "clusters require remote.owners" $r.owners) "keyService" (required "clusters require remote.keyService" $r.keyService) "objectStore" (required "clusters require remote.objectStore" $r.objectStore)) -}}
{{- end -}}
{{- $_ := set $pub "regionalOffer" $offer -}}
{{- end -}}
{{- $_ := set $c "public" $pub -}}
{{- end -}}
{{- with include "asservat.hubApi.clusters" . | fromJsonArray -}}
{{- if not $.Values.origin }}{{ fail "clusters require origin (the hub-api issues their bootstraps)" }}{{ end -}}
{{- $_ := set $c "clusters" . -}}
{{- end -}}
{{- toJson $c -}}
{{- end -}}

{{/* The empty download-worker control catalog (contracts.OwnerWorkerTrust). */}}
{{- define "asservat.hubApi.workerControls" -}}
{{- toJson (dict "format" "asservat-owner-worker-trust/v1" "controls" list) -}}
{{- end -}}

{{/* browser.json (contracts.BrowserSettings): rootID and sessionEpoch come
     from the <name>-ids Secret in the reader. */}}
{{- define "asservat.hubApi.browserSettings" -}}
{{- $i := .Values.identity -}}
{{- $id := fromJson (include "asservat.hubApi.identity" .) -}}
{{- toJson (dict "schemaVersion" "browser-settings/v1" "revision" (int .Release.Revision) "issuer" (required "identity.issuer is required" $id.issuer) "clientID" (required "identity.clientID is required" $id.clientID) "origin" .Values.origin "suspended" false
  "maxLifetimeSeconds" (int $i.maxLifetimeSeconds) "maxLogins" (int $i.maxLogins) "maxSessions" (int $i.maxSessions) "maxLogoutEvents" (int $i.maxLogoutEvents)) -}}
{{- end -}}

{{/* identity.json (contracts.IdentitySettings). Without identity.clients the
     console client is the one human client. */}}
{{- define "asservat.hubApi.identitySettings" -}}
{{- $i := .Values.identity -}}
{{- $id := fromJson (include "asservat.hubApi.identity" .) -}}
{{- if and (empty $i.eligibleSubjects) (empty $i.eligibleGroups) (ne .Values.services.identity.provider "keycloak") }}{{ fail "identity.eligibleSubjects or identity.eligibleGroups is required when origin is set" }}{{ end -}}
{{- $clients := default (list (dict "id" $id.clientID "kind" "human" "classQualified" true)) $i.clients -}}
{{- $out := dict "schemaVersion" "identity-settings/v1" "revision" (int .Release.Revision) "issuer" $id.issuer "clients" $clients "eligibleSubjects" (default list $i.eligibleSubjects) "eligibleGroups" (default list $i.eligibleGroups) "groupsAtIssueQualified" true "groupMaxAgeSeconds" (int $i.groupMaxAgeSeconds) -}}
{{- with $i.approvals }}{{ $_ := set $out "approvals" . }}{{ end -}}
{{- toJson $out -}}
{{- end -}}

{{/* download-environment.json (contracts.DownloadEnvironmentSettings), also
     the capacity processing source (ADR-192). rootID, installationID and
     recoveryEpoch come from the <name>-ids Secret in the reader. With
     download workers the hub-local region is permitted and every human
     client may download context captures of the baseline's purpose over
     every installed path (installedPaths). */}}
{{- define "asservat.hubApi.downloadEnvironment" -}}
{{- $i := .Values.identity -}}
{{- $id := fromJson (include "asservat.hubApi.identity" .) -}}
{{- $p := fromJson (include "asservat.providers" .) -}}
{{- $regions := list -}}
{{- $clients := list -}}
{{- if include "asservat.hubApi.workerNamespaces" . | fromJsonArray -}}
{{- $regions = list $p.objectStore.region -}}
{{- with .Values.retention.purposeRef -}}
{{- $purpose := . -}}
{{- range (default (list (dict "id" $id.clientID "kind" "human")) $i.clients) -}}
{{- if eq .kind "human" -}}
{{- $clients = append $clients (dict "issuer" $id.issuer "id" .id "kind" .kind "dataClasses" (list "metadata" "extract" "raw") "privacyClasses" (list "potentialPersonalData") "evidenceTypes" (list "context" "packetCapture" "syscallTrace" "profile" "logs") "purposes" (list $purpose) "pathIDs" list "installedPaths" true) -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- if not $i.processingOperators }}{{ fail "identity.processingOperators needs at least one stable operator identity (the download environment refuses an empty list)" }}{{ end -}}
{{- $out := dict "format" "asservat-download-environment/v1" "revision" (int .Release.Revision) "suspended" false "permittedRegions" $regions "paths" list "clients" $clients "operators" (default list $i.processingOperators) -}}
{{- /* With download workers the paths are the readers' installed (derived)
     paths: Helm does not know their generated fields. */ -}}
{{- if $regions }}{{ $_ := set $out "installedPaths" true }}{{ end -}}
{{- if hasKey .Values "processors" }}{{ $_ := set $out "processors" (default list .Values.processors) }}{{ end -}}
{{- toJson $out -}}
{{- end -}}
