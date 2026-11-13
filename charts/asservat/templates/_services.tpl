{{/*
Federation, key service and publisher helpers. Everything shared (names,
labels, image, Secrets, providers, CAs, schema wait, security contexts) is in
_helpers.tpl.
*/}}

{{/*
Serving TLS Secret name of a peer listener (kubernetes.io/tls with ca.crt);
call with (list $ "federation"|"key-service"). Order: tls.existingSecret,
then a cert-manager Certificate (tls.issuerRef.name), else the secrets hook's
generated CA and certificate.
*/}}
{{- define "asservat.svc.tlsSecret" -}}
{{- $root := index . 0 -}}
{{- $tls := default dict (index $root.Values.hub (index . 1)).tls -}}
{{- default (printf "%s-tls" (include "asservat.fullname" .)) $tls.existingSecret -}}
{{- end -}}

{{/*
The serving TLS objects of a peer listener; call with (list $ "component").
Without existingSecret: a cert-manager Certificate when tls.issuerRef.name is
set, else nothing: the `secrets` hook creates `<name>-<component>-tls` once
(asservat.svc.servingTLS) with its own CA, never rotated.
*/}}
{{- define "asservat.svc.tlsObjects" -}}
{{- $root := index . 0 -}}
{{- $component := index . 1 -}}
{{- $tls := default dict (index $root.Values.hub $component).tls -}}
{{- $svc := include "asservat.fullname" . -}}
{{- $ns := $root.Release.Namespace -}}
{{- $secret := printf "%s-tls" $svc -}}
{{- $dns := concat (list $svc (printf "%s.%s" $svc $ns) (printf "%s.%s.svc" $svc $ns) (printf "%s.%s.svc.cluster.local" $svc $ns)) (default list $tls.dnsNames) -}}
{{- $issuer := default dict $tls.issuerRef -}}
{{- if $tls.existingSecret -}}
{{- else if $issuer.name }}
---
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: {{ $svc }}
  namespace: {{ $ns }}
  labels: {{- include "asservat.labels" . | trim | nindent 4 }}
spec:
  secretName: {{ $secret }}
  duration: 2160h
  renewBefore: 360h
  privateKey: {algorithm: ECDSA, size: 256, rotationPolicy: Always}
  usages: [server auth]
  dnsNames: {{- toYaml $dns | nindent 4 }}
  issuerRef:
    name: {{ $issuer.name | quote }}
    kind: {{ default "Issuer" $issuer.kind | quote }}
    group: {{ default "cert-manager.io" $issuer.group | quote }}
{{- end }}
{{- end -}}

{{/* Peer Service; call with (list $ "component" port). */}}
{{- define "asservat.svc.service" -}}
{{- $root := index . 0 -}}
{{- $component := index . 1 -}}
{{- $s := default dict (index $root.Values.hub $component).service -}}
{{- $type := default "ClusterIP" $s.type -}}
{{- if not (has $type (list "ClusterIP" "NodePort" "LoadBalancer")) -}}
{{- fail (printf "hub.%s.service.type must be ClusterIP, NodePort or LoadBalancer" $component) -}}
{{- end }}
apiVersion: v1
kind: Service
metadata:
  name: {{ include "asservat.fullname" (list $root $component) }}
  namespace: {{ $root.Release.Namespace }}
  labels: {{- include "asservat.labels" (list $root $component) | trim | nindent 4 }}
  {{- with $s.annotations }}
  annotations: {{- toYaml . | nindent 4 }}
  {{- end }}
spec:
  type: {{ $type }}
  selector: {{- include "asservat.selectorLabels" (list $root $component) | trim | nindent 4 }}
  ports:
    - name: {{ $component }}
      port: {{ index . 2 }}
      targetPort: {{ $component }}
      protocol: TCP
      {{- if and (ne $type "ClusterIP") $s.nodePort }}
      nodePort: {{ $s.nodePort }}
      {{- end }}
{{- end -}}

{{/*
ServiceAccount, the namespace UID read (field class N) and an optional
namespaced Role with the given rules; call with (list $ "component" rules).
*/}}
{{- define "asservat.svc.account" -}}
{{- $root := index . 0 -}}
{{- $component := index . 1 -}}
{{- $full := include "asservat.fullname" (list $root $component) -}}
{{- $cluster := printf "%s-%s-namespace" $root.Release.Namespace $full -}}
apiVersion: v1
kind: ServiceAccount
metadata:
  name: {{ $full }}
  namespace: {{ $root.Release.Namespace }}
  labels: {{- include "asservat.labels" (list $root $component) | trim | nindent 4 }}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: {{ $cluster }}
  labels: {{- include "asservat.labels" (list $root $component) | trim | nindent 4 }}
rules:
  - apiGroups: [""]
    resources: [namespaces]
    resourceNames: [{{ $root.Release.Namespace | quote }}]
    verbs: [get]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: {{ $cluster }}
  labels: {{- include "asservat.labels" (list $root $component) | trim | nindent 4 }}
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: ClusterRole, name: {{ $cluster }}}
subjects: [{kind: ServiceAccount, name: {{ $full }}, namespace: {{ $root.Release.Namespace }}}]
{{- with index . 2 }}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: {{ $full }}
  namespace: {{ $root.Release.Namespace }}
  labels: {{- include "asservat.labels" (list $root $component) | trim | nindent 4 }}
rules: {{- toYaml . | nindent 2 }}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: {{ $full }}
  namespace: {{ $root.Release.Namespace }}
  labels: {{- include "asservat.labels" (list $root $component) | trim | nindent 4 }}
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: Role, name: {{ $full }}}
subjects: [{kind: ServiceAccount, name: {{ $full }}, namespace: {{ $root.Release.Namespace }}}]
{{- end }}
{{- end -}}

{{/* The component's SQL Secret, each sql-<purpose>.json at its own name;
     call with (list $ "component" purposes). */}}
{{- define "asservat.svc.sql" -}}
{{- $root := index . 0 -}}
- secret:
    name: {{ include "asservat.secretName" (list $root (printf "sql-%s" (index . 1))) | quote }}
    items:
      {{- range index . 2 }}
      - {key: {{ printf "sql-%s.json" . }}, path: {{ printf "sql-%s.json" . }}}
      {{- end }}
{{- end -}}

{{/* One object-store credential: (list $ "principal" "path"). */}}
{{- define "asservat.svc.s3" -}}
- secret:
    name: {{ include "asservat.secretName" (list (index . 0) (printf "s3-%s" (index . 1))) | quote }}
    items: [{key: credentials.json, path: {{ index . 2 | quote }}}]
{{- end -}}

{{/* The `<name>-audit-mac` keys, one file each. */}}
{{- define "asservat.svc.auditMAC" -}}
- secret:
    name: {{ include "asservat.secretName" (list . "audit-mac") | quote }}
    items:
      {{- range list "inputVersion" "inputKey" "accountVersion" "accountKey" }}
      - {key: {{ . }}, path: {{ . }}}
      {{- end }}
{{- end -}}

{{/*
The Deployment of one service; call with (dict "root" $ "component" c
"command" "hub-federation" "dir" "/run/asservat/federation" "port" 9446|0
"config" configJSON "sources" projectedSourcesYAML "grace" seconds
"sqlFile" "sql-x.json").
*/}}
{{- define "asservat.svc.deployment" -}}
{{- $root := .root -}}
{{- $c := .component -}}
{{- $v := default dict (index $root.Values.hub $c) -}}
{{- $inputs := list (dict "name" "inputs" "mountPath" .dir "readOnly" true) -}}
apiVersion: v1
kind: ConfigMap
metadata:
  name: {{ printf "%s-config" (include "asservat.fullname" (list $root $c)) }}
  namespace: {{ $root.Release.Namespace }}
  labels: {{- include "asservat.labels" (list $root $c) | trim | nindent 4 }}
data:
  config.json: {{ .config | quote }}
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{ include "asservat.fullname" (list $root $c) }}
  namespace: {{ $root.Release.Namespace }}
  labels: {{- include "asservat.labels" (list $root $c) | trim | nindent 4 }}
spec:
  replicas: {{ default 1 $v.replicas }}
  revisionHistoryLimit: 2
  strategy: {type: Recreate}
  selector:
    matchLabels: {{- include "asservat.selectorLabels" (list $root $c) | trim | nindent 6 }}
  template:
    metadata:
      labels: {{- include "asservat.labels" (list $root $c) | trim | nindent 8 }}
      annotations:
        checksum/config: {{ sha256sum .config | quote }}
    spec:
      serviceAccountName: {{ include "asservat.fullname" (list $root $c) }}
      # The in-cluster API token reads names under the Roles above.
      automountServiceAccountToken: true
      enableServiceLinks: false
      terminationGracePeriodSeconds: {{ .grace }}
      securityContext: {{- include "asservat.podSecurityContext" $root | nindent 8 }}
      {{- include "asservat.imagePullSecrets" $root | nindent 6 }}
      {{- include "asservat.placement" (list $root $c) | nindent 6 }}
      initContainers:
        {{- include "asservat.waitSchema" (dict "root" $root "config" (printf "%s/config.json" .dir) "credential" (printf "%s/%s" .dir .sqlFile) "ca" (printf "%s/postgres-ca.crt" .dir) "volumeMounts" $inputs) | nindent 8 }}
      containers:
        - name: {{ $c }}
          image: {{ include "asservat.image" $root | quote }}
          imagePullPolicy: {{ $root.Values.image.pullPolicy }}
          command: [/asservat, {{ .command }}]
          {{- if .port }}
          ports: [{name: {{ $c }}, containerPort: {{ .port }}, protocol: TCP}]
          {{- end }}
          securityContext: {{- include "asservat.securityContext" $root | nindent 12 }}
          resources: {{- include "asservat.resources" (list $root $c) | nindent 12 }}
          volumeMounts:
            - {name: inputs, mountPath: {{ .dir }}, readOnly: true}
            {{- include "asservat.idsMount" $root | nindent 12 }}
      volumes:
        - name: inputs
          projected:
            defaultMode: 0440
            sources:
              - configMap:
                  name: {{ printf "%s-config" (include "asservat.fullname" (list $root $c)) }}
                  items: [{key: config.json, path: config.json}]
              {{- .sources | nindent 14 }}
        {{- include "asservat.idsVolume" $root | nindent 8 }}
{{- end -}}

{{/* Serving TLS Secrets the secrets hook generates (no existingSecret and no
     issuerRef) as JSON [{secret, dnsNames}]. */}}
{{- define "asservat.svc.servingTLS" -}}
{{- $root := . -}}
{{- $out := list -}}
{{- range $component := list "federation" "key-service" -}}
{{- $tls := default dict (index $root.Values.hub $component).tls -}}
{{- if and (not $tls.existingSecret) (not (dig "issuerRef" "name" "" $tls)) -}}
{{- $svc := include "asservat.fullname" (list $root $component) -}}
{{- $ns := $root.Release.Namespace -}}
{{- $dns := concat (list $svc (printf "%s.%s" $svc $ns) (printf "%s.%s.svc" $svc $ns) (printf "%s.%s.svc.cluster.local" $svc $ns)) (default list $tls.dnsNames) -}}
{{- $out = append $out (dict "secret" (printf "%s-tls" $svc) "dnsNames" $dns) -}}
{{- end -}}
{{- end -}}
{{- toJson $out -}}
{{- end -}}
