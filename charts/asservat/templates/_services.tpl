{{/*
Helm-native federation, key service and publisher helpers. Provider names
(mounts, keys, roles, audiences) are chart constants that the `setup` Job
reads back from the rendered component ConfigMaps.
*/}}

{{- define "asservat.svc.name" -}}
{{- $i := default dict .Values.installation -}}
{{- default "asservat" $i.name -}}
{{- end -}}

{{- define "asservat.svc.image" -}}
{{- $i := default dict .Values.image -}}
{{- if not (regexMatch "^[a-z0-9][a-z0-9./:_-]{0,255}$" (default "" $i.repository)) -}}
{{- fail "image.repository is required for Helm-rendered Asservat services" -}}
{{- end -}}
{{- if not (regexMatch "^sha256:[a-f0-9]{64}$" (default "" $i.digest)) -}}
{{- fail "image.digest must be sha256:<64 hex>" -}}
{{- end -}}
{{- printf "%s@%s" $i.repository $i.digest -}}
{{- end -}}

{{- define "asservat.svc.labels" -}}
app.kubernetes.io/name: asservat
app.kubernetes.io/instance: {{ .root.Release.Name | quote }}
app.kubernetes.io/managed-by: {{ .root.Release.Service | quote }}
app.kubernetes.io/part-of: asservat
app.kubernetes.io/component: {{ .component }}
{{- end -}}

{{- define "asservat.svc.selector" -}}
app.kubernetes.io/instance: {{ .root.Release.Name | quote }}
app.kubernetes.io/component: {{ .component }}
{{- end -}}

{{/* secretName: dict root, key (secrets.<key>), default. */}}
{{- define "asservat.svc.secret" -}}
{{- default .default (dig .key "existingSecret" "" (default dict .root.Values.secrets)) -}}
{{- end -}}

{{/*
Providers each component dials: bundled services in the release namespace or
services.<provider>.external. caSecret holds the PEM CA at key ca.crt.
*/}}
{{- define "asservat.svc.providers" -}}
{{- $name := include "asservat.svc.name" . -}}
{{- $ns := .Release.Namespace -}}
{{- $s := default dict .Values.services -}}
{{- $out := dict -}}
{{- if eq (dig "postgres" "provider" "external" $s) "bundled" -}}
{{- $_ := set $out "postgres" (dict "host" (printf "%s-postgres.%s.svc" $name $ns) "port" 5432 "database" "asservat" "caSecret" (printf "%s-postgres-state" $name)) -}}
{{- else -}}
{{- $e := dig "postgres" "external" dict $s -}}
{{- $_ := set $out "postgres" (dict "host" (default "" $e.host) "port" (default 5432 $e.port | int) "database" (default "asservat" $e.database) "caSecret" (default "" $e.caSecret)) -}}
{{- end -}}
{{- if eq (dig "objectStore" "provider" "external" $s) "seaweedfs" -}}
{{- $_ := set $out "objectStore" (dict "endpoint" (printf "https://%s-objectstore.%s.svc:8333" $name $ns) "region" "us-east-1" "auditBucket" "asservat-audit" "evidenceBucket" "asservat-evidence" "caSecret" (printf "%s-objectstore-state" $name)) -}}
{{- else -}}
{{- $e := dig "objectStore" "external" dict $s -}}
{{- $_ := set $out "objectStore" (dict "endpoint" (default "" $e.endpoint) "region" (default "us-east-1" $e.region) "auditBucket" (default "asservat-audit" $e.auditBucket) "evidenceBucket" (default "asservat-evidence" $e.evidenceBucket) "caSecret" (default "" $e.caSecret)) -}}
{{- end -}}
{{- if eq (dig "keyService" "provider" "external" $s) "openbao" -}}
{{- $_ := set $out "openBao" (dict "endpoint" (printf "https://%s-openbao.%s.svc:8200" $name $ns) "caSecret" (printf "%s-openbao-state" $name)) -}}
{{- else -}}
{{- $e := dig "keyService" "external" dict $s -}}
{{- $_ := set $out "openBao" (dict "endpoint" (default "" $e.endpoint) "caSecret" (default "" $e.caSecret)) -}}
{{- end -}}
{{- range $k, $v := $out -}}
{{- if not $v.caSecret -}}{{- fail (printf "services.%s.external.caSecret is required" $k) -}}{{- end -}}
{{- end -}}
{{- toJson $out -}}
{{- end -}}

{{/* Chart constants shared with setup. */}}
{{- define "asservat.svc.constants" -}}
{{- $name := include "asservat.svc.name" . -}}
{{- $ns := .Release.Namespace -}}
{{- toJson (dict
  "authMount" "asservat-kubernetes"
  "auditMount" "asservat-audit"
  "connectorPKIMount" "connector-pki"
  "workerPKIMount" "worker-pki"
  "keyID" (printf "%s-artifact" $name)
  "federationAuditKey" (printf "%s-federation-audit" $name)
  "publisherAuditKey" (printf "%s-publisher-audit" $name)
  "connectorClientRole" (printf "%s-connector-client" $name)
  "connectorServerRole" (printf "%s-connector-server" $name)
  "verifierRole" (printf "%s-verifier" $name)
  "ownerConfiguration" (printf "%s-owner-source" $name)
  "clusterCatalog" (printf "%s-cluster-catalog" $name)
  "workerConfiguration" (printf "%s-worker-configuration" $name)
  "federationAudience" (printf "asservat:%s:%s:federation-provider" $ns $name)
  "publisherAudience" (printf "asservat:%s:%s:publisher-provider" $ns $name)
) -}}
{{- end -}}

{{/* CA bundle projection: dict secret, path. */}}
{{- define "asservat.svc.caSource" -}}
- secret:
    name: {{ .secret | quote }}
    optional: false
    items: [{key: ca.crt, path: {{ .path }}}]
{{- end -}}

{{/* The generated installation IDs. */}}
{{- define "asservat.svc.idsVolume" -}}
- name: ids
  secret:
    secretName: {{ include "asservat.svc.secret" (dict "root" . "key" "ids" "default" (printf "%s-ids" (include "asservat.svc.name" .))) | quote }}
    defaultMode: 0440
    items:
      {{- range list "installationID" "clusterID" "permissionRootID" "issuerEpoch" }}
      - {key: {{ . }}, path: {{ . }}}
      {{- end }}
{{- end -}}

{{/*
Minimal schema wait (the chart stream's helper replaces it): runs
`asservat schema-wait` with the component's inputs until setup reports the
compiled schema version.
*/}}
{{- define "asservat.svc.schemaWait" -}}
- name: schema-wait
  image: {{ include "asservat.svc.image" .root | quote }}
  imagePullPolicy: {{ dig "pullPolicy" "IfNotPresent" (default dict .root.Values.image) }}
  command: [/asservat, schema-wait, {{ .root_dir }}]
  securityContext: {{ include "asservat.svc.containerSecurity" . | nindent 4 }}
  resources:
    requests: {cpu: 10m, memory: 32Mi}
    limits: {cpu: 100m, memory: 64Mi}
  volumeMounts:
    - {name: inputs, mountPath: {{ .root_dir }}, readOnly: true}
    - {name: ids, mountPath: /run/asservat/ids, readOnly: true}
{{- end -}}

{{- define "asservat.svc.containerSecurity" -}}
allowPrivilegeEscalation: false
readOnlyRootFilesystem: true
capabilities: {drop: [ALL]}
{{- end -}}

{{- define "asservat.svc.podSecurity" -}}
runAsNonRoot: true
runAsUser: 65532
runAsGroup: 65532
fsGroup: 65532
seccompProfile: {type: RuntimeDefault}
{{- end -}}

{{/* Pod scheduling: hub.<component> nodeSelector, tolerations. */}}
{{- define "asservat.svc.scheduling" -}}
{{- with .nodeSelector }}
nodeSelector: {{ toYaml . | nindent 2 }}
{{- end }}
{{- with .tolerations }}
tolerations: {{ toYaml . | nindent 2 }}
{{- end }}
{{- end -}}

{{/*
Serving TLS for a peer listener: a cert-manager Certificate when
federation.tls.issuerRef is set, else the listener's existingSecret.
dict root, component, values (hub.<component>), port.
*/}}
{{- define "asservat.svc.tlsSecret" -}}
{{- $name := include "asservat.svc.name" .root -}}
{{- $tls := default dict .values.tls -}}
{{- $issuer := dig "tls" "issuerRef" "name" "" (default dict .root.Values.federation) -}}
{{- if $tls.existingSecret -}}
{{- $tls.existingSecret -}}
{{- else if $issuer -}}
{{- printf "%s-%s-tls" $name .component -}}
{{- else -}}
{{- fail (printf "hub.%s.tls.existingSecret or federation.tls.issuerRef is required" .key) -}}
{{- end -}}
{{- end -}}

{{- define "asservat.svc.certificate" -}}
{{- $name := include "asservat.svc.name" .root -}}
{{- $tls := default dict .values.tls -}}
{{- $issuer := dig "tls" "issuerRef" dict (default dict .root.Values.federation) -}}
{{- if and (not $tls.existingSecret) $issuer.name }}
{{- $svc := printf "%s-%s" $name .component }}
---
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: {{ $svc }}
  namespace: {{ .root.Release.Namespace }}
  labels: {{ include "asservat.svc.labels" (dict "root" .root "component" .component) | nindent 4 }}
spec:
  secretName: {{ printf "%s-tls" $svc }}
  duration: 2160h
  renewBefore: 360h
  privateKey: {algorithm: ECDSA, size: 256, rotationPolicy: Always}
  usages: [server auth]
  dnsNames:
    - {{ $svc }}
    - {{ printf "%s.%s.svc" $svc .root.Release.Namespace }}
    - {{ printf "%s.%s.svc.cluster.local" $svc .root.Release.Namespace }}
    {{- range (default list $tls.dnsNames) }}
    - {{ . | quote }}
    {{- end }}
  issuerRef:
    name: {{ $issuer.name | quote }}
    kind: {{ default "Issuer" $issuer.kind | quote }}
    group: {{ default "cert-manager.io" $issuer.group | quote }}
{{- end }}
{{- end -}}

{{/* Peer Service: dict root, component, values, port. */}}
{{- define "asservat.svc.service" -}}
{{- $name := include "asservat.svc.name" .root -}}
{{- $svc := default dict .values.service -}}
{{- $type := default "ClusterIP" $svc.type -}}
{{- if not (has $type (list "ClusterIP" "NodePort" "LoadBalancer")) -}}
{{- fail (printf "hub.%s.service.type must be ClusterIP, NodePort or LoadBalancer" .key) -}}
{{- end }}
apiVersion: v1
kind: Service
metadata:
  name: {{ printf "%s-%s" $name .component }}
  namespace: {{ .root.Release.Namespace }}
  labels: {{ include "asservat.svc.labels" (dict "root" .root "component" .component) | nindent 4 }}
  {{- with $svc.annotations }}
  annotations: {{ toYaml . | nindent 4 }}
  {{- end }}
spec:
  type: {{ $type }}
  {{- if and (ne $type "ClusterIP") $svc.externalTrafficPolicy }}
  externalTrafficPolicy: {{ $svc.externalTrafficPolicy }}
  {{- end }}
  {{- if and (eq $type "LoadBalancer") $svc.loadBalancerSourceRanges }}
  loadBalancerSourceRanges: {{ toYaml $svc.loadBalancerSourceRanges | nindent 4 }}
  {{- end }}
  selector: {{ include "asservat.svc.selector" (dict "root" .root "component" .component) | nindent 4 }}
  ports:
    - name: {{ .component }}
      port: {{ .port }}
      targetPort: {{ .component }}
      protocol: TCP
      {{- if and (ne $type "ClusterIP") $svc.nodePort }}
      nodePort: {{ $svc.nodePort }}
      {{- end }}
{{- end -}}

{{/* Namespace UID read (field class N) for the three services. */}}
{{- define "asservat.svc.namespaceReader" -}}
{{- $name := include "asservat.svc.name" .root }}
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: {{ printf "%s-%s-%s-namespace" .root.Release.Namespace $name .component }}
  labels: {{ include "asservat.svc.labels" (dict "root" .root "component" .component) | nindent 4 }}
rules:
  - apiGroups: [""]
    resources: [namespaces]
    resourceNames: [{{ .root.Release.Namespace | quote }}]
    verbs: [get]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: {{ printf "%s-%s-%s-namespace" .root.Release.Namespace $name .component }}
  labels: {{ include "asservat.svc.labels" (dict "root" .root "component" .component) | nindent 4 }}
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: {{ printf "%s-%s-%s-namespace" .root.Release.Namespace $name .component }}
subjects:
  - kind: ServiceAccount
    name: {{ printf "%s-%s" $name .component }}
    namespace: {{ .root.Release.Namespace }}
{{- end -}}
