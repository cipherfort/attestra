{{/* SPDX-License-Identifier: Apache-2.0 */}}
{{- define "aap.fullname" -}}
{{- if contains .Chart.Name .Release.Name -}}{{ .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else -}}{{ printf "%s-%s" .Release.Name .Chart.Name | trunc 63 | trimSuffix "-" }}{{- end -}}
{{- end -}}
{{- define "aap.labels" -}}
app.kubernetes.io/name: fortproof
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version }}
{{- end -}}
{{- define "aap.selector" -}}
app.kubernetes.io/name: fortproof
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}
{{- define "aap.image" -}}
{{- if .Values.image.digest -}}{{ .Values.image.repository }}@{{ .Values.image.digest }}
{{- else -}}{{ .Values.image.repository }}:{{ .Values.image.tag | default .Chart.AppVersion }}{{- end -}}
{{- end -}}
{{- define "aap.serviceAccount" -}}{{ if .Values.serviceAccount.create }}{{ include "aap.fullname" . }}{{ else }}default{{ end }}{{- end -}}

{{/* Pod spec shared by every process. Call with (dict "ctx" $ "component" "api" "args" (list ...) "ports" ...) */}}
{{- define "aap.podSpec" -}}
{{- $ := .ctx -}}
serviceAccountName: {{ include "aap.serviceAccount" $ }}
automountServiceAccountToken: false
securityContext: {{- toYaml $.Values.podSecurityContext | nindent 2 }}
{{- with $.Values.imagePullSecrets }}
imagePullSecrets: {{- toYaml . | nindent 2 }}
{{- end }}
containers:
  - name: {{ .component }}
    image: {{ include "aap.image" $ }}
    imagePullPolicy: {{ $.Values.image.pullPolicy }}
    args: {{- toYaml .args | nindent 6 }}
    securityContext: {{- toYaml $.Values.securityContext | nindent 6 }}
    env:
      - { name: AAP_CONFIG_FILE, value: /etc/aap/aap.yaml }
      - { name: AAP_SECRETS_BACKEND, value: mounted }
      - { name: AAP_SECRETS_DIR, value: /var/run/secrets/aap }
      - { name: AAP_DATABASE_URL_FILE, value: {{ printf "/var/run/secrets/aap/%s" .dbKey | quote }} }
      - { name: HOME, value: /tmp }
    {{- with .ports }}
    ports: {{- toYaml . | nindent 6 }}
    {{- end }}
    {{- with .probes }}
    {{- toYaml . | nindent 4 }}
    {{- end }}
    resources: {{- toYaml .resources | nindent 6 }}
    volumeMounts:
      - { name: settings, mountPath: /etc/aap, readOnly: true }
      - { name: secrets, mountPath: /var/run/secrets/aap, readOnly: true }
      - { name: tmp, mountPath: /tmp }
volumes:
  - name: settings
    configMap: { name: {{ include "aap.fullname" $ }}-settings }
  - name: secrets
    secret:
      secretName: {{ $.Values.secrets.existingSecret }}
      defaultMode: 0440
      optional: true
      items:
        {{- range (index $.Values.secrets.keys .keys) }}
        - { key: {{ . }}, path: {{ . }} }
        {{- end }}
  - name: tmp
    emptyDir: { sizeLimit: 256Mi }
{{- with $.Values.nodeSelector }}
nodeSelector: {{- toYaml . | nindent 2 }}
{{- end }}
{{- with $.Values.tolerations }}
tolerations: {{- toYaml . | nindent 2 }}
{{- end }}
{{- with $.Values.affinity }}
affinity: {{- toYaml . | nindent 2 }}
{{- end }}
{{- end -}}
