# Install on Kubernetes (Helm)

The supported production path. The chart, its values and the full procedure (verify, credentials, install, upgrade,
rotate, back up) are documented with the chart: [charts/fortproof/README.md](../../charts/fortproof/README.md).

Before you start you need:
- a Kubernetes cluster (1.27 or later) and an ingress controller;
- PostgreSQL 16, managed or operated (CloudNativePG works);
- an evidence bucket with write-once retention: S3 with Object Lock, or Azure Blob with an immutability policy
  ([examples/terraform](../../examples/terraform/README.md) creates either);
- an OpenID Connect identity provider (Entra ID, Okta, Keycloak, ...) with an app registration for the platform.
