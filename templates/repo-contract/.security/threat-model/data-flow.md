# Data flows: Claims API

> Each flow ID (DF-nn) and trust boundary (TB-nn) is defined in `assets.yaml`, and threats reference them.
> Trust boundaries are Mermaid subgraphs. Update this diagram in the same PR as any change that adds a
> flow, store or boundary, and label that PR `architecture-change` (this invalidates the threat-model review: ASC-TM-02).

```mermaid
flowchart LR
  subgraph TB01[TB-01 Internet]
    customer([Customer browser])
  end
  subgraph TB02[TB-02 Azure app environment]
    api[Claims API]
    scan[Malware scan function]
  end
  subgraph TB03[TB-03 Data tier - private endpoints]
    db[(claims-db)]
    blob[(documents)]
  end
  subgraph TB04[TB-04 Third parties]
    notify[Email service]
  end
  customer -- "DF-01 claim + PII (HTTPS, OIDC token)" --> api
  customer -- "DF-02 document upload" --> api
  api -- "DF-03 claim records" --> db
  api -- "DF-04 documents" --> blob
  blob -- "DF-05 blob event" --> scan
  api -- "DF-06 email address, claim ref" --> notify
```
