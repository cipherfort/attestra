# ADR-024: Event and queue architecture

**Status:** Proposed (2026-10-07)  ·  **Related:** ADR-008, ADR-025

## Context

Work is asynchronous: webhook processing, artifact download and verification, connector syncs, control re-evaluation, risk re-scoring, ticket sync, SIEM events, scheduled sweeps. Expected volume is modest (design peak tens of jobs/second, typical < 5/s). Many jobs must be **transactionally consistent** with DB writes (e.g. "evidence inserted ⇒ re-evaluate controls").

## Decision

- **PostgreSQL-backed job queue** (`jobs` table) claimed with `SELECT … FOR UPDATE SKIP LOCKED`, plus a **transactional outbox** (`outbox` table) written in the same transaction as domain changes. A dispatcher turns outbox rows into jobs or external deliveries.
- **At-least-once** delivery. **Every handler is idempotent** (dedup keys, unique constraints, upserts on projections).
- Retries with exponential backoff and jitter. `max_attempts` per queue. Then `dead` status with an alert and a replay tool.
- Named queues by workload (`ingest`, `github-sync`, `evaluate`, `risk`, `tickets`, `siem`, `scheduler`) so one noisy queue cannot starve another. Worker replicas are scaled per queue via the **KEDA PostgreSQL scaler** (supported by Container Apps scale rules).
- A thin `Queue` interface in code, so **Azure Service Bus** can replace the PG queue without touching handlers.
- **Revisit trigger:** sustained > 50 jobs/s, or a need for multi-consumer fan-out to systems outside the platform.

## Alternatives considered

| Option | Why not (now) |
|---|---|
| Azure Service Bus | Excellent managed broker. But still needs an outbox for DB consistency, adds a component, identity and network path, and the volume doesn't need it. **The designated upgrade path.** |
| Redis + Celery (as DefectDojo uses) | Weaker durability. The infra repo already hit Azure Managed Redis clustering quirks. Another stateful service. |
| Kafka / Event Hubs | Built for streaming at scales far beyond ours. Operationally heavy. |

## Decision drivers

Transactional consistency · fewest moving parts · durability · replaceability.

## Consequences

The DB carries queue load (small). Vacuum tuning on `jobs`. Completed jobs are purged after 30 days.

## Security implications

Job payloads contain identifiers, not secrets or raw artefacts. Raw artefacts stay in blob storage and are referenced by digest.

## Operational implications

Dead-letter monitoring. Queue-depth and age SLO alerts (ADR-027). A replay CLI.
