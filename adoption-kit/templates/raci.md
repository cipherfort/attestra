# RACI — {{ORGANIZATION}}

R responsible, A accountable, C consulted, I informed. One A per row. Replace the role names with yours; keep the
separation in rows marked *: the platform enforces it, so the people must exist.

| Activity | {{SPONSOR}} | {{APPSEC_LEAD}} | AppSec engineers | {{PLATFORM_OWNER}} | Unit leads | Champions | Engineering teams |
|---|---|---|---|---|---|---|---|
| Set and change the rules (controls, tiers, risk model) | A | R | C | C | C | I | I |
| Run and upgrade the platform | I | C | I | A/R | I | I | I |
| Approve the shipped pipelines' releases (trusted producers) | I | A | R | C | I | I | I |
| Register an application | I | I | C | I | A | R | C |
| Approve a Tier 1/2 classification * | I | A | R | I | C | C | I |
| Triage and fix findings | I | I | C | I | A | R | R |
| Confirm a false positive * | I | A | R | I | I | C | C |
| Approve an exception * | I | A | R (per policy) | I | R (per policy) | C | C |
| Independent assessment (M2) * | I | A | R | I | I | C | C |
| Grant platform roles * | I | C | I | A/R | C | I | I |
| Report to {{STEERING_GROUP}} | A | R | C | C | C | I | I |

\* The requester never approves their own request; independent work is done outside the owning team.
