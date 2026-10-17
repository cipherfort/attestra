# SPDX-License-Identifier: Apache-2.0
"""Application onboarding (M2): register an application from its repository contract through the API.

* `application_classifications.requested_by`: who asked for the classification, so the decision can enforce
  segregation of duties (the requester never approves it).
* The API may create the repository record and its link (registration), and enqueue jobs (the onboarding job;
  evidence is still written only by the worker: the API cannot forge evidence, schema test T9).

Revision ID: 0006_onboarding
"""

from alembic import op

revision = "0006_onboarding"
down_revision = "0005_process_logins"

SQL = """
SET search_path = aap, public;
ALTER TABLE application_classifications ADD COLUMN IF NOT EXISTS requested_by uuid REFERENCES users(id);
GRANT INSERT ON repositories, application_repositories TO aap_api;
GRANT UPDATE (full_name, head_sha, detected, updated_at) ON repositories TO aap_api;
GRANT INSERT ON jobs TO aap_api;
"""


def upgrade() -> None:
    op.get_bind().connection.driver_connection.execute(SQL)


def downgrade() -> None:
    raise RuntimeError("forward-only")
