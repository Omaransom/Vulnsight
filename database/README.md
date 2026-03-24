# Database folder

**What goes here**

- **`schema.sql`** — Human-readable reference for the SQLite schema (same shapes as `src/db/repository.py` and `src/db/auth_repository.py`).
- **`vulnsight.db`** — The actual SQLite file when you run the app (created automatically; `*.db` is gitignored).

**What does *not* go here**

- Application logic belongs under **`src/`** (`src/db` for persistence, `src/api` for HTTP, etc.).
- There is nothing extra you must “run” in this folder for the product to work: starting the API creates/opens the DB and tables.

**Teammate experiments** (PCAP ingest, extra dashboards, alternate ML) should live in **`src/`** if they become part of the product, or a separate **`scripts/`** folder if they stay one-off tools—not mixed into this folder as a second app.
