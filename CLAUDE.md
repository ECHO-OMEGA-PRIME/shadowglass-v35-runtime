
## Library-First Protocol (MANDATORY)
<!-- echo-library-first-v1 -->

Before writing ANY function in this repo, call:

  echo.functions.search(q="<intent>")

against the 1M-function corpus in `arcanum_sdk.functions` (FORGE).

If a result ranks > 0.05, READ that source via `echo.functions.source(id=...)` and reuse, extend, or import — do **NOT** rewrite.

**Enforcement:**
- `fs_write` of `.py` without a prior `search` call in this `run_id` will be rejected
- Duplicate-rate audited nightly; flagged builders lose autonomy
- All new functions auto-ingest to the corpus on save (inotify watcher)

**Search examples:**

  echo.functions.search(q="parse pdf", has_docstring=true, limit=10)
  echo.functions.search(q="twilio sms", async_only=true)
  echo.functions.source(id=12345, lines=80)

Full doctrine: `feedback_library_first_protocol.md` in MEMORY.md.
