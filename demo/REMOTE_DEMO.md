# Remote demo: participants run the UI, the proxy runs in AWS

Each participant runs the demo UI and its tools on their own laptop. Every model
call goes to the SecureLiteLLM proxy in AWS (`scripts/aws_dryrun.sh`), which
decides allow / block / hold. The presenter watches every participant's
decisions in CloudWatch.

```
participant laptop                         AWS (allow-listed IPs only)
  browser -> demo UI :8003  --HTTPS-->  load balancer -> proxy -> Bedrock
             demo tools :8002                              |
                                                 decision log -> CloudWatch -> presenter
```

## Participants

You need about 10 minutes before the demo, and an internet connection.

### 1. Send the presenter your public IP

Open <https://checkip.amazonaws.com> and send the number it shows. The proxy
only accepts connections from listed IPs. If you change networks (home Wi-Fi to
school Wi-Fi, or a phone hotspot) your IP changes: send the new one.

### 2. Install git and uv

uv installs the right Python for you.

- macOS / Linux: `curl -LsSf https://astral.sh/uv/install.sh | sh`
- Windows (PowerShell): `powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"`,
  and git from <https://git-scm.com/download/win>

Open a new terminal afterwards so `uv` is on your PATH.

### 3. Get the code

```bash
git clone https://github.com/uchenna-j-edeh/securelitellm.git
cd securelitellm
uv sync
```

### 4. Unpack your demo file

The presenter sends you `<your-name>.zip` privately. Unzip it **outside** the
repository, for example into your home folder. It contains:

- `securelitellm-demo.env`: your agent key, your approver key and the proxy
  address. Don't share it; it stops working when the demo deployment is
  removed.
- `cert.pem`: the demo's certificate. Keep it next to the env file.

### 5. Start the demo

From the `securelitellm` folder:

```bash
uv run python scripts/demo_remote.py ~/<your-name>/securelitellm-demo.env
```

(Windows: `uv run python scripts\demo_remote.py %USERPROFILE%\<your-name>\securelitellm-demo.env`.)

Then open <http://localhost:8003>. Ctrl-C stops it.

### 6. During the demo

- Pick a beat and send it, or type your own request. The agent's tool calls
  (web pages, files, email) run on your laptop; email is only logged, never
  sent.
- Only **session** mode exists in the default AWS deployment. The stateless
  switch is disabled unless a stateless proxy URL is explicitly configured.
- If the proxy holds a send for approval, the Approve / Deny panel shows it.
  Your approver key can decide it.
- The decision panel can read this session's actual CloudWatch records when
  the UI server has authorized AWS read access (see below). Without it,
  the panel explains the connection error. You can also load a saved export;
  those records are clearly marked **Recorded evidence**, not a live replay.
- GitHub beats read a public demo repository. Gmail beats show as not
  configured (they need the presenter's mailbox).
- **Jira beats:** open `securelitellm-demo.env`, fill in your own
  `JIRA_EMAIL=` (your Atlassian login) and `JIRA_API_TOKEN=` (from
  <https://id.atlassian.com/manage-profile/security/api-tokens>), and restart
  the launcher. The site, project and issue keys are already in the file.
  Without them the Jira beats stay hidden.

### If something goes wrong

| What you see | Cause and fix |
|---|---|
| Timeout or "connection refused" on every request | Your IP isn't on the list. Recheck step 1 and send the new IP |
| Certificate error (`CERTIFICATE_VERIFY_FAILED`) | `cert.pem` isn't next to the env file, or the deployment was rebuilt; ask for a new zip |
| 401 / "invalid key" | The deployment was rebuilt since your zip was made; ask for a new zip |
| "address already in use" on 8002 or 8003 | Another copy is running: stop it, or set `DEMO_PORT` / `MCP_SERVER_PORT` and `DEMO_TOOL_SERVER_URL` in the env file |

## Presenter

### Show decisions on the same page

The page displays chat, tool results, and gateway decisions together. Live
CloudWatch access is configured on the UI server; browser clients do not need
AWS credentials. If participants run their own UI servers, each server needs
authorized read access to enable live CloudWatch decisions. Keep AWS
credentials on the UI server rather than in participant env files.

On the machine running the UI server, use AWS CLI v2 and an existing authorized
profile with `logs:FilterLogEvents` on the demo log group. No gateway redeploy
or IAM write permission is needed for this page change. Before starting the UI:

```bash
export DEMO_DECISION_SOURCE=cloudwatch
export DEMO_CLOUDWATCH_PROFILE=securelitellm-infra  # or your existing read-only profile
export DEMO_CLOUDWATCH_REGION=us-east-1
export DEMO_CLOUDWATCH_LOG_GROUP=/ecs/securelitellm-dryrun
uv run python scripts/demo_remote.py ~/<your-name>/securelitellm-demo.env
```

`DEMO_CLOUDWATCH_PROFILE` falls back to `DRYRUN_AWS_PROFILE`, then the AWS CLI's
normal credential chain. AWS settings stay on the UI server. The browser can
ask only for a server-owned UI session, never an arbitrary CloudWatch query.
Records must match that session's fingerprint, configured agent (when set),
and memory mode. The panel polls during the task and for 30 seconds afterwards
to accommodate log ingestion delay; **Refresh logs** retries later. It shows
source errors explicitly rather than inventing a decision. Repeated polls do
not duplicate cards or counters.

For a local Docker stack, `DEMO_DECISION_SOURCE=docker` uses the proxy container
logs. `auto` (the default) chooses CloudWatch for the remote launcher and Docker
for localhost proxies.

**Saved evidence:** click **Load recorded log** and select a CloudWatch Logs
Insights JSON export (`@message` as JSON text or an object), or raw decision
JSONL. The file is read in the browser, not uploaded to AWS or the model. Choose
one agent/session if the export contains several. The banner explicitly says
these are recorded records. **New Session** returns to live mode. Loading a
saved file does not run an agent or prove the outcome of a different live task.

The four visible fields are **Risk score**, **Risk level**, **Route**, and
**Action**. Risk score is a policy score, not an attack probability. The page
also explains the action in plain language and exposes original audit fields
under **Evidence details**. The full tool result can be expanded in the chat.

All commands use the AWS profile that can create the infrastructure:

```bash
export DRYRUN_AWS_PROFILE=securelitellm-infra
```

### Before the demo (allow 30 minutes)

```bash
scripts/aws_dryrun.sh up                     # about 10 minutes; admits your own IP
scripts/aws_dryrun.sh release                # images, db-setup, service
scripts/aws_dryrun.sh allow 203.0.113.7 198.51.100.24   # participants' IPs (or CIDRs)
scripts/aws_dryrun.sh participant alice      # one per person
scripts/aws_dryrun.sh participant bob
scripts/aws_dryrun.sh participant carol
```

`participant <name>` creates two LiteLLM users, `demo-<name>` (agent key,
model `llm` only) and `demo-<name>-approver` (proxy admin, used only by the
UI's approve/deny buttons; it can't send model requests), and writes
`infra/.dryrun/participants/<name>.zip`. Send each zip privately (not in a
group chat). The env file in it has none of your `deploy/.env` secrets: no
master key, Jira, Gmail, SMTP or Groq values.

Run `allow` again whenever someone's IP changes; the list only grows, and your
own current IP is always included. Participants on the same network share one
public IP.

### During the demo

```bash
scripts/aws_dryrun.sh watch     # one line per decision: time, agent, phase, action, risk, rules
```

Or in the console: CloudWatch -> Live Tail -> log group
`/ecs/securelitellm-dryrun`, filter `"action"`. Logs Insights, per participant:

```
fields @timestamp, agent, phase, action, risk_score, matched_rules
| filter ispresent(action) | sort @timestamp desc
```

### Between and after demos

- Leaving it up overnight costs about $5 a day; keys, URL and zips stay valid.
- `down` removes everything. A later `up` gives a new address, certificate
  and keys, so every participant needs a new zip (their IPs are kept only
  if you `allow` them again).
- The certificate `up` makes is valid for 7 days.
