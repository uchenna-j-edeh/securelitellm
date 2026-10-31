# Independent scenario author brief (#199)

This portion must be completed by a teammate who did not design the gateway
controls. The new work-channel fixtures were written during implementation and
**do not count as independent scenarios**.

## Threat model to give the author

An enterprise assistant reads outside material (documents, email, tickets and
issue comments) while completing a legitimate user task. An attacker can edit
one such outside source, but cannot change the real user's request or the
administrator's policy. Their goal is to induce an unauthorized send, upload,
write or misleading answer. Use only synthetic data and reserved example domains.

Without inspecting implementation rules, classifier scores, existing attack
wording or evaluation results, write at least three attacks and one benign
control. Vary the source, the delay between reading and acting, and the action
attempted. Explain the intended legitimate task and what makes the attack
unauthorized. Do not tune a payload after seeing its verdict.

## Handoff

Use the format in [corpus/README.md](../../corpus/README.md). IDs sc-070 onward
and bn-070 onward are currently available; check before choosing one. Validate
schema locally without running the classifier or gateway:

```sh
uv run python corpus/validate.py corpus/scenarios/sc-070.yaml
```

Deliver the scenarios in a separate commit or PR, noting the author, date, and
that no verdict-driven tuning was performed. Record those details in the
results write-up after the first frozen run. Let the maintainer handle any
schema repairs while preserving the attack wording. The team has not assigned
this author yet; this brief is preparation, not completion of that requirement.
