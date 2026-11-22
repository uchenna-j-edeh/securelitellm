# Final presentation: 12 minutes, one screen

The audience has no project context. Start with the problem and one simple
picture before showing an interface. Organize around user tasks and outcomes,
not implementation modules or which teammate wrote them.

## Slide-led structure

| Presentation time | What the audience sees | What to explain |
| --- | --- | --- |
| 0:00–1:30 | A normal user request beside a malicious instruction hidden in an email | An assistant must read outside content, but its author must not gain the user's authority. Define prompt injection using this example. |
| 1:30–3:00 | One architecture slide: agent → SecureLiteLLM → model; tool results return through that boundary | Briefly introduce injection detection, session memory, destination controls, and restricted routes. Define tools, route and action once. |
| 3:00–8:00 | A prerecorded 5-minute demonstration, only the project page | Show user intent → external content → gateway decision → executed/not-executed action. |
| 8:00–10:00 | Verified evaluation results, with attack and benign denominators | Separate evidence of enforcement in the video from reliability across a test set. Use current repository result tables; do not infer detection rates from selected clips. |
| 10:00–11:00 | Two or three concrete limitations | Classifier false positives, tested threat scope, and deployment/model-routing limits relevant to the actual recording. |
| 11:00–12:00 | Contribution and takeaway | Return to the original example: useful tasks proceed; outside instructions do not automatically acquire authority. |

Use slide handoffs for the three speakers. During the video, one person handles
playback; the other two do not operate separate laptops. Record voice-over in
advance, or agree exact chapter timestamps for live narration. This removes
the need to coordinate three browsers or find logs mid-presentation.

## Five-minute video storyboard

Select working, rehearsed scenarios. A focused demonstration is better than
clicking every button. The timings below are edit targets, not promises about
model latency.

| Video time | Operator steps on the project page | What the narrator explains |
| --- | --- | --- |
| 0:00–0:40 | New Session → Gmail control → Send. Keep chat and decision panel visible. | The assistant reads a clean message and completes a summary. Confirm the corresponding gateway records before describing them as allowed. |
| 0:40–2:20 | New Session → Gmail attack → Send. Expand **Show full tool result** under `read_email`. Pause on the instruction, then on the matching decision card. | User asks to handle invoice 4471. The email asks to forward a customer list and ignore previous instructions. Explain `INJECTION`, high risk, quarantine, and `strip-tools` only when these are the recorded values. Show the actual tool-call sequence. |
| 2:20–3:20 | New Session → one rehearsed Jira or GitHub attack/control item. | A second untrusted source reaches the same boundary. Explain what this adds, rather than repeating every technical field. If unavailable, use this minute to explain the Gmail trace more clearly. |
| 3:20–4:30 | New Session → New supplier (approval), or one sensitive-data route scenario that has been verified with the deployed model configuration. | Show a distinct decision: hold for review, or routing sensitive context to the configured approved model. If approving, show the resulting tool outcome; approval alone does not prove execution. Do not call a Bedrock route local. |
| 4:30–5:00 | Hold the final decision and matching task outcome on screen. | Relate the four fields to the user task. Save a still frame for a backup slide. |

The Gmail control summarizes a message without sending. It is not a successful
send control. With email mode `log`, a send tool writes a local outbox entry;
it does not deliver Gmail or SMTP mail. Describe exactly what the recording
shows. Do not use an empty Gmail Sent folder as evidence of gateway enforcement.

## Before recording

1. Use one laptop with all required tool accounts and the UI changes installed.
   Configure CloudWatch reads as described in [REMOTE_DEMO.md](REMOTE_DEMO.md#show-decisions-on-the-same-page).
2. Rehearse each item once. Confirm **Risk score**, **Risk level**, **Route** and
   **Action** appear for the correct agent/session. Missing or delayed logs are
   a readiness issue, not an allow/block result.
3. Capture a 16:9 browser view at 1920×1080 where possible. Keep the same zoom
   and window size throughout. Do not film terminals, AWS credentials or
   notification popups.
4. Expand only the source text and decision details needed to explain the case.
   Read the actual `action`; quarantine and hold are not both called block.
5. Start a fresh session for independent attack/control items. Keep the same
   session only for an intentional multi-turn memory experiment.
6. If showing a session-versus-stateless comparison, run the actual dual stack.
   The default AWS deployment has only session mode. Gmail injection detection
   alone does not establish a session-memory advantage.

## Capture and edit

- Record the actual complete interactions first, then add narration. Cut long
  waits and pointer hunting while keeping the prompt, source read, decision
  and tool outcome intact.
- Use the same recording's audit records. If loading a saved export, keep the
  **Recorded evidence** banner visible and introduce it as that run's saved
  evidence; it is not a new live decision or a replay.
- Spend a few seconds on the malicious sentence and a few on the decision
  fields. Viewers should not have to read a full JSON object or a changing
  console while listening.
- Export an MP4 and embed it in the deck. Test playback on the actual
  presentation machine; keep the MP4 available locally as a backup. The final
  deck/video files are separate deliverables, not produced by this code change.

## Plain-English narration for the Gmail chapter

> We connected the demo to Gmail so the assistant can read actual email content.
> Here is a normal request: read a message and summarize it. The assistant
> completes that task.
>
> Now the user asks it to handle an invoice. The email contains an additional
> instruction to forward a customer list to another address and ignore previous
> instructions. That instruction comes from the email's author, not the user.
> All the data in this example is synthetic.
>
> After the email is read, the gateway record identifies an injection and selects
> quarantine with strip-tools. The model can still reply in text, but its tools
> are removed for that request. In this recorded run, no send-email call executes.
>
> The panel gives us the policy risk score, the risk level, the model route and
> the action taken. These are gateway audit records, separate from the assistant's
> answer. Together with the tool results, they show what the system actually did.

Use the last two paragraphs only with the matching verified attack trace.
The current UI is designed to keep all this evidence on the project page.
