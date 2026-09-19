---
title: 'AI did not change security. It changed the price of overlooking the obvious.'
date: 2026-05-23 22:06:48 +0200
categories: ['AI & Cybersecurity', 'Strategy & Philosophy']
tags: ['ai', 'agentic-workflows', 'vulnerability-management', 'application-security', 'red-team', 'blue-team']
description: 'Why AI and agentic workflows do not make cybersecurity fundamentals obsolete, but rather raise the price of overlooking the obvious and fundamentally reshape vulnerability management.'
image:
  path: /assets/images/ai-security/cover.jpg
  alt: 'AI did not change security. It changed the price of overlooking the obvious.'
---

This term, a few cybersecurity students came to me with the same question about security agentic workflows: *will I still be useful?*

What they mean is that AI seems to do, faster and better, the work they were planning to learn. The premise is wrong.

Security has always had a visibility problem. Most issues are not ignored because nobody cares; they are ignored because they are buried under noise, distributed across systems, or individually look too benign to prioritize.

---

## The Economics of the Obvious

By January 2026, automated vulnerability reports had pushed Daniel Stenberg to close curl's bug bounty programme entirely. Seth Larson at the Python Software Foundation reported similar patterns.

The story has since moved. By April 2026, Stenberg reported that the slop had largely stopped, replaced by higher-quality, genuine automated findings.

The shape of the curve matters more than any single data point.

Phase one—plausible hallucination, no underlying truth—is (was) a problem of incentives and verification costs. Defenders do not just need better signal-to-noise. They need a different way to absorb signal at this cadence.

Confirmation bias and automation bias make this worse on the defensive side. When we expect AI to find things, we trust what it surfaces without checking, or we dismiss what it flags as hallucination. These are well-documented failure modes in SOC triage and code review. They have arrived now in vulnerability management.

---

## How Real Attacks Compose

The highest-impact attacks are not always built around one spectacular vulnerability. Wormable bugs like Log4Shell or EternalBlue get the headlines, but the everyday compromises that cause real damage are usually compositions.

A small exposure gives access to metadata. Metadata points to an identity. The identity has permissions nobody reviewed. Those permissions reach a build system. The build system can deploy to production. Production has access to sensitive data. At the start of the chain, the finding does not look dramatic. At the end of it, it is an incident.

None of those steps is exotic:
- Overprivileged service accounts
- Weak trust boundaries
- Exposed internal endpoints
- CI/CD pipelines with production access
- Secrets at build time
- Services that assume "internal" means "trusted"
- Low-severity bugs that become dangerous in combination

These are not new problems. They are the raw material of most real attacks. What makes them dangerous is putting them together.

This is where AI changes the economics: surfacing weak signals, recognising familiar failure modes, connecting them into plausible attack paths. Attackers have always worked this way; good red teamers do it constantly. They enumerate, hypothesise, test, fail, adjust, continue. They do not need every step to be novel. They need the chain to work.

It is also where the asymmetry shows. Attackers and defenders both get AI tooling, but the structural asymmetry of the field has not changed: **attackers need one chain to work, defenders need every chain to fail.** AI scales the search on both sides; only the attacker keeps the wins. That is why the agentic side of AI matters.

A model that answers one question is useful but limited. A system that can plan, call tools, inspect results, keep state, adjust strategy, and continue toward a goal is much closer to how offensive security actually happens. An AI-assisted offensive workflow does not need a new zero-day to be dangerous; it can become very effective at combining known weaknesses into working attack paths.

Genuinely novel failure modes remain harder. The line is not clean, since many "new" attacks are new compositions of old ideas, but AI is strongest where there are patterns to recognise and steps to automate.

So back to the opening question: *Will I still be useful?*

What we just described—understanding why something is exploitable, recognising the compositions that turn the ordinary into the dangerous, building the systems that surface them at scale—**is the work.** The worry has the field backwards.

---

## Vulnerability Management Has to Evolve

If agentic AI is closing this gap on offence, defence has to evolve to match it. A scanner can tell you a package is vulnerable. What it cannot do, by design, is reason through a multi-step path. It is single-shot: one artefact, one rule, one verdict.

Real attacks compose. They cross identity boundaries, deployment surfaces, runtime context. The mismatch between scanning and attacker behaviour is the structural gap defenders have always lived with; AI is just making it impossible to ignore.

The industry has been narrowing it for years:
- **EPSS** adds probabilistic exploit likelihood to CVSS.
- **SSVC** adds context-driven decision logic.
- **CISA's KEV** catalogue tells you what is actually being exploited in the wild.
- **Reachability-aware SCA** tries to answer whether a vulnerable function sits on a callable path.

All useful... but most organisations do not combine them, and none of them alone answers the question that matters: *given my architecture, identity, privilege, and runtime, what can an attacker chain together from here?*

The newer generation of AI-assisted security systems is already getting better at that question than the previous one. Hallucinations are less frequent. False positives are dropping, particularly with systems that pair code analysis with active exploitation, validating a finding by trying it rather than just inferring it.

The models are improving at the part that used to be hardest for them: knowing what is actually worth surfacing and what is not. None of this is finished, and the rate of progress is uneven, but the direction is clear. The next iteration will handle more convoluted scenarios than this one, and the one after that more than that.

That changes the shape of vulnerability management:
- Less waiting for a CVE identifier (or GHSA) to tell you something deserves attention; more discovering it yourself, in context, before the catalogue catches up.
- Less reactive patching against a known list; more continuous reasoning about what your system actually exposes, and a delivery pipeline that can act on the answer fast enough for it to matter.

The question stops being which of yesterday's vulnerabilities have we patched and starts being how quickly does our system understand and respond to new ones, including the ones we may be the first to find.

This brings us back to ideas we already have: *shift left, defence in depth, zero trust, least privilege, threat modelling, secure CI/CD.*

None of them are new. The problem is that we treated them as slogans:
- *"Shift left"* became running a scanner earlier.
- *"Zero trust"* became a product category.
- *"CI/CD security"* stopped at repository permissions, while build pipelines quietly became some of the most privileged systems in the company.

The shift from reactive to continuous is what could finally make these ideas work... but only if someone builds the systems that hold them up. And underneath all of it sits a harder question: **can we actually redeploy faster?**

---

## Why You Are Still Very Much Needed

That is the point. Someone has to build these systems and evolve them.

**If you go to the red side**, you will need to build the offensive ones: the agents, the harnesses, the orchestrators that compose known weaknesses into working chains and surface the genuinely novel ones. Penetration testing is moving from a manual craft to an engineered discipline, and that engineering has to be done by people who understand both how attacks compose and how systems fail.

**If you go to the blue side**, you will need to build the defensive ones: the analysis pipelines, the reasoning agents, the attack-path-aware tooling... and the half of the problem defenders have always under-invested in: the delivery rate. Discovering a vulnerability faster only matters if your organisation can fix it faster. Continuous discovery without continuous remediation is just a louder backlog.

Both sides are engineering problems. Both demand the fundamentals worth doubling down on:
- Operating systems and memory safety
- Networking and protocols
- Identity, authentication, and authorisation
- Web security and API boundaries
- Cryptographic primitives and their misuse
- Containers, cloud platforms, and orchestrators
- Build systems and deployment pipelines

And both demand the higher-order skills that compound with AI: adversarial thinking, architecture review, identity and privilege reasoning, threat modelling, and the judgement to know when a model's answer is right for the wrong reason. These are exactly the skills it takes to build these systems well.

The work will keep us occupied for years. And while we are building, the technology will keep moving, the bar will keep rising, and what counts as "obvious" will keep shifting upward. That is normal. That is what every meaningful transition in this field has looked like.

---

## This is One of Those Moments

If history teaches us anything, it is that it repeats itself with variation. And the variation is often what makes the pattern hard to recognise while you are inside it.

The shift from on-prem to cloud. The shift from machines to containers. The shift from waterfall to continuous deployment. Each one looked, at the time, like it might make the previous generation's skills obsolete. Each one instead raised the bar on what those skills had to do.

This is another one of those moments. AI did not make the fundamentals obsolete. It changed the price of overlooking them... and it changed who gets to build what comes next.

Will you still be useful? **Yes, and you will be needed more than the industry has needed anyone in a while.**

Let's build it.
