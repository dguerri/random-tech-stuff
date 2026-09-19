---
title: 'Lessons from an “Exemption Exam” CTF: Combining Ethical Hacking with Real-World Challenges'
date: 2025-05-31 08:02:40 +0200
categories: ['Education', 'Ethical Hacking']
tags: ['ctf', 'ethical-hacking', 'education', 'kubernetes', 'passkeys', 'web-security']
description: 'Lessons learned from conducting an ethical hacking "exemption exam" CTF for university students at Sapienza University of Rome, exploring LLM usage in CTFs, anti-cheating, and hands-on offensive security.'
image:
  path: /assets/images/exemption-ctf/cover.jpg
  alt: 'Lessons from an Exemption Exam CTF'
---

As part of the ethical hacking course I am teaching at La Sapienza University of Rome, I recently conducted an “exemption exam” in the form of a Capture The Flag (CTF) competition. This exercise was designed to simulate real-world hacking challenges and test students’ practical skills in a controlled environment.

The CTF required students to capture three flags, each corresponding to a different user, to prove their access level. Students had 2 hours and 45 minutes to do so. The first three students to capture the root flag received maximum marks (30/30 cum laude), while others were graded based on their progress.

---

## Themed Environment and Technical Challenges

Inspired by the *“Back to the Future”* movie (which I watched recently with my kids), the CTF machine was named after the DeLorean time machine.

The web application featured a classical 2-tiered architecture, running on a home Kubernetes cluster. It was built using Python (Flask) with a PostgreSQL database.

To give a “futuristic” touch (actually, more a contemporary one 😀), I implemented a password-less registration system using WebAuthn / Passkeys. Students could register using either passkeys or usernames and passwords. After that, they could access the DeLorean dashboard.

---

## Intended Exploitation Path

1. **Initial Access**: The dashboard accepted temporal coordinates to simulate a “temporal jump”. By design, it was vulnerable to command injection through a poorly sanitized parameter, allowing students to obtain a reverse shell.
2. **Privilege Escalation (User)**: Once they had a reverse shell, students discovered a setuid binary owned by a user `ebrown`, which was vulnerable to a path/environment manipulation vulnerability.
3. **Root Escalation**: By exploiting this, they could impersonate `ebrown` (with its effective UID) and access a memory coredump that revealed the final credential material needed to escalate to `root`.

---

## Key Lessons Learned

As one of my students commented at the end of the CTF: *I allowed using LLMs because I knew they would not be enough.*

I saw a diverse range of LLMs and versions being used: DeepSeek, generic ChatGPT, custom GPTs focused on ethical hacking, and Claude.

The results spoke for themselves:
- **37** students registered
- **30** captured the first flag
- **22** captured the second flag
- **15** captured the third (`root`) flag

The first student, who captured all the flags, did so in about **1 hour**.

An unplanned but interesting side effect (which I could have anticipated in hindsight) was that, towards the end of the exam, many students relied heavily on LLMs to debug their exploits. This often led to a **“prompt loop”** where students spent more time refining prompts than analyzing the binary or network traffic.

Again, one of the most significant insights for the students was that **AI and generic online instructions can provide hints, but without foundational knowledge and hands-on experience, they cannot solve non-trivial security challenges.**

---

## Conclusion

Overall, the CTF was a resounding success. It tested students’ technical abilities and underscored the importance of foundational knowledge in binary exploitation, web security, and Linux internals.

While this exercise was meant to simulate real-life engagements, we are still only scratching the surface of ethical hacking. Since this was an ethical hacking course, we also had an anti-cheating system in place to ensure the integrity of the exam (monitoring network traffic, unique per-student flag generation, and correlation of submission timestamps).
