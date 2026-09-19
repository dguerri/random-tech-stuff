---
title: 'Facebook (Meta) Gizmo - From Cardboard Prototypes to Secure Corporate Devices'
date: 2025-08-14 07:31:08 +0200
categories: ['Hardware & Firmware', 'Systems & Security']
tags: ['hardware', 'firmware', 'tpm', 'embedded', 'minnowboard', 'meta', 'facebook', 'provisioning', 'security']
description: 'The engineering story of Gizmo at Facebook (Meta): how a cardboard prototype with MinnowBoard and TPM 2.0 evolved into a hardened, securely provisioned corporate device fleet.'
image:
  path: /assets/images/gizmo/cover.jpg
  alt: 'Facebook Gizmo - From Cardboard Prototypes to Secure Corporate Devices'
---

Back in my early years at Facebook (now Meta), I worked on something that was both challenging and surprisingly fun. The most unexpected part? I would never have guessed I’d end up working on it at all.

I was part of a team called Collaboration Engineering. Our focus was building collaboration tools for internal use, starting with conference rooms. At the time, we were looking for an in-house way to manage our meeting room displays (the ones outside rooms showing schedules and availability) and other small appliances.

In my early days on the team, I was given a potential project related to provisioning, via Chef, on an embedded device. The goal was to configure and maintain our growing fleet of in-room displays. But the more I looked at it, the less sense it made to manage these devices like traditional Linux servers.

The challenges with the original approach were clear. We had to ensure continuous delivery of the core application, manage operating system updates, handle device enrollment and identity, and secure everything properly. Doing that with Chef would have required extensive scaffolding, a heavy runtime on low-power devices, and constant state reconciliation.

Fortunately, my manager at the time was open-minded enough to consider an alternative design I proposed.

Chef works well in a tightly controlled, standardized environment like a datacenter (though I could tell you some war stories about datacenter Chef runs, too!). But applying it to thousands of small, distributed, low-power devices across offices worldwide felt like the wrong tool for the job.

The idea was simple. Instead of provisioning devices with a base OS and updating them periodically through Chef, we would use an approach closer to modern mobile operating systems: **immutable, cryptographically signed “golden images”** delivered directly from the network. The device would treat its local storage as a cache, verifying each image before running it.

Of course, we still had to address some serious security requirements. The threat model for these devices included:

- A stolen device with its contents analyzed (*)
- Interception of device traffic (passive or MITM)
- Device impersonation to gain unauthorized access to internal resources

So, at minimum, our provisioning system had to:

- Identify each device uniquely so the right application and settings could be delivered
- Deliver secrets securely
- Minimize the attack surface on the device itself
- Prevent persistent compromise if a device was tampered with

Around that time (this was 2016), I had been reading about Trusted Platform Module (TPM) technology and its role in secure hardware identification and attestation. The concept was promising: use a TPM to generate and hold cryptographic keys that never leave the hardware, enabling secure identity verification even in hostile environments.

One of the big mottos at Facebook then was, *“What would you do if you were not afraid?”* Our provisioning idea was solid, but we needed to prove it could work in practice.

So, we started prototyping using one of the few devices that could be extended with a firmware TPM 2.0: the **MinnowBoard MAX**.

![MinnowBoard MAX Prototype](/assets/images/gizmo/prototype-minnowboard.jpg)
*Early prototype based on the MinnowBoard MAX with firmware TPM 2.0*

As the prototype matured and proved viable, we secured enough funding to hire a couple of electronics engineers and design fully custom hardware and mechanics from scratch. That is how **Gizmo** was born: [Andrea Locatelli - Facebook RoomTool](https://andrea-locatelli.com/facebook-roomtool).

![Facebook Gizmo Hardware](/assets/images/gizmo/gizmo-hardware.jpg)
*The custom-designed Facebook Gizmo hardware*

It was not perfect from day one. Gizmo went through several iterations and improvements. But the provisioning design was flexible enough to support quick, safe experimentation. The golden image approach made it easy to roll out updates, test new features, and recover from failures without physically touching the devices.

---

### How it worked in practice

Each Gizmo could be in one of two states: **unprovisioned** or **provisioned**.

Devices arrived from the factory (Quanta Computing at the time) with custom firmware we wrote. Initially, this was a UEFI firmware; in later iterations, we switched to Coreboot with a Linux payload.

The firmware booted from the network using HTTPS, downloading a kernel and initramfs that contained a custom second-stage bootloader we called the *enrollment image*.

The enrollment image displayed a QR code that refreshed every few minutes. An operator would scan it with a custom application, log in with corporate credentials, and enter the device location, owner, and purpose (VC control panel, Wayfinder, RoomTool, etc.).

![Gizmo Enrollment QR Code](/assets/images/gizmo/enrollment-qr.jpg)
*Enrollment image displaying a dynamically refreshing QR code*

During enrollment, the device generated an RSA key pair and sent the public key to Facebook’s backends via the operator application.

Once enrolled, the device rebooted. Now, during boot, it could be securely identified, and the backend could deliver the correct golden image for its assigned role. The image was verified, decrypted using keys bound to the TPM, and booted into RAM.

After boot, the same encryption mechanisms were used to send device- and application-specific settings and secrets. Among other things, the device received a client certificate that allowed it to communicate with the Facebook corporate network.

---

(*) *And yes, in case you are wondering, someone actually stole a Gizmo. They still could not extract any protected information from it.*
