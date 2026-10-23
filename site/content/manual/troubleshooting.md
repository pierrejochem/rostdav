+++
title = "Troubleshooting"
description = "Answers to common problems: the app cannot connect, sign-in is blocked, the server says it is in maintenance, a file will not upload or is missing."
weight = 70
[extra]
edit = "manual/troubleshooting.md"
+++

## The app cannot connect to my server

- Use the full address with `https://`, exactly as your administrator gave it.
- Open the same address in a browser. If the browser shows a certificate warning, the app will refuse too: the administrator has to fix the certificate.
- If the sign-in page opens but the app does not notice that you finished, close the page and start the sign-in from the app again; the link is only valid for a short time.

## "Too many attempts" at sign-in

Sign-in is blocked for a while after repeated wrong passwords or codes. Wait the time shown, or ask an administrator to lift the block under **Administration → Sign-in and maintenance**.

## The apps say the server is in maintenance

An administrator switched on maintenance mode, for a backup or an upgrade. The apps wait and retry by themselves. The web interface keeps working.

## A file does not upload

- The name may be refused: no `/` or `\`, no control characters, at most 255 bytes, and not ending in `.part` or `.filepart`.
- You may be over your quota. The storage meter shows it; empty the trash or delete old versions to free space.
- The file may be larger than the server allows (16 GiB by default).

## A file is gone

Look in the **Trash bin**. If it was overwritten, look in the file's **Versions**. If somebody shared the folder with you and removed the share, the folder disappears from your list; ask them to share it again.

## I lost my phone

Open **Devices & security** and revoke the phone's app password. Then change your password if you think someone else could use it.

## I forgot my password

Ask an administrator to set a new one. There is no e-mail reset.
