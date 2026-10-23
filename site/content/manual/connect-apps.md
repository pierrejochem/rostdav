+++
title = "Connect the Nextcloud apps"
description = "Sign in with the official Nextcloud Android, iOS or desktop app: the browser flow, app passwords per device, and the WebDAV address."
weight = 20
[extra]
edit = "manual/connect-apps.md"
+++

Rostdav is made to work with the **unmodified Nextcloud apps**. You install the app from your usual source (Google Play, F-Droid, App Store, or the Nextcloud download page for the desktop client), and then point it at your Rostdav server instead of a Nextcloud server.

> Rostdav is not a Nextcloud product. Only the functions in the [compatibility report](@/reference/compatibility.md) are supported; the report also says which app versions were tried.

## Connect an app

1. Open the app and choose to **log in** to a server. Enter your server address, for example `https://files.example.org`.
2. The app opens your browser on a page titled **Connect device**. Check that the address bar shows your own server before you type anything.
3. Sign in with your user name and password (and the second-factor code if you use one), then choose **Sign in and allow access**. To refuse, choose **Deny**.
4. The page says **Device connected**. Close it and go back to the app, which now shows your files.

This is *Login Flow v2*, the sign-in the Nextcloud apps use. Your account password never goes to the app. The app receives an **app password** that belongs to that one device.

Rostdav never asks for an app password on this page. If a page asks for one, do not enter it.

## Your devices and app passwords

Under **Devices & security** you see every connected device with the time it was last used. To disconnect a lost or sold phone, **revoke** its app password. The app stops working at once and has to sign in again.

You can also create an app password by hand for software that does not know the browser flow (for example a script or a WebDAV client). The password is shown **once**; copy it right away.

## Other WebDAV programs

Any WebDAV client can use your files. Under **Settings** the page shows your **WebDAV address**; use it with your user name and an app password:

Rostdav speaks standard WebDAV, so file managers and tools that support WebDAV can connect to that address (for example `curl` or `rclone`). Only the clients named in the [compatibility report](@/reference/compatibility.md) were actually tried; for others, test with unimportant files first.

## What works and what was tried

The real **Android app** and the **desktop sync engine** were used with Rostdav: sign-in (also with two-factor), listing, upload (also chunked, large files), download, rename, move, delete, favorites, sharing with users and by link, versions, trash, and offline use. The **desktop app's graphical window** and the **iOS app** were not tried yet. Do not rely on them until the [compatibility report](@/reference/compatibility.md) says so.

Not supported, because Rostdav leaves it out on purpose: calendars, contacts, talk, the app store and other Nextcloud apps. Rostdav is a file server.
