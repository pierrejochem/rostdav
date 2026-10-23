+++
title = "Administrator guide"
description = "Install, configure, back up, upgrade and watch a Rostdav server."
sort_by = "weight"
weight = 2
+++

Rostdav is one program with one data folder. It does not terminate TLS itself: you run it behind a reverse proxy that does.

Start with the [installation guide](@/admin/deployment.md). The [administration reference](@/admin/administration.md) covers roles, the `rostdav admin` command line, settings, retention and the event log. How each part is secured is in the [security concept](@/reference/security.md).

{{ shot(name="admin-users", alt="Administration: the user list") }}

In the web interface, administrators have an **Administration** area with users, the event log, status and a consistency check, sign-in and maintenance mode, and the server settings (including adjustable limits and the optional version check).
