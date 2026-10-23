// Uploads on the Files page: chunked and resumable, with drag and drop of files and whole
// folders, a folder picker, and one progress bar for the whole batch. Without this script the
// plain form still uploads files. Text is only ever set with textContent.
(function () {
  "use strict";
  // texts: English is the key, German in the table (page language from <html lang>)
  var DE = {
    "Your session has ended. Sign in again.": "Deine Sitzung ist beendet. Melde dich erneut an.",
    "Could not start the upload.": "Der Upload konnte nicht gestartet werden.",
    "Your storage is full.": "Dein Speicher ist voll.",
    "The file is too large.": "Die Datei ist zu groß.",
    "Upload failed. Select the file again to resume.": "Upload fehlgeschlagen. Wähle die Datei erneut, um fortzusetzen.",
    "A folder with that name exists.": "Ein Ordner mit diesem Namen existiert.",
    "Could not finish the upload. Select the file again to resume.": "Der Upload konnte nicht abgeschlossen werden. Wähle die Datei erneut, um fortzusetzen.",
    "Upload cancelled.": "Upload abgebrochen.",
    "Uploading": "Lade hoch",
    "part": "Teil",
    "of": "von",
    "Could not create the folder": "Der Ordner konnte nicht angelegt werden",
    "A file with that name exists.": "Eine Datei mit diesem Namen existiert.",
    "The name is not allowed.": "Der Name ist nicht erlaubt.",
    "Uploaded": "Hochgeladen",
    "files": "Dateien",
    "Not uploaded": "Nicht hochgeladen",
    "Reload the page": "Seite neu laden",
    "Too many files at once (more than 20,000). Upload them in smaller batches.": "Zu viele Dateien auf einmal (mehr als 20.000). Lade sie in kleineren Gruppen hoch.",
    "Nothing to upload.": "Nichts zum Hochladen.",
    "Choose a folder": "Ordner wählen",
    "Drop files or folders to upload them here": "Dateien oder Ordner hier ablegen, um sie hochzuladen",
    "They go into the folder that is open": "Sie landen im geöffneten Ordner",
    "Reading the dropped folders": "Lese die abgelegten Ordner"
  };
  var de = document.documentElement.lang === "de";
  function _(s) { return de && DE[s] ? DE[s] : s; }
  var CHUNK = 8 * 1024 * 1024;
  var MAX_ITEMS = 20000;
  var form = document.getElementById("upload-form");
  if (!form || !window.fetch || !window.File) return;
  var status = document.getElementById("upload-status");
  var progress = document.getElementById("upload-progress");
  var card = document.getElementById("upload-card");
  var cancelBtn = document.getElementById("upload-cancel");
  var fileInput = form.elements.file;
  var csrf = form.elements.csrf.value;
  var dir = form.elements.dir.value; // the open folder, like "Docs/2026" ("" = the top)
  var ctl = null, current = null, running = false;

  function say(text) { status.textContent = text; }
  function join(a, b) { return a ? a + "/" + b : b; }

  function api(method, url, body, headers) {
    var h = Object.assign({ "X-CSRF-Token": csrf }, headers || {});
    return fetch(url, { method: method, body: body, headers: h, credentials: "same-origin", redirect: "manual", signal: ctl ? ctl.signal : undefined })
      .then(function (r) {
        if (r.type === "opaqueredirect") throw fatal(_("Your session has ended. Sign in again."));
        return r;
      });
  }

  // An error that stops the whole batch (the others only skip one file).
  function fatal(msg) { var e = new Error(msg); e.fatal = true; return e; }

  // Same path, same size, same time: an interrupted upload resumes where it stopped.
  function transferId(file, rel) {
    var s = rel + "|" + file.size + "|" + file.lastModified, h = 5381;
    for (var i = 0; i < s.length; i++) h = ((h * 33) ^ s.charCodeAt(i)) >>> 0;
    return "w-" + h.toString(16) + "-" + file.size;
  }

  function chunkName(i) { return ("000000" + i).slice(-6); }

  // `item`: { file, rel } where rel is the path below the open folder ("a/b/c.txt").
  // `onBytes(n)` reports bytes done in this file.
  function uploadFile(item, label, onBytes) {
    var file = item.file;
    var slash = item.rel.lastIndexOf("/");
    var folder = join(dir, slash < 0 ? "" : item.rel.slice(0, slash));
    var id = transferId(file, join(dir, item.rel)), base = "/web/upload/" + id;
    current = base;
    var count = Math.max(1, Math.ceil(file.size / CHUNK));
    var have = {};
    // Start the transfer; "409" means it exists from an interrupted run, so ask what is there.
    return api("POST", base).then(function (c) {
      if (c.status === 201) return;
      if (c.status !== 409) throw new Error(_("Could not start the upload."));
      return api("GET", base).then(function (r) {
        if (!r.ok) throw new Error(_("Could not start the upload."));
        return r.json().then(function (j) { j.chunks.forEach(function (x) { have[x.name] = x.size; }); });
      });
    }).then(function () {
      var i = 0;
      function next() {
        if (i >= count) return Promise.resolve();
        var idx = i++, start = idx * CHUNK, end = Math.min(file.size, start + CHUNK);
        onBytes(start);
        if (have[chunkName(idx)] === end - start && end - start > 0) return next();
        say(_("Uploading") + " " + label + (count > 1 ? " – " + _("part") + " " + (idx + 1) + " " + _("of") + " " + count : ""));
        return api("PUT", base + "/" + chunkName(idx), file.slice(start, end)).then(function (r) {
          if (r.status === 507) throw fatal(_("Your storage is full."));
          if (r.status === 413) throw new Error(_("The file is too large."));
          if (!r.ok) throw new Error(_("Upload failed. Select the file again to resume."));
          return next();
        });
      }
      return next();
    }).then(function () {
      return api("POST", base + "/finish", JSON.stringify({ dir: folder, name: file.name, total: file.size }),
        { "Content-Type": "application/json" });
    }).then(function (r) {
      // 400 and 409 will not get better by trying again: drop the uploaded parts now
      if (r.status === 409 || r.status === 400) {
        fetch(base, { method: "DELETE", headers: { "X-CSRF-Token": csrf }, credentials: "same-origin" });
      }
      if (r.status === 409) throw new Error(_("A folder with that name exists."));
      if (r.status === 507) throw fatal(_("Your storage is full."));
      if (r.status === 400) throw new Error(_("The name is not allowed."));
      if (!r.ok) throw new Error(_("Could not finish the upload. Select the file again to resume."));
      onBytes(file.size);
    });
  }

  function makeFolder(rel) {
    return api("POST", "/web/mkdir", JSON.stringify({ path: join(dir, rel) }), { "Content-Type": "application/json" })
      .then(function (r) {
        if (r.status === 409) throw new Error(_("A file with that name exists."));
        if (r.status === 400) throw new Error(_("The name is not allowed."));
        if (r.status === 507) throw fatal(_("Your storage is full."));
        if (!r.ok) throw new Error(_("Could not create the folder"));
      });
  }

  // Runs a batch: first the folders (parents before children), then the files one by one.
  // A file that fails is skipped and reported at the end; a lost session or a full storage stops.
  function run(items, dirs) {
    if (running) return;
    if (!items.length && !dirs.length) { card.hidden = false; say(_("Nothing to upload.")); return; }
    if (items.length + dirs.length > MAX_ITEMS) { card.hidden = false; say(_("Too many files at once (more than 20,000). Upload them in smaller batches.")); return; }
    running = true;
    ctl = new AbortController();
    card.hidden = false;
    cancelBtn.textContent = cancelLabel;
    var total = items.reduce(function (n, it) { return n + it.file.size; }, 0) || 1;
    var done = 0, ok = 0, failed = [], failedDirs = {};
    progress.value = 0;
    var chain = Promise.resolve();
    dirs.slice().sort(function (a, b) { return a.split("/").length - b.split("/").length; }).forEach(function (d) {
      chain = chain.then(function () {
        say(_("Uploading") + " " + d + "/");
        return makeFolder(d).catch(function (e) {
          if (e.fatal || e.name === "AbortError") throw e;
          failedDirs[d] = true; failed.push(d + "/ – " + e.message);
        });
      });
    });
    items.forEach(function (it, k) {
      chain = chain.then(function () {
        var parent = it.rel.split("/").slice(0, -1);
        for (var j = 1; j <= parent.length; j++) {
          if (failedDirs[parent.slice(0, j).join("/")]) { failed.push(it.rel + " – " + _("Could not create the folder")); return; }
        }
        var base = done;
        return uploadFile(it, it.rel + " (" + (k + 1) + "/" + items.length + ")", function (n) {
          progress.value = Math.min(1, (base + n) / total);
        }).then(function () { done += it.file.size; ok++; }, function (e) {
          if (e.fatal || e.name === "AbortError") throw e;
          failed.push(it.rel + " – " + e.message);
        });
      });
    });
    chain.then(function () {
      progress.value = 1;
      running = false;
      if (!failed.length) { window.location.reload(); return; }
      say(_("Uploaded") + " " + ok + "/" + items.length + " " + _("files") + ". " + _("Not uploaded") + ": " + failed.slice(0, 5).join("; ") + (failed.length > 5 ? " … (+" + (failed.length - 5) + ")" : ""));
      cancelBtn.textContent = _("Reload the page");
      reloadOnClick = true;
    }, function (e) {
      running = false;
      say(e.name === "AbortError" ? _("Upload cancelled.") : e.message);
      fileInput.disabled = false;
      if (ok) { cancelBtn.textContent = _("Reload the page"); reloadOnClick = true; }
    });
  }
  var cancelLabel = cancelBtn.textContent, reloadOnClick = false;

  // ---- choosing: the form's own files input, and a folder picker added here -----------------

  function itemsFromList(list) {
    var items = [], dirs = {};
    Array.prototype.forEach.call(list, function (f) {
      var rel = f.webkitRelativePath || f.name;
      items.push({ file: f, rel: rel });
      var parts = rel.split("/");
      for (var i = 1; i < parts.length; i++) dirs[parts.slice(0, i).join("/")] = true;
    });
    return { items: items, dirs: Object.keys(dirs) };
  }

  form.addEventListener("submit", function (ev) {
    if (!fileInput.files || !fileInput.files.length) return;
    ev.preventDefault();
    var s = itemsFromList(fileInput.files);
    fileInput.value = "";
    run(s.items, s.dirs);
  });

  var picker = document.createElement("input");
  picker.type = "file"; picker.multiple = true; picker.hidden = true;
  picker.setAttribute("webkitdirectory", ""); picker.setAttribute("directory", "");
  var pickBtn = document.createElement("button");
  pickBtn.type = "button"; pickBtn.textContent = _("Choose a folder");
  pickBtn.addEventListener("click", function () { picker.click(); });
  picker.addEventListener("change", function () {
    if (!picker.files || !picker.files.length) return;
    var s = itemsFromList(picker.files);
    picker.value = "";
    run(s.items, s.dirs);
  });
  form.appendChild(pickBtn);
  form.appendChild(picker);

  // ---- drag and drop: files and whole folders anywhere on the page --------------------------

  var overlay = document.createElement("div");
  overlay.className = "drop-overlay"; overlay.hidden = true; overlay.setAttribute("aria-hidden", "true");
  var box = document.createElement("div");
  var small = document.createElement("small");
  box.textContent = _("Drop files or folders to upload them here");
  small.textContent = _("They go into the folder that is open");
  box.appendChild(small); overlay.appendChild(box); document.body.appendChild(overlay);

  function hasFiles(ev) {
    var t = ev.dataTransfer && ev.dataTransfer.types;
    return !!t && Array.prototype.indexOf.call(t, "Files") >= 0;
  }
  var depth = 0;
  document.addEventListener("dragenter", function (ev) {
    if (!hasFiles(ev)) return;
    ev.preventDefault(); depth++; overlay.hidden = false;
  });
  document.addEventListener("dragover", function (ev) {
    if (!hasFiles(ev)) return;
    ev.preventDefault(); // allow the drop
    if (ev.dataTransfer) ev.dataTransfer.dropEffect = "copy";
  });
  document.addEventListener("dragleave", function (ev) {
    if (!hasFiles(ev)) return;
    depth = Math.max(0, depth - 1); if (!depth) overlay.hidden = true;
  });
  document.addEventListener("drop", function (ev) {
    if (!hasFiles(ev)) return;
    ev.preventDefault(); depth = 0; overlay.hidden = true;
    if (running) return;
    var dt = ev.dataTransfer, entries = [], loose = [];
    // the entries must be taken now: the list is emptied when this handler returns
    if (dt.items && dt.items.length) {
      for (var i = 0; i < dt.items.length; i++) {
        var it = dt.items[i];
        if (it.kind && it.kind !== "file") continue;
        var en = it.webkitGetAsEntry ? it.webkitGetAsEntry() : null;
        if (en) entries.push(en); else if (it.getAsFile) { var f = it.getAsFile(); if (f) loose.push({ file: f, rel: f.name }); }
      }
    } else if (dt.files) {
      Array.prototype.forEach.call(dt.files, function (f) { loose.push({ file: f, rel: f.name }); });
    }
    card.hidden = false; say(_("Reading the dropped folders") + " …");
    var out = { items: loose, dirs: [], count: 0 };
    var chain = Promise.resolve();
    entries.forEach(function (en) { chain = chain.then(function () { return walk(en, "", out); }); });
    chain.then(function () { run(out.items, out.dirs); }, function (e) { say(e.message); });
  });

  function readAll(reader) {
    return new Promise(function (resolve, reject) {
      var all = [];
      (function more() {
        reader.readEntries(function (batch) {
          if (!batch.length) return resolve(all);
          all = all.concat(Array.prototype.slice.call(batch)); more();
        }, reject);
      })();
    });
  }

  // Adds an entry and, for a folder, everything below it. Empty folders are kept.
  function walk(entry, prefix, out) {
    if (++out.count > MAX_ITEMS) return Promise.reject(new Error(_("Too many files at once (more than 20,000). Upload them in smaller batches.")));
    if (entry.isFile) {
      return new Promise(function (res, rej) { entry.file(res, rej); }).then(function (f) {
        out.items.push({ file: f, rel: prefix + entry.name });
      });
    }
    if (!entry.isDirectory) return Promise.resolve();
    var here = prefix + entry.name;
    out.dirs.push(here);
    return readAll(entry.createReader()).then(function (kids) {
      var p = Promise.resolve();
      kids.forEach(function (k) { p = p.then(function () { return walk(k, here + "/", out); }); });
      return p;
    });
  }

  // ---- cancel / reload ----------------------------------------------------------------------

  cancelBtn.addEventListener("click", function () {
    if (reloadOnClick) { window.location.reload(); return; }
    if (ctl) ctl.abort();
    var base = current;
    if (base) {
      // best effort: drop the partial upload on the server
      fetch(base, { method: "DELETE", headers: { "X-CSRF-Token": csrf }, credentials: "same-origin" });
    }
    card.hidden = false;
  });
})();
