// Chunked, resumable upload for the Files page. Without this script the plain
// form still works. Text is only ever set with textContent.
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
    "of": "von"
  };
  var de = document.documentElement.lang === "de";
  function _(s) { return de && DE[s] ? DE[s] : s; }
  var CHUNK = 8 * 1024 * 1024;
  var form = document.getElementById("upload-form");
  if (!form || !window.fetch || !window.File) return;
  var status = document.getElementById("upload-status");
  var progress = document.getElementById("upload-progress");
  var card = document.getElementById("upload-card");
  var cancelBtn = document.getElementById("upload-cancel");
  var ctl = null, current = null;
  var csrf = form.elements.csrf.value;
  var dir = form.elements.dir.value;

  function say(text) { status.textContent = text; }

  function api(method, url, body, headers) {
    var h = Object.assign({ "X-CSRF-Token": csrf }, headers || {});
    return fetch(url, { method: method, body: body, headers: h, credentials: "same-origin", redirect: "manual", signal: ctl ? ctl.signal : undefined })
      .then(function (r) {
        if (r.type === "opaqueredirect") throw new Error(_("Your session has ended. Sign in again."));
        return r;
      });
  }

  // Same file, same id: an interrupted upload resumes where it stopped.
  function transferId(file) {
    var s = file.name + "|" + file.size + "|" + file.lastModified, h = 5381;
    for (var i = 0; i < s.length; i++) h = ((h * 33) ^ s.charCodeAt(i)) >>> 0;
    return "w-" + h.toString(16) + "-" + file.size;
  }

  function chunkName(i) { return ("000000" + i).slice(-6); }

  function uploadFile(file, n, of) {
    var id = transferId(file), base = "/web/upload/" + id;
    current = base;
    var count = Math.max(1, Math.ceil(file.size / CHUNK));
    var label = file.name + " (" + n + "/" + of + ")";
    var have = {};
    return api("GET", base).then(function (r) {
      if (r.status === 404) return api("POST", base).then(function (c) {
        if (!c.ok) throw new Error(_("Could not start the upload."));
      });
      if (!r.ok) throw new Error(_("Could not start the upload."));
      return r.json().then(function (j) { j.chunks.forEach(function (c) { have[c.name] = c.size; }); });
    }).then(function () {
      var i = 0;
      function next() {
        if (i >= count) return Promise.resolve();
        var idx = i++, start = idx * CHUNK, end = Math.min(file.size, start + CHUNK);
        progress.value = idx / count;
        if (have[chunkName(idx)] === end - start && end - start > 0) return next();
        say(_("Uploading") + " " + label + " – " + _("part") + " " + (idx + 1) + " " + _("of") + " " + count);
        return api("PUT", base + "/" + chunkName(idx), file.slice(start, end)).then(function (r) {
          if (r.status === 507) throw new Error(_("Your storage is full."));
          if (r.status === 413) throw new Error(_("The file is too large."));
          if (!r.ok) throw new Error(_("Upload failed. Select the file again to resume."));
          return next();
        });
      }
      return next();
    }).then(function () {
      return api("POST", base + "/finish", JSON.stringify({ dir: dir, name: file.name, total: file.size }),
        { "Content-Type": "application/json" });
    }).then(function (r) {
      if (r.status === 409) throw new Error(_("A folder with that name exists."));
      if (r.status === 507) throw new Error(_("Your storage is full."));
      if (!r.ok) throw new Error(_("Could not finish the upload. Select the file again to resume."));
      progress.value = 1;
    });
  }

  form.addEventListener("submit", function (ev) {
    var files = Array.prototype.slice.call(form.elements.file.files);
    if (!files.length) return;
    ev.preventDefault();
    form.elements.file.disabled = true;
    ctl = new AbortController();
    card.hidden = false;
    var chain = Promise.resolve();
    files.forEach(function (f, k) { chain = chain.then(function () { return uploadFile(f, k + 1, files.length); }); });
    chain.then(function () { window.location.reload(); }, function (e) {
      say(e.name === "AbortError" ? _("Upload cancelled.") : e.message);
      form.elements.file.disabled = false;
    });
  });

  cancelBtn.addEventListener("click", function () {
    if (ctl) ctl.abort();
    var base = current;
    if (base) {
      // best effort: drop the partial upload on the server
      fetch(base, { method: "DELETE", headers: { "X-CSRF-Token": csrf }, credentials: "same-origin" });
    }
    card.hidden = false;
  });
})();
