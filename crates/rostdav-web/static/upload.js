// Chunked, resumable upload for the Files page. Without this script the plain
// form still works. Text is only ever set with textContent.
(function () {
  "use strict";
  var CHUNK = 8 * 1024 * 1024;
  var form = document.getElementById("upload-form");
  if (!form || !window.fetch || !window.File) return;
  var status = document.getElementById("upload-status");
  var progress = document.getElementById("upload-progress");
  var csrf = form.elements.csrf.value;
  var dir = form.elements.dir.value;

  function say(text) { status.textContent = text; }

  function api(method, url, body, headers) {
    var h = Object.assign({ "X-CSRF-Token": csrf }, headers || {});
    return fetch(url, { method: method, body: body, headers: h, credentials: "same-origin", redirect: "manual" })
      .then(function (r) {
        if (r.type === "opaqueredirect") throw new Error("Your session has ended. Sign in again.");
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
    var count = Math.max(1, Math.ceil(file.size / CHUNK));
    var label = file.name + " (" + n + "/" + of + ")";
    var have = {};
    return api("GET", base).then(function (r) {
      if (r.status === 404) return api("POST", base).then(function (c) {
        if (!c.ok) throw new Error("Could not start the upload.");
      });
      if (!r.ok) throw new Error("Could not start the upload.");
      return r.json().then(function (j) { j.chunks.forEach(function (c) { have[c.name] = c.size; }); });
    }).then(function () {
      var i = 0;
      function next() {
        if (i >= count) return Promise.resolve();
        var idx = i++, start = idx * CHUNK, end = Math.min(file.size, start + CHUNK);
        progress.value = idx / count;
        if (have[chunkName(idx)] === end - start && end - start > 0) return next();
        say("Uploading " + label + " – part " + (idx + 1) + " of " + count);
        return api("PUT", base + "/" + chunkName(idx), file.slice(start, end)).then(function (r) {
          if (r.status === 507) throw new Error("Your storage is full.");
          if (r.status === 413) throw new Error("The file is too large.");
          if (!r.ok) throw new Error("Upload failed. Select the file again to resume.");
          return next();
        });
      }
      return next();
    }).then(function () {
      return api("POST", base + "/finish", JSON.stringify({ dir: dir, name: file.name, total: file.size }),
        { "Content-Type": "application/json" });
    }).then(function (r) {
      if (r.status === 409) throw new Error("A folder with that name exists.");
      if (r.status === 507) throw new Error("Your storage is full.");
      if (!r.ok) throw new Error("Could not finish the upload. Select the file again to resume.");
      progress.value = 1;
    });
  }

  form.addEventListener("submit", function (ev) {
    var files = Array.prototype.slice.call(form.elements.file.files);
    if (!files.length) return;
    ev.preventDefault();
    form.elements.file.disabled = true;
    progress.hidden = false;
    var chain = Promise.resolve();
    files.forEach(function (f, k) { chain = chain.then(function () { return uploadFile(f, k + 1, files.length); }); });
    chain.then(function () { window.location.reload(); }, function (e) {
      say(e.message);
      form.elements.file.disabled = false;
    });
  });
})();
