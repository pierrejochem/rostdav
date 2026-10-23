// Profile picture: pick or drop any picture; it is cropped to a square, shrunk and re-encoded
// here in the browser so that it fits what the server stores (at most 256 KiB, 16 to 1024
// pixels). Without this script the plain form still works for small PNG and JPEG files.
// Text is only ever set with textContent.
(function () {
  "use strict";
  var zone = document.getElementById("avatar-zone");
  var form = document.getElementById("avatar-form");
  if (!zone || !form || !window.createImageBitmap || !window.DataTransfer || !window.File) return;
  var DE = {
    "This file is not a picture your browser can read.": "Diese Datei ist kein Bild, das dein Browser lesen kann.",
    "The picture is too large (over 40 MB).": "Das Bild ist zu groß (über 40 MB).",
    "Could not shrink the picture enough.": "Das Bild konnte nicht genug verkleinert werden.",
    "Ready: the picture was cropped to a square and shrunk to": "Fertig: das Bild wurde quadratisch zugeschnitten und verkleinert auf",
    "pixels,": "Pixel,"
  };
  var de = document.documentElement.lang === "de";
  function _(s) { return de && DE[s] ? DE[s] : s; }
  var input = form.elements.file;
  var preview = document.getElementById("avatar-preview");
  var msg = document.getElementById("avatar-msg");
  var save = document.getElementById("avatar-save");
  var MAX_ORIGINAL = 40 * 1024 * 1024; // what we are willing to read in the browser
  var MAX_STORED = 240 * 1024;         // below the server's 256 KiB
  var SIZES = [512, 384, 256, 128];
  var busy = false;

  function say(text, bad) {
    msg.textContent = text;
    msg.className = bad ? "err" : "muted";
  }

  // The part of the picture that is kept: a centred square.
  function drawSquare(bmp, size, flat) {
    var c = document.createElement("canvas");
    c.width = c.height = size;
    var g = c.getContext("2d");
    if (flat) { g.fillStyle = "#fff"; g.fillRect(0, 0, size, size); }
    var side = Math.min(bmp.width, bmp.height);
    g.imageSmoothingQuality = "high";
    g.drawImage(bmp, (bmp.width - side) / 2, (bmp.height - side) / 2, side, side, 0, 0, size, size);
    return c;
  }

  function toBlob(canvas, type, quality) {
    return new Promise(function (res) { canvas.toBlob(res, type, quality); });
  }

  // First size and quality that fits. PNG (keeps transparency) is tried first for pictures that
  // came as PNG, everything else goes straight to JPEG.
  function encode(bmp, wasPng) {
    var plan = [];
    SIZES.forEach(function (s) {
      var size = Math.min(s, Math.min(bmp.width, bmp.height));
      if (wasPng) plan.push({ size: size, type: "image/png" });
      [0.9, 0.8, 0.7, 0.55].forEach(function (q) { plan.push({ size: size, type: "image/jpeg", q: q }); });
    });
    var i = 0;
    function next() {
      if (i >= plan.length) return Promise.resolve(null);
      var p = plan[i++];
      var c = drawSquare(bmp, Math.max(16, p.size), p.type === "image/jpeg");
      return toBlob(c, p.type, p.q).then(function (b) {
        if (b && b.type === p.type && b.size <= MAX_STORED) return { blob: b, canvas: c, size: Math.max(16, p.size) };
        return next();
      });
    }
    return next();
  }

  function showPreview(canvas) {
    preview.width = preview.height = 96;
    var g = preview.getContext("2d");
    g.clearRect(0, 0, 96, 96);
    g.drawImage(canvas, 0, 0, 96, 96);
    preview.hidden = false;
  }

  function pick(file) {
    if (!file || busy) return;
    if (file.size > MAX_ORIGINAL) { say(_("The picture is too large (over 40 MB)."), true); return; }
    busy = true;
    save.disabled = true;
    createImageBitmap(file).then(function (bmp) {
      return encode(bmp, file.type === "image/png").then(function (r) {
        if (bmp.close) bmp.close();
        if (!r) { say(_("Could not shrink the picture enough."), true); return; }
        var name = r.blob.type === "image/png" ? "avatar.png" : "avatar.jpg";
        var dt = new DataTransfer();
        dt.items.add(new File([r.blob], name, { type: r.blob.type }));
        input.files = dt.files;
        showPreview(r.canvas);
        say(_("Ready: the picture was cropped to a square and shrunk to") + " " + r.size + "×" + r.size + " " + _("pixels,") + " " + Math.round(r.blob.size / 1024) + " KiB.");
        save.disabled = false;
      });
    }).catch(function () {
      say(_("This file is not a picture your browser can read."), true);
    }).then(function () { busy = false; });
  }

  // The input covers the whole zone, so a drop on it fills it natively; this handles the change.
  input.removeAttribute("required"); // a picture is checked below; the raw file may be too large
  input.addEventListener("change", function () {
    // setting `input.files` below does not fire this event again
    pick(input.files && input.files[0]);
  });
  ["dragenter", "dragover"].forEach(function (t) {
    zone.addEventListener(t, function () { zone.classList.add("over"); });
  });
  ["dragleave", "drop"].forEach(function (t) {
    zone.addEventListener(t, function () { zone.classList.remove("over"); });
  });
  form.addEventListener("submit", function (ev) {
    var f = input.files && input.files[0];
    if (!f || busy) ev.preventDefault();
  });
  save.disabled = true;
})();
