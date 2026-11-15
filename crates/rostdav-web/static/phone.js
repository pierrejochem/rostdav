// Sign-in with the RustMFA phone: asks the server every two seconds whether the phone has
// answered. <div data-status-url="…" data-finish-form="id" data-back-url="…"> marks the waiting area. When the
// answer is "approved" the page submits the finish form; when it was denied or has expired the
// page goes back to the second step. Without this script the form's button does the same.
(function () {
  "use strict";
  var box = document.querySelector("[data-status-url]");
  if (!box || !window.fetch) return;
  var url = box.getAttribute("data-status-url");
  var form = document.getElementById(box.getAttribute("data-finish-form"));
  var back = box.getAttribute("data-back-url") || "/login/2fa";
  var done = false;
  function poll() {
    if (done) return;
    fetch(url, { credentials: "same-origin", cache: "no-store" })
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (j) {
        if (!j || done) return;
        if (j.status === "approved") { done = true; if (form) form.submit(); }
        else if (j.status === "denied" || j.status === "expired") { done = true; location.href = back; }
      })
      .catch(function () {});
  }
  setInterval(poll, 2000);
})();
