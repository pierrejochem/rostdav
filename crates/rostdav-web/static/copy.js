// "Copy" buttons: <button data-copy="id"> copies the text of the element with that id.
// The buttons start hidden and only appear when the browser can copy.
(function () {
  "use strict";
  // texts: English is the key, German in the table (page language from <html lang>)
  var DE = {
    "Copied": "Kopiert"
  };
  var de = document.documentElement.lang === "de";
  function _(s) { return de && DE[s] ? DE[s] : s; }
  if (!navigator.clipboard) return;
  Array.prototype.forEach.call(document.querySelectorAll("button[data-copy]"), function (btn) {
    var src = document.getElementById(btn.getAttribute("data-copy"));
    if (!src) return;
    btn.hidden = false;
    btn.addEventListener("click", function () {
      navigator.clipboard.writeText(src.textContent).then(function () {
        var old = btn.textContent;
        btn.textContent = _("Copied");
        setTimeout(function () { btn.textContent = old; }, 1500);
      });
    });
  });
})();
