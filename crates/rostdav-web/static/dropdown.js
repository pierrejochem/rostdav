// The menus of the page (account, new folder, upload, add user) are <details class="pop">.
// Browsers keep a <details> open until its summary is clicked again; menus are expected to close
// when you click elsewhere, press Esc, move on with Tab, or open another menu.
(function () {
  function open() { return document.querySelectorAll("details.pop[open]"); }
  function closeAll(except) {
    open().forEach(function (d) { if (d !== except) d.removeAttribute("open"); });
  }
  // a click (or tap) outside every open menu closes them; so does opening another one
  document.addEventListener("click", function (e) {
    var inside = e.target.closest ? e.target.closest("details.pop") : null;
    closeAll(inside);
  });
  document.addEventListener("toggle", function (e) {
    if (e.target.matches && e.target.matches("details.pop") && e.target.open) closeAll(e.target);
  }, true);
  // Esc closes the menu and puts the focus back on its button
  document.addEventListener("keydown", function (e) {
    if (e.key !== "Escape") return;
    var o = open();
    if (!o.length) return;
    var first = o[0].querySelector("summary");
    closeAll(null);
    if (first) first.focus();
  });
  // Tab (or a click on something unfocusable) moving the focus out of a menu closes it
  document.addEventListener("focusin", function (e) {
    var inside = e.target.closest ? e.target.closest("details.pop") : null;
    closeAll(inside);
  });
})();
