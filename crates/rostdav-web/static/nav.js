// On a phone the navigation is one row that scrolls sideways; show the current page in it.
(function () {
  var nav = document.querySelector("nav.side");
  var cur = nav && nav.querySelector("a[aria-current=page]");
  if (!cur || nav.scrollWidth <= nav.clientWidth) return;
  nav.scrollLeft = cur.offsetLeft - (nav.clientWidth - cur.offsetWidth) / 2;
})();
