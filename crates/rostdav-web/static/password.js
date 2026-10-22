// Adds a "show password" button to every password field. Without this script the
// fields simply stay masked. Text is only ever set with textContent/attributes.
(function () {
  "use strict";
  var NS = "http://www.w3.org/2000/svg";
  var EYE = ["M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12Z", "M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6Z"];
  var SLASH = ["M3 3l18 18"];

  function icon(paths) {
    var svg = document.createElementNS(NS, "svg");
    svg.setAttribute("class", "i");
    svg.setAttribute("viewBox", "0 0 24 24");
    svg.setAttribute("aria-hidden", "true");
    paths.forEach(function (d) {
      var p = document.createElementNS(NS, "path");
      p.setAttribute("d", d);
      svg.appendChild(p);
    });
    return svg;
  }

  Array.prototype.forEach.call(document.querySelectorAll("input[type=password]"), function (input) {
    var label = input.closest("label");
    // the button sits inside the label: keep it out of the field's accessible name
    if (label && !input.getAttribute("aria-label") && !input.getAttribute("aria-labelledby")) {
      input.setAttribute("aria-label", label.textContent.trim());
    }
    var wrap = document.createElement("span");
    wrap.className = "pw";
    input.parentNode.insertBefore(wrap, input);
    wrap.appendChild(input);

    var btn = document.createElement("button");
    btn.type = "button";
    btn.className = "pw-toggle";
    btn.setAttribute("aria-label", "Show password");
    btn.setAttribute("aria-pressed", "false");
    btn.appendChild(icon(EYE));
    wrap.appendChild(btn);

    btn.addEventListener("click", function () {
      var show = input.type === "password";
      input.type = show ? "text" : "password";
      input.setAttribute("autocapitalize", "off");
      input.setAttribute("spellcheck", "false");
      btn.setAttribute("aria-pressed", show ? "true" : "false");
      btn.replaceChildren(icon(show ? EYE.concat(SLASH) : EYE));
      input.focus();
    });
  });
})();
