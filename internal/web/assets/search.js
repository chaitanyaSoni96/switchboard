// Client-side filter over the rendered cards. Filtering never asks the server
// for anything: the cards the browser already has are the only cards it is
// allowed to see, so narrowing them is purely a display concern.
(function () {
  const input = document.getElementById("search");
  const root = document.getElementById("services");
  if (!input || !root) return;

  function apply() {
    const q = input.value.trim().toLowerCase();
    let shown = 0;
    const cards = root.querySelectorAll(".card");
    cards.forEach(function (card) {
      const hit = q === "" || (card.dataset.search || "").indexOf(q) !== -1;
      card.classList.toggle("is-hidden", !hit);
      if (hit) shown++;
    });

    // A section with nothing left in it goes away with its cards, rather than
    // leaving a heading over empty space.
    root.querySelectorAll("section[data-section]").forEach(function (sec) {
      const total = sec.querySelectorAll(".card").length;
      const visible = sec.querySelectorAll(".card:not(.is-hidden)").length;
      sec.classList.toggle("is-hidden", q !== "" && total > 0 && visible === 0);
    });

    const note = document.getElementById("filter-note");
    if (note) note.textContent = q === "" ? "" : shown + "/" + cards.length + " match";
  }

  input.addEventListener("input", apply);
  // Any refresh replaces the grid wholesale; re-filter the new nodes.
  document.body.addEventListener("htmx:afterSwap", apply);
  apply();
})();
