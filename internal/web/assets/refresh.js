// Auto-refresh control.
//
// Switchboard has no background scanner: it does work only when something asks
// it to. That makes the refresh cadence a property of the page, not the server,
// so it lives here and defaults to off — an open tab costs nothing until you
// choose otherwise.
(function () {
  var KEY = "switchboard:refresh-interval";
  var root = document.getElementById("services");
  var sel = document.getElementById("interval");
  var now = document.getElementById("refresh-now");
  if (!root) return;

  var timer = null;
  var wasHidden = false;

  function refresh() {
    if (window.htmx) window.htmx.trigger(root, "sb:refresh");
  }

  function seconds() {
    return sel ? Number(sel.value) || 0 : 0;
  }

  function disarm() {
    if (timer !== null) {
      clearInterval(timer);
      timer = null;
    }
  }

  function arm() {
    disarm();
    var s = seconds();
    if (sel) {
      // An armed interval is worth seeing at a glance.
      sel.classList.toggle("text-accent", s > 0);
      sel.classList.toggle("text-muted", s === 0);
    }
    // A hidden tab is nobody looking, so it gets no timer at all. Returning to
    // it refreshes once, which is what you actually wanted from those ticks.
    if (s > 0 && !document.hidden) timer = setInterval(refresh, s * 1000);
  }

  var saved = 0;
  try {
    saved = parseInt(window.localStorage.getItem(KEY), 10) || 0;
  } catch (e) {
    // Storage can be unavailable (private mode, blocked cookies); the default
    // of "off" is a fine answer and not worth failing the page over.
  }
  if (sel && saved > 0) {
    for (var i = 0; i < sel.options.length; i++) {
      if (Number(sel.options[i].value) === saved) {
        sel.value = String(saved);
        break;
      }
    }
  }
  arm();

  if (sel) {
    sel.addEventListener("change", function () {
      try {
        window.localStorage.setItem(KEY, String(seconds()));
      } catch (e) {
        // Not persisting the choice is survivable; applying it is not.
      }
      arm();
    });
  }

  if (now) {
    now.addEventListener("click", function () {
      refresh();
    });
  }

  document.addEventListener("visibilitychange", function () {
    if (document.hidden) {
      disarm();
      wasHidden = true;
      return;
    }
    // Coming back to a tab that has been away: whatever is on screen is stale,
    // so catch up once regardless of whether auto-refresh is on.
    if (wasHidden) {
      wasHidden = false;
      refresh();
    }
    arm();
  });
})();
