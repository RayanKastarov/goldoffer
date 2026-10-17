"use strict";
const $ = id => document.getElementById(id);
const token = new URLSearchParams(location.search).get("token") || "";
history.replaceState(null, "", location.pathname); // remove the token from the address bar and browser history
const form = $("resetForm"), msg = $("msg"), pw = $("pw"), pw2 = $("pw2"), btn = $("submitBtn");
function show(text, ok) { msg.textContent = text; msg.className = "msg " + (ok ? "ok" : "bad"); msg.hidden = !text; }
if (!/^[\w-]+\.[\w-]+\.[\w-]+$/.test(token)) {
  form.hidden = true; $("intro").hidden = true;
  show("This reset link is missing or damaged. Go back and use “Forgot password?” to get a new one.", false);
  $("backLink").textContent = "← Back to TitanCDN";
}

// Eye button at the end of each password field
document.querySelectorAll(".pw-eye").forEach(function (b) {
  b.addEventListener("click", function () {
    const input = b.parentElement.querySelector("input"), on = input.type === "password";
    input.type = on ? "text" : "password";
    b.setAttribute("aria-pressed", String(on));
    b.setAttribute("aria-label", on ? "Hide password" : "Show password");
    input.focus({ preventScroll: true });
  });
});

// Live strength meter and checklist
const LEVELS = ["", "Too short", "Okay", "Good", "Strong"];
function level(p) {
  if (!p) return 0;
  if (p.length < 12) return 1;
  const kinds = [/[a-z]/, /[A-Z]/, /\d/, /[^A-Za-z0-9]/].filter(function (r) { return r.test(p); }).length;
  return Math.min(4, 2 + (p.length >= 16 ? 1 : 0) + (kinds >= 3 ? 1 : 0));
}
function update() {
  const a = pw.value, b = pw2.value, lv = level(a);
  $("meter").dataset.level = lv;
  $("meterLabel").textContent = LEVELS[lv];
  const lenOk = a.length >= 12 && a.length <= 128, matchOk = !!b && a === b;
  $("ruleLen").classList.toggle("ok", lenOk);
  $("ruleMatch").classList.toggle("ok", matchOk);
  btn.disabled = !(lenOk && matchOk);
}
pw.addEventListener("input", update); pw2.addEventListener("input", update); update();

form.addEventListener("submit", async function (e) {
  e.preventDefault();
  const a = pw.value, b = pw2.value;
  if (a.length < 12) return show("Password must be at least 12 characters.", false);
  if (a.length > 128) return show("Password must be at most 128 characters.", false);
  if (a !== b) return show("The two passwords do not match.", false);
  btn.disabled = true; btn.classList.add("busy"); show("Saving your new password...", true);
  try {
    const r = await fetch("/api/auth/reset-password", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ token: token, password: a }) });
    let d = {}; try { d = await r.json(); } catch (_) { d = {}; }
    if (!r.ok) throw new Error(d.error || ("HTTP " + r.status));
    pw.value = ""; pw2.value = "";
    form.hidden = true; $("intro").hidden = true; msg.hidden = true; $("backLink").hidden = true;
    $("done").hidden = false;
    let left = 6;
    const tick = setInterval(function () {
      left -= 1; $("count").textContent = String(left);
      if (left <= 0) { clearInterval(tick); location.href = "/?reset=1"; }
    }, 1000);
  } catch (err) { show(err.message, false); btn.classList.remove("busy"); update(); }
});