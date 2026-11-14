// Biometric card lab: browser side.
// Every decision (unlock, payments, approvals, attacks, fraud alerts, the ML verdict) is made
// by the Flask server; this file draws the card, runs the hold-to-scan animation and Touch ID,
// and sends what you do to the API.
(() => {
  "use strict";
  const $ = (id) => document.getElementById(id);
  const fmt = (n) => "$" + Number(n).toLocaleString("en-CA", { minimumFractionDigits: 2, maximumFractionDigits: 2 });
  const hourNow = () => new Date().getHours();
  const UNLOCK_S = 15, BIO_LOCK_S = 30, STEP_S = 120, RING = 415;
  const page = document.body.dataset.page;
  const mission = +(document.querySelector("[data-mission]")?.dataset.mission || 0);

  // ---------------------------------------------------------------- server
  async function api(path, body) {
    const opts = body === undefined ? {} : { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) };
    const r = await fetch(path, { credentials: "same-origin", ...opts });
    if (!r.ok) throw new Error(`${path}: ${r.status}`);
    return r.json();
  }
  let S = null, gotAt = 0;              // last state from the server and when it arrived
  const since = () => (performance.now() - gotAt) / 1000;
  let seenAlerts = window.LAB.seenAlerts;
  function setState(st) {
    S = st; gotAt = performance.now();
    if (st.alerts.length > seenAlerts) st.alerts.slice(0, st.alerts.length - seenAlerts).reverse().forEach((a) => toast(a.title));
    seenAlerts = st.alerts.length;
    const badge = $("navAlerts"); badge.hidden = !st.alerts.length; badge.textContent = st.alerts.length;
    for (const m of st.done) { const t = document.querySelector(`[data-tick="${m}"]`); if (t) t.textContent = "✓"; }
    if (mission && st.done.includes(mission) && $("mDone")) $("mDone").hidden = false;
    document.querySelectorAll("[data-stat]").forEach((el) => {
      const v = st.stats[el.dataset.stat]; el.textContent = el.dataset.stat === "volume" ? fmt(v) : v;
    });
    syncPush();
    if (mission === 4) drawChart();
    tick();
  }
  const refresh = () => api("/api/state").then(setState).catch(() => {});

  // ---------------------------------------------------------------- NOVA voice and toasts
  let typing;
  function say(text) {
    const el = $("nova");
    clearInterval(typing);
    if (matchMedia("(prefers-reduced-motion: reduce)").matches) { el.textContent = text; return; }
    let i = 0; el.textContent = "";
    typing = setInterval(() => { el.textContent = text.slice(0, ++i); if (i >= text.length) clearInterval(typing); }, 14);
  }
  function toast(text) {
    const t = document.createElement("div");
    t.className = "toast"; t.innerHTML = "<small>FRAUD ALERT</small><div></div>";
    t.querySelector("div").textContent = text;
    t.title = "Open the bank server";
    t.onclick = () => { location.href = window.LAB.bank; };
    $("toasts").prepend(t);
    setTimeout(() => t.remove(), 5200);
  }
  function lcd(el, kind, big, small) {
    if (!el) return;
    el.hidden = false; el.className = "lcd" + (kind ? " " + kind : "");
    el.innerHTML = '<div class="big"></div><div></div>';
    el.children[0].textContent = big; el.children[1].textContent = small;
  }

  // ---------------------------------------------------------------- clock and card display
  function tick() {
    const clock = $("clockChip");
    if (clock) clock.textContent = new Date().toLocaleTimeString("en-CA", { hour: "2-digit", minute: "2-digit", hourCycle: "h23" });
    if (!S || !$("card")) return;
    const left = S.unlock_left - since(), lock = S.bio_lock_left - since();
    const on = left > 0, blocked = lock > 0;
    $("card").classList.toggle("on", on); $("card").classList.toggle("blocked", blocked && !on);
    reactor.classList.toggle("on", on); reactor.classList.toggle("blocked", blocked && !on);
    $("cState").textContent = on ? "Chip active" : blocked ? "Sensor locked" : "Chip locked";
    if (!hold && !TID.busy) {
      const ring = $("ring");
      if (on) { ring.setAttribute("stroke", "#47F0A0"); ring.setAttribute("stroke-dasharray", `${(left / UNLOCK_S) * RING} ${RING}`);
        $("sensorBig").textContent = Math.ceil(left) + "s"; $("sensorSmall").textContent = "to tap the card"; }
      else if (blocked) { ring.setAttribute("stroke", "#FF4D5E"); ring.setAttribute("stroke-dasharray", `${(lock / BIO_LOCK_S) * RING} ${RING}`);
        $("sensorBig").textContent = "LOCKED"; $("sensorSmall").textContent = `Too many wrong fingers. ${Math.ceil(lock)}s`; }
      else { ring.setAttribute("stroke-dasharray", `0 ${RING}`); $("sensorBig").textContent = "LOCKED";
        $("sensorSmall").textContent = TID.mode === "touch" ? "Click the sensor to scan with Touch ID" : "Press and hold the sensor to scan"; }
    }
    const cvvLeft = Math.max(0, S.cvv_left - since());
    if (cvvLeft <= 0.05) { refresh(); return; }            // the code just changed on the server
    $("cvv").textContent = S.cvv;
    $("cvvBar").style.width = (cvvLeft / STEP_S) * 100 + "%";
    const s = Math.ceil(cvvLeft);
    $("cvvTimer").textContent = `CVV changes in ${Math.floor(s / 60)}:${String(s % 60).padStart(2, "0")}`;
    if (S.pending && $("pushLeft")) $("pushLeft").textContent = `Expires in ${Math.max(0, Math.ceil(S.pending.left - since()))}s.`;
  }

  // ---------------------------------------------------------------- fingerprint sensor
  const reactor = $("reactor") || document.createElement("button");
  const TID = { available: false, mode: "sim", credId: null, busy: false };
  let finger = "owner", hold = null;

  function startScan(onDone) {
    if (hold) return;
    const t0 = performance.now();
    reactor.classList.add("scanning");
    hold = { onDone, raf: 0 };
    const step = (now) => {
      const p = Math.min(1, (now - t0) / 1100);
      $("ring").setAttribute("stroke-dasharray", `${p * RING} ${RING}`); $("ring").setAttribute("stroke", "#F2B63D");
      $("sensorBig").textContent = "SCANNING"; $("sensorSmall").textContent = "Keep holding";
      if (p >= 1) { const cb = hold.onDone; endScan(); cb(finger === "owner"); return; }
      hold.raf = requestAnimationFrame(step);
    };
    hold.raf = requestAnimationFrame(step);
  }
  function endScan(cancelled) {
    if (!hold) return;
    cancelAnimationFrame(hold.raf); hold = null; reactor.classList.remove("scanning");
    if (cancelled) say("Scan cancelled. Hold your finger on the sensor until the ring fills.");
    tick();
  }
  async function cardScan(ok) {
    const body = TID.mode === "touch" ? { touch_id_match: ok } : { finger: ok ? "owner" : "thief" };
    const res = await api("/api/scan", body);
    say(TID.mode === "touch" && res.result.result === "fail" ? res.result.message.replace("Fingerprint rejected. That isn't the owner.", "Touch ID didn't confirm the owner.") : res.result.message);
    setState(res.state);
  }

  // real Touch ID through WebAuthn passkeys: macOS checks the fingerprint, the page only gets yes or no
  const randBytes = (n) => crypto.getRandomValues(new Uint8Array(n));
  const toB64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)));
  const fromB64 = (str) => Uint8Array.from(atob(str), (c) => c.charCodeAt(0));
  try { const saved = localStorage.getItem("cardlab-passkey"); if (saved) TID.credId = fromB64(saved); } catch {}
  const embedded = (() => { try { return window.self !== window.top; } catch { return true; } })();
  const policyBlocks = !!(document.featurePolicy && !document.featurePolicy.allowsFeature("publickey-credentials-get"));
  if ($("reactor")) {
    if (embedded || policyBlocks) $("tidNote").hidden = false;
    else if (window.PublicKeyCredential?.isUserVerifyingPlatformAuthenticatorAvailable) {
      PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable().then((ok) => { TID.available = ok; if (ok) setMode("touch"); }).catch(() => {});
    }
  }
  async function touchId() {
    const started = performance.now();
    try {
      if (!TID.credId) {
        const cred = await navigator.credentials.create({ publicKey: {
          challenge: randBytes(32), rp: { name: "Biometric Card Lab" },
          user: { id: randBytes(16), name: "cardholder", displayName: "Card owner" },
          pubKeyCredParams: [{ type: "public-key", alg: -7 }, { type: "public-key", alg: -257 }],
          authenticatorSelection: { authenticatorAttachment: "platform", userVerification: "required", residentKey: "discouraged" },
          timeout: 60000, attestation: "none" } });
        TID.credId = new Uint8Array(cred.rawId);
        try { localStorage.setItem("cardlab-passkey", toB64(cred.rawId)); } catch {}
        return "match";
      }
      await navigator.credentials.get({ publicKey: { challenge: randBytes(32), allowCredentials: [{ type: "public-key", id: TID.credId }], userVerification: "required", timeout: 60000 } });
      return "match";
    } catch (e) {
      if (e && e.name === "NotAllowedError" && performance.now() - started > 600) return "fail";
      return "unavailable";
    }
  }
  async function runTouch(handler) {
    if (TID.busy) return;
    TID.busy = true; reactor.classList.add("scanning");
    $("sensorBig").textContent = "TOUCH ID"; $("sensorSmall").textContent = "Touch the Touch ID key on your Mac";
    say(TID.credId ? "Touch ID requested. Put your finger on the key." : "First scan: your Mac will enrol your fingerprint for this page.");
    const result = await touchId();
    TID.busy = false; reactor.classList.remove("scanning");
    if (result === "unavailable") {
      setMode("sim"); $("tidNote").hidden = false;
      say("Touch ID was blocked here, so the sensor switched to simulation."); tick(); return;
    }
    handler(result === "match");
  }
  function setMode(m) {
    TID.mode = m === "touch" && TID.available ? "touch" : "sim";
    const real = TID.mode === "touch";
    $("modeRow").hidden = !TID.available; $("fingerRow").hidden = real;
    $("mTouch").setAttribute("aria-pressed", real); $("mSim").setAttribute("aria-pressed", !real);
    reactor.setAttribute("aria-label", real ? "Fingerprint sensor. Click to scan with Touch ID." : "Fingerprint sensor. Press and hold to scan.");
    tick();
  }
  function bindHold(el, handler) {
    el.addEventListener("click", () => { if (TID.mode === "touch") runTouch(handler); });
    el.addEventListener("pointerdown", (e) => { if (TID.mode === "touch") return; e.preventDefault(); el.setPointerCapture?.(e.pointerId); startScan(handler); });
    ["pointerup", "pointercancel", "pointerleave"].forEach((ev) => el.addEventListener(ev, () => endScan(true)));
    el.addEventListener("keydown", (e) => { if (TID.mode === "touch") return; if ((e.key === " " || e.key === "Enter") && !e.repeat) { e.preventDefault(); startScan(handler); } });
    el.addEventListener("keyup", (e) => { if (TID.mode === "touch") return; if (e.key === " " || e.key === "Enter") endScan(true); });
  }
  if ($("reactor")) {
    bindHold(reactor, cardScan);
    $("mTouch").onclick = () => { setMode("touch"); say("Real Touch ID on. Click the sensor and use your own finger."); };
    $("mSim").onclick = () => { setMode("sim"); say("Simulated sensor on. Press and hold, and pick whose finger it is."); };
    const setFinger = (f) => { finger = f; $("fOwner").setAttribute("aria-pressed", f === "owner"); $("fThief").setAttribute("aria-pressed", f !== "owner");
      say(f === "owner" ? "Owner's finger selected." : "Stranger's finger selected. Try unlocking the card now."); };
    $("fOwner").onclick = () => setFinger("owner");
    $("fThief").onclick = () => setFinger("thief");
  }

  // ---------------------------------------------------------------- mission 01: in store
  if ($("tapBtn")) $("tapBtn").onclick = async () => {
    const amount = parseFloat($("posAmt").value);
    if (!(amount > 0)) { say("Enter an amount first."); return; }
    const res = await api("/api/tap", { amount, hour: hourNow() });
    const e = res.entry;
    if (e.ok) { lcd($("lcd"), "", `APPROVED ${fmt(e.amount)}`, "Fingerprint verified on the card."); say("Approved. The fingerprint never left the card. The terminal only saw a working chip."); }
    else { lcd($("lcd"), "bad", "DECLINED", "Card chip locked. Fingerprint required."); say("Declined. Without the owner's fingerprint the chip won't pay, so a stolen card is useless here."); }
    setState(res.state);
  };

  // ---------------------------------------------------------------- mission 02: online + approval
  function askNotify() { try { if ("Notification" in window && Notification.permission === "default") Notification.requestPermission(); } catch {} }
  let note = null, pushShown = false;
  function notifyLaptop(amount) {
    try {
      if (!("Notification" in window) || Notification.permission !== "granted") return;
      note = new Notification("NOVA BANK: approve this purchase?", { body: `${fmt(amount)} at Northwind Electronics, card ending 1111. If this wasn't you, deny it.`, requireInteraction: true, tag: "cardlab-approval" });
      note.onclick = () => { window.focus(); note.close(); };
    } catch {}
  }
  function syncPush() {
    if (!$("pushBox")) return;
    if (S.pending && !pushShown) showPush(S.pending.amount);
    if (!S.pending && pushShown) {                     // the server timed it out
      pushShown = false; $("pushBox").innerHTML = ""; try { note && note.close(); } catch {}
      const e = S.ledger[0];
      if (e && /No answer/.test(e.reason)) { lcd($("shopLcd"), "bad", "DECLINED", "No answer within 60 seconds."); say("Nobody approved it in time, so the bank declined it."); }
    }
  }
  function showPush(amount) {
    pushShown = true;
    const box = $("pushBox");
    box.innerHTML = `<div class="push" role="dialog" aria-label="Approve purchase"><div class="who">NOVA BANK: APPROVE THIS PURCHASE?</div>
      <div class="amt num">${fmt(amount)}</div><p>Northwind Electronics, card ending 1111. <span id="pushLeft" class="num"></span></p>
      <div class="row"><button class="btn" id="pushDeny">Deny</button><button class="btn gold hold" id="pushOk"><span class="fill" id="pushFill"></span>${TID.mode === "touch" ? "Approve with Touch ID" : "Hold to approve with fingerprint"}</button></div></div>`;
    $("pushDeny").onclick = () => finishPush("deny");
    const okBtn = $("pushOk");
    if (TID.mode === "touch") { okBtn.onclick = () => runTouch((ok) => finishPush(ok ? "approve" : "badfinger")); return; }
    let t0 = 0, raf = 0;
    const stop = () => { cancelAnimationFrame(raf); raf = 0; if ($("pushFill")) $("pushFill").style.width = "0"; };
    const go = (e) => { e?.preventDefault?.(); if (raf) return; t0 = performance.now();
      const loop = (now) => { const p = Math.min(1, (now - t0) / 900); $("pushFill").style.width = p * 100 + "%";
        if (p >= 1) { raf = 0; finishPush(finger === "owner" ? "approve" : "badfinger"); return; } raf = requestAnimationFrame(loop); };
      raf = requestAnimationFrame(loop); };
    okBtn.addEventListener("pointerdown", go);
    ["pointerup", "pointerleave", "pointercancel"].forEach((ev) => okBtn.addEventListener(ev, stop));
    okBtn.addEventListener("keydown", (e) => { if ((e.key === " " || e.key === "Enter") && !e.repeat) go(e); });
    okBtn.addEventListener("keyup", stop);
  }
  async function finishPush(decision) {
    pushShown = false; $("pushBox").innerHTML = ""; try { note && note.close(); } catch {}
    const res = await api("/api/approve", { decision });
    const e = res.entry;
    if (!e) { setState(res.state); return; }
    if (decision === "approve") { lcd($("shopLcd"), "", `APPROVED ${fmt(e.amount)}`, "Code valid and approved by the owner."); say("Approved. Two locks opened: the live code and the owner's fingerprint."); }
    else if (decision === "badfinger") { lcd($("shopLcd"), "bad", "DECLINED", "Approval needs the owner's fingerprint."); say("Declined. Someone tapped approve, but it wasn't the owner's finger."); }
    else { lcd($("shopLcd"), "bad", "DECLINED", "The owner didn't recognise this purchase."); say("Denied. The bank logs it as fraud. A thief with the code still couldn't get past the owner."); }
    setState(res.state);
  }
  if ($("payBtn")) {
    $("readCvv").onclick = () => { if (S) { $("coCvv").value = S.cvv; say("Code copied from the card's screen. Pay before it changes."); } };
    $("payBtn").onclick = async () => {
      askNotify();
      const res = await api("/api/pay", { pan: $("coPan").value, cvv: $("coCvv").value.trim(), amount: parseFloat($("coAmt").value), hour: hourNow() });
      if (res.status === "pending") {
        lcd($("shopLcd"), "wait", "WAITING", res.message);
        say("The code checks out. Now the bank asks the owner to approve this exact purchase.");
        setState(res.state); notifyLaptop(res.state.pending.amount); return;
      }
      if (res.status === "busy") say(res.message);
      else if (res.status === "invalid") lcd($("shopLcd"), "bad", res.message === "The CVV is 3 digits." ? "CHECK CVV" : "DECLINED", res.message);
      else { lcd($("shopLcd"), "bad", res.message.startsWith("Too many wrong codes") ? "BLOCKED" : "DECLINED", res.message);
        say(res.stale ? "Declined. That code expired, so whoever has it is using stolen data." : "Declined. " + res.message); }
      setState(res.state);
    };
  }

  // ---------------------------------------------------------------- mission 03: attacks
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  document.querySelectorAll("[data-attack]").forEach((b) => b.onclick = async () => {
    const kind = b.dataset.attack;
    document.querySelectorAll("[data-attack]").forEach((x) => (x.disabled = true));
    try {
      if (kind === "replay") {
        say("Attacker replays leaked card details captured 4 minutes ago..."); await sleep(700);
        const res = await api("/api/attack/replay", { hour: hourNow() });
        lcd($("atkLcd"), "bad", "DECLINED", `Old CVV ${res.code}: ${res.message}`);
        say("Blocked. The stolen code expired, and the bank flagged the card as leaked."); setState(res.state);
      } else if (kind === "testing") {
        say("A thief has the card but not the owner's finger. Tapping three times..."); await sleep(700);
        const res = await api("/api/attack/testing", { hour: hourNow() });
        lcd($("atkLcd"), "bad", `${res.entries.length} x DECLINED`, "Every tap failed. The pattern triggered an alert.");
        say("All three taps declined, and the monitor spotted the burst."); setState(res.state);
      } else {
        say("A bot starts guessing codes..."); await sleep(700);
        const res = await api("/api/attack/guess", { hour: hourNow() });
        lcd($("atkLcd"), "bad", "3 WRONG GUESSES", res.tries.map((t) => t.code).join(", ") + ": " + res.tries[res.tries.length - 1].message);
        say("Three misses and online payments pause for a minute. Guessing 1,000 codes is now impossible."); setState(res.state);
      }
    } finally { document.querySelectorAll("[data-attack]").forEach((x) => (x.disabled = false)); }
  });

  // ---------------------------------------------------------------- mission 04: fraud AI
  let HISTORY = [], plotPts = [], judgeTimer = 0, judgeSeq = 0;
  const ai = { amount: 42.5, hour: 12, online: false };
  const sliderToAmt = (v) => Math.round(5 * Math.pow(2000 / 5, v / 1000) * 100) / 100;
  const amtToSlider = (a) => Math.round((1000 * Math.log(a / 5)) / Math.log(2000 / 5));
  async function judge(preset) {
    const seq = ++judgeSeq;
    const j = await api("/api/judge", { amount: ai.amount, at_hour: ai.hour, online: ai.online, preset: !!preset });
    if (seq !== judgeSeq) return j;                     // a newer slider move is on its way
    $("vZ").textContent = j.z.toFixed(2); $("vZ").className = "num " + (j.outlier ? "bad" : "ok");
    $("vL").textContent = j.lof.toFixed(2); $("vL").className = "num " + (j.pattern ? "bad" : "ok");
    $("vLt").textContent = "flags above " + j.lof_limit.toFixed(2);
    $("vOut").textContent = j.flagged ? "FLAGGED" : "LOOKS NORMAL"; $("vOut").className = j.flagged ? "bad" : "ok";
    $("vWhy").textContent = j.outlier ? "Amount is far outside normal spending" : j.pattern ? "Amount, time and channel don't match the owner" : "Fits the owner's usual spending";
    if (preset) refresh();
    return j;
  }
  function updateAI(now) {
    $("aiAmtV").textContent = fmt(ai.amount); $("aiHourV").textContent = String(ai.hour).padStart(2, "0") + ":00";
    drawChart();
    clearTimeout(judgeTimer);
    if (now) judge(); else judgeTimer = setTimeout(judge, 120);
  }
  function setAI(a, h, on) {
    ai.amount = a; ai.hour = h; ai.online = on;
    $("aiAmt").value = amtToSlider(a); $("aiHour").value = h;
    $("chStore").setAttribute("aria-pressed", !on); $("chOnline").setAttribute("aria-pressed", on);
  }
  const cv = $("chart"), ctx = cv?.getContext("2d");
  function drawChart() {
    if (!cv) return;
    const dpr = Math.min(2, window.devicePixelRatio || 1), W = cv.clientWidth, H = cv.clientHeight;
    if (!W) return;
    cv.width = W * dpr; cv.height = H * dpr; ctx.setTransform(dpr, 0, 0, dpr, 0, 0); ctx.clearRect(0, 0, W, H);
    const L = 52, R = 14, T = 14, B = 34;
    const x = (h) => L + ((h + 0.5) / 24) * (W - L - R);
    const lo = Math.log(4), hi = Math.log(2500);
    const y = (a) => T + (1 - (Math.log(Math.max(4, Math.min(2500, a))) - lo) / (hi - lo)) * (H - T - B);
    ctx.font = "11px 'JetBrains Mono', monospace"; ctx.textBaseline = "middle";
    for (const v of [5, 10, 25, 50, 100, 250, 500, 1000, 2000]) {
      ctx.strokeStyle = "rgba(94,231,255,.08)"; ctx.beginPath(); ctx.moveTo(L, y(v)); ctx.lineTo(W - R, y(v)); ctx.stroke();
      ctx.fillStyle = "#80A4B4"; ctx.textAlign = "right"; ctx.fillText(v >= 1000 ? `$${v / 1000}k` : `$${v}`, L - 8, y(v));
    }
    ctx.textAlign = "center";
    for (let h = 0; h <= 21; h += 3) ctx.fillText(String(h).padStart(2, "0") + ":00", x(h), H - 14);
    ctx.fillStyle = "rgba(255,200,87,.05)"; ctx.fillRect(x(-0.5), T, x(6.5) - x(-0.5), H - T - B);
    plotPts = [];
    for (const p of HISTORY) {
      const px = x(p.hour) + ((p.amount * 97) % 1 - 0.5) * 14, py = y(p.amount);
      ctx.fillStyle = "rgba(94,231,255,.38)"; ctx.beginPath(); ctx.arc(px, py, 2.6, 0, 7); ctx.fill();
      plotPts.push({ px, py, label: `Past ${p.online ? "online" : "in-store"}: ${fmt(p.amount)} at ${p.hour}:00` });
    }
    for (const e of S?.ledger || []) {
      const px = x(e.hour), py = y(e.amount);
      if (e.ok) { ctx.fillStyle = "#47F0A0"; ctx.beginPath(); ctx.arc(px, py, 6, 0, 7); ctx.fill(); }
      else { ctx.strokeStyle = "#FF4D5E"; ctx.lineWidth = 2.5; ctx.beginPath(); ctx.moveTo(px - 5, py - 5); ctx.lineTo(px + 5, py + 5); ctx.moveTo(px + 5, py - 5); ctx.lineTo(px - 5, py + 5); ctx.stroke(); }
      plotPts.push({ px, py, label: `Today ${e.channel}: ${fmt(e.amount)}, ${e.ok ? "approved" : "declined"}` });
    }
    const px = x(ai.hour), py = y(ai.amount);
    ctx.strokeStyle = "rgba(242,182,61,.45)"; ctx.lineWidth = 1; ctx.setLineDash([4, 4]);
    ctx.beginPath(); ctx.moveTo(px, T); ctx.lineTo(px, H - B); ctx.moveTo(L, py); ctx.lineTo(W - R, py); ctx.stroke(); ctx.setLineDash([]);
    ctx.save(); ctx.translate(px, py); ctx.rotate(Math.PI / 4); ctx.fillStyle = "#F2B63D"; ctx.fillRect(-7, -7, 14, 14); ctx.restore();
    ctx.strokeStyle = "#F2B63D"; ctx.lineWidth = 1.5; ctx.beginPath(); ctx.arc(px, py, 15, 0, 7); ctx.stroke();
    plotPts.push({ px, py, label: `Testing: ${fmt(ai.amount)} at ${ai.hour}:00, ${ai.online ? "online" : "in store"}` });
  }
  if (cv) {
    cv.addEventListener("mousemove", (e) => {
      const r = cv.getBoundingClientRect(), mx = e.clientX - r.left, my = e.clientY - r.top;
      let best = null, bd = 12;
      for (const p of plotPts) { const d = Math.hypot(p.px - mx, p.py - my); if (d < bd) { bd = d; best = p; } }
      const tip = $("tip");
      if (!best) { tip.hidden = true; return; }
      tip.hidden = false; tip.textContent = best.label;
      tip.style.left = Math.min(best.px + 12, r.width - tip.offsetWidth - 6) + "px"; tip.style.top = Math.max(4, best.py - 34) + "px";
    });
    cv.addEventListener("mouseleave", () => ($("tip").hidden = true));
    addEventListener("resize", drawChart);
    $("aiAmt").oninput = (e) => { ai.amount = sliderToAmt(+e.target.value); updateAI(); };
    $("aiHour").oninput = (e) => { ai.hour = +e.target.value; updateAI(); };
    $("chStore").onclick = () => { setAI(ai.amount, ai.hour, false); updateAI(true); };
    $("chOnline").onclick = () => { setAI(ai.amount, ai.hour, true); updateAI(true); };
    document.querySelectorAll("[data-preset]").forEach((b) => b.onclick = async () => {
      const [a, h, on] = b.dataset.preset.split(",").map(Number);
      setAI(a, h, !!on); $("aiAmtV").textContent = fmt(a); $("aiHourV").textContent = String(h).padStart(2, "0") + ":00"; drawChart();
      clearTimeout(judgeTimer);
      const j = await judge(true);
      say(j.flagged ? "Flagged. That purchase doesn't look like the owner." : "Looks normal. That's how the owner usually spends.");
    });
    api("/api/history").then((h) => { HISTORY = h; setAI(42.5, 12, false); updateAI(true); });
  }

  // ---------------------------------------------------------------- bank page: local times
  document.querySelectorAll("time[data-t]").forEach((el) => {
    el.textContent = new Date(el.dataset.t * 1000).toLocaleTimeString("en-CA", { hour: "2-digit", minute: "2-digit", second: "2-digit", hourCycle: "h23" });
  });

  // ---------------------------------------------------------------- start
  refresh();
  setInterval(tick, 250);
  setInterval(refresh, mission ? 2000 : 5000);
})();
