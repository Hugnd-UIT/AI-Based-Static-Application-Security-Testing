window.openDemo = function () {
  if (document.body.classList.contains("page-loading")) return !1;
  var m = document.getElementById("demoModal");
  if (m) {
    m.classList.add("open");
    document.body.style.overflow = "hidden";
  }

  return !1;
};

(function () {
  document.addEventListener(
    "click",
    function (e) {
      var trigger = e.target.closest(".js-open-demo, .js-open-contact");
      if (trigger) {
        e.preventDefault();
        window.openDemo();
        return;
      }
    },
    !0,
  );
})();
document.addEventListener("DOMContentLoaded", function () {
  document.querySelectorAll("img[data-lazy-src]").forEach(function (img) {
    img.src = img.getAttribute("data-lazy-src");
    img.removeAttribute("data-lazy-src");
  });
});
window.addEventListener("load", function () {
  document.body.classList.remove("page-loading");
});

(function () {
  var toggle = document.getElementById("ub-form-toggle");
  var panel = document.getElementById("ub-form-panel");
  var arrow = document.getElementById("ub-form-arrow");
  if (!toggle || !panel) return;
  toggle.addEventListener("click", function (e) {
    e.preventDefault();
    var isOpen = panel.style.display === "block";
    panel.style.display = isOpen ? "none" : "block";
    if (arrow)
      arrow.style.transform = isOpen ? "rotate(0deg)" : "rotate(180deg)";
  });
})();

(function () {
  var burger = document.getElementById("navBurger"),
    menu = document.getElementById("navMobile"),
    overlay = document.getElementById("navOverlay");
  if (!burger || !menu) return;
  function setOpen(open) {
    burger.classList.toggle("open", open);
    menu.classList.toggle("open", open);
    if (overlay) overlay.classList.toggle("open", open);
    burger.setAttribute("aria-expanded", open ? "true" : "false");
    if (open) {
      document.body.style.overflow = "hidden";
    } else {
      var modalOpen = document.querySelector(
        ".demo-modal-overlay.open,.thankyou-modal-overlay.open",
      );
      document.body.style.overflow = modalOpen ? "hidden" : "";
    }
  }

  burger.addEventListener("click", function (e) {
    e.stopPropagation();
    setOpen(!menu.classList.contains("open"));
  });

  menu.addEventListener("click", function (e) {
    if (e.target.closest("a")) setOpen(!1);
  });

  if (overlay)
    overlay.addEventListener("click", function () {
      setOpen(!1);
    });

  document.addEventListener("click", function (e) {
    if (
      menu.classList.contains("open") &&
      !menu.contains(e.target) &&
      !burger.contains(e.target)
    )
      setOpen(!1);
  });

  document.addEventListener("keydown", function (e) {
    if (e.key === "Escape") setOpen(!1);
  });
})();
const rvEls = document.querySelectorAll(".rv");
const rvObs = new IntersectionObserver(
  (entries) => {
    entries.forEach((e) => {
      if (e.isIntersecting) {
        e.target.classList.add("vis");
      } else {
        e.target.classList.remove("vis");
      }
    });
  },
  { threshold: 0.12, rootMargin: "0px 0px -50px 0px" },
);
rvEls.forEach((el) => rvObs.observe(el));
const nav = document.getElementById("nav");
let ticking = !1;
window.addEventListener(
  "scroll",
  () => {
    if (!ticking) {
      requestAnimationFrame(() => {
        nav.classList.toggle("scrolled", window.scrollY > 60);
        const fc = document.getElementById("floatCta");
        if (fc) {
          var nearBottom =
            window.scrollY + window.innerHeight >
            document.documentElement.scrollHeight - 260;
          fc.classList.toggle("show", window.scrollY > 800 && !nearBottom);
        }

        ticking = !1;
      });

      ticking = !0;
    }
  },
  { passive: !0 },
);

(function () {
  const dots = document.querySelectorAll(".side-dot");
  const sideDots = document.getElementById("sideDots");
  if (!dots.length || !sideDots) return;
  const sectionIds = Array.from(dots).map((d) =>
    d.getAttribute("href").slice(1),
  );
  const sections = sectionIds
    .map((id) => document.getElementById(id))
    .filter(Boolean);
  let sdTicking = !1;
  window.addEventListener(
    "scroll",
    () => {
      if (sdTicking) return;
      sdTicking = !0;
      requestAnimationFrame(() => {
        const scrollY = window.scrollY + window.innerHeight / 3;
        let activeIdx = 0;
        sections.forEach((sec, i) => {
          if (sec.offsetTop <= scrollY) activeIdx = i;
        });

        dots.forEach((d, i) => d.classList.toggle("active", i === activeIdx));
        const allSecs = document.querySelectorAll(
          ".sec,.mega,.trust,.cta-strip",
        );
        let isLight = !1;
        allSecs.forEach((s) => {
          if (s.offsetTop <= scrollY)
            isLight = s.classList.contains("sec-light");
        });

        sideDots.classList.toggle("on-light", isLight);
        sdTicking = !1;
      });
    },
    { passive: !0 },
  );
  dots.forEach((d) => {
    d.addEventListener("click", (e) => {
      e.preventDefault();
      const t = document.getElementById(d.getAttribute("href").slice(1));
      if (t) {
        const navH = document.querySelector(".nav").offsetHeight || 70;
        const secPad = parseInt(getComputedStyle(t).paddingTop) || 0;
        const y =
          t.getBoundingClientRect().top + window.scrollY - navH + secPad - 20;
        window.scrollTo({ top: y, behavior: "auto" });
      }
    });
  });
})();

(function () {
  var el = document.querySelector(".qsc");
  if (!el) return;
  var filesEl = document.getElementById("qscFiles");
  var timeEl = document.getElementById("qscTime");
  var vulnsEl = document.getElementById("qscVulns");
  var doneEl = document.getElementById("qscDone");
  var raf = null;
  var totalFiles = 10247,
    totalTime = 3.6,
    totalVulns = 18;
  function runCount() {
    var dur = 3600,
      start = performance.now();
    function tick(now) {
      var p = Math.min((now - start) / dur, 1);
      var ease = 1 - Math.pow(1 - p, 3);
      filesEl.textContent = Math.round(totalFiles * ease).toLocaleString();
      timeEl.textContent = (totalTime * ease).toFixed(1) + "s";
      vulnsEl.textContent = Math.round(totalVulns * ease);
      if (p >= 1) {
        filesEl.textContent = totalFiles.toLocaleString();
        filesEl.classList.add("done");
        timeEl.textContent = totalTime + "s";
        timeEl.classList.add("done");
        vulnsEl.textContent = totalVulns;
        vulnsEl.classList.add("done");
        doneEl.classList.add("show");
        return;
      }

      raf = requestAnimationFrame(tick);
    }

    raf = requestAnimationFrame(tick);
  }

  function reset() {
    filesEl.textContent = "0";
    filesEl.classList.remove("done");
    timeEl.textContent = "0.0s";
    timeEl.classList.remove("done");
    vulnsEl.textContent = "0";
    vulnsEl.classList.remove("done");
    doneEl.classList.remove("show");
  }

  var obs = new IntersectionObserver(
    function (entries) {
      entries.forEach(function (e) {
        if (e.isIntersecting) {
          el.classList.add("vis");
          reset();
          setTimeout(runCount, 500);
        } else {
          el.classList.remove("vis");
          if (raf) cancelAnimationFrame(raf);
          reset();
        }
      });
    },
    { threshold: 0.15 },
  );
  obs.observe(el);
})();

(function () {
  const stage = document.querySelector(".ag2-stage");
  if (!stage) return;
  const typed = document.getElementById("ag2Typed");
  const enterKey = document.getElementById("ag2Enter");
  const brainLabel = document.getElementById("ag2BrainLabel");
  const energy = document.getElementById("ag2Energy");
  const railFill = document.getElementById("ag2RailFill");
  const timeline = document.getElementById("ag2Timeline");
  const feed = document.getElementById("ag2Feed");
  const summary = document.getElementById("ag2Summary");
  const filesStat = document.getElementById("ag2Files");
  const vulnsStat = document.getElementById("ag2Vulns");
  const fixedStat = document.getElementById("ag2Fixed");
  const planDots = document.getElementById("ag2PlanDots");
  const missions = [
    {
      prompt:
        "scan my repo, fix all critical vulns, create tickets, notify the team",
      steps: [
        {
          name: "DEEP SCAN",
          output: [
            "Scanning <span>847 files</span> across 12 modules...",
            "AST parsed | Data flow traced | <span>23 taint paths</span>",
          ],
          metrics: ["847 files", "4.2s"],
          feed: [
            { t: "[00:01] Parsing src/auth/login.js...", c: "" },
            { t: "[00:02] Deep taint analysis started...", c: "" },
            { t: "[00:02] 23 taint paths identified", c: "" },
          ],
          stats: [847, 0, 0],
        },
        {
          name: "FIND VULNS",
          output: [
            "<span>12 critical</span> | 8 high | 3 medium",
            "SQL Injection, XSS, RCE, Path Traversal",
          ],
          metrics: ["23 vulns", "12 critical"],
          feed: [
            { t: "[00:03] CRITICAL: SQL Injection in auth.js:47", c: "crit" },
            { t: "[00:03] CRITICAL: RCE in exec.js:12", c: "crit" },
            { t: "[00:04] HIGH: XSS in render.js:89", c: "crit" },
          ],
          stats: [847, 12, 0],
        },
        {
          name: "AUTO-FIX",
          output: [
            "auth.js:47 → <span>parameterized query</span>",
            "exec.js:12 → <span>input sanitization</span>",
          ],
          metrics: ["12 fixes", "100% auto"],
          feed: [
            {
              t: "[00:05] Fixing SQL Injection → parameterized query",
              c: "fix",
            },
            { t: "[00:06] Fixing RCE → input validation added", c: "fix" },
            { t: "[00:06] All 12 critical vulns patched", c: "fix" },
          ],
          stats: [847, 12, 9],
        },
        {
          name: "PR & TICKETS",
          output: [
            "PR <span>#247</span> opened on main branch",
            "JIRA <span>SEC-1042</span>, SEC-1043 created",
          ],
          metrics: ["1 PR", "2 tickets"],
          feed: [
            { t: "[00:07] PR #247 created → github.com/repo/pull/247", c: "" },
            { t: "[00:07] JIRA SEC-1042 assigned to @dev-team", c: "" },
          ],
          stats: [847, 12, 11],
        },
        {
          name: "RUN TESTS",
          output: [
            "<span>142 tests passed</span> | 0 regressions",
            "Coverage: <span>94.2%</span> | No breaking changes",
          ],
          metrics: ["142 passed", "0 fail"],
          feed: [
            { t: "[00:08] Test suite running... 142/142 passed", c: "fix" },
            { t: "[00:09] Zero regressions detected", c: "fix" },
          ],
          stats: [847, 12, 12],
        },
        {
          name: "DEPLOY & NOTIFY",
          output: [
            "Deployed to <span>staging</span> environment",
            "Slack <span>#security</span> notified | Email sent to CTO",
          ],
          metrics: ["staging", "notified"],
          feed: [
            { t: "[00:10] Deployed to staging-secure.sec1.io", c: "fix" },
            { t: "[00:10] Team notified on Slack #security", c: "" },
          ],
          stats: [847, 12, 12],
        },
      ],
    },
    {
      prompt: "audit auth module for OWASP Top 10, generate compliance report",
      steps: [
        {
          name: "DEEP SCAN",
          output: [
            "Scanning <span>312 files</span> in auth module...",
            "Focused scan: OWASP Top 10 ruleset active",
          ],
          metrics: ["312 files", "1.8s"],
          feed: [
            { t: "[00:01] Auth module targeted scan...", c: "" },
            { t: "[00:01] OWASP Top 10 rules loaded", c: "" },
          ],
          stats: [312, 0, 0],
        },
        {
          name: "FIND VULNS",
          output: [
            "<span>5 critical</span> | 3 high | 7 medium",
            "A01:Broken Access, A03:Injection, A07:Auth Failure",
          ],
          metrics: ["15 vulns", "5 critical"],
          feed: [
            {
              t: "[00:02] CRITICAL: Broken Access Control in rbac.js",
              c: "crit",
            },
            { t: "[00:03] CRITICAL: Injection in query.js:23", c: "crit" },
          ],
          stats: [312, 5, 0],
        },
        {
          name: "AUTO-FIX",
          output: [
            "rbac.js → <span>role validation</span> added",
            "query.js:23 → <span>prepared statements</span>",
          ],
          metrics: ["5 fixes", "100% auto"],
          feed: [
            { t: "[00:04] Fixing Broken Access → role checks", c: "fix" },
            { t: "[00:05] All 5 critical vulns patched", c: "fix" },
          ],
          stats: [312, 5, 4],
        },
        {
          name: "PR & TICKETS",
          output: [
            "PR <span>#312</span> opened for auth hardening",
            "JIRA <span>SEC-2001</span> created with full audit trail",
          ],
          metrics: ["1 PR", "1 ticket"],
          feed: [
            { t: "[00:06] PR #312 created with detailed diff", c: "" },
            { t: "[00:06] JIRA SEC-2001 linked", c: "" },
          ],
          stats: [312, 5, 5],
        },
        {
          name: "RUN TESTS",
          output: [
            "<span>89 tests passed</span> | Auth suite green",
            "Pen test validation: <span>all clear</span>",
          ],
          metrics: ["89 passed", "0 fail"],
          feed: [
            { t: "[00:07] Auth test suite: 89/89 passed", c: "fix" },
            { t: "[00:07] Penetration validation clear", c: "fix" },
          ],
          stats: [312, 5, 5],
        },
        {
          name: "DEPLOY & NOTIFY",
          output: [
            "<span>OWASP compliance report</span> generated",
            "PDF emailed to <span>leadership@company.com</span>",
          ],
          metrics: ["report", "emailed"],
          feed: [
            { t: "[00:08] Compliance report: owasp-audit-2024.pdf", c: "fix" },
            { t: "[00:08] Report emailed to leadership", c: "" },
          ],
          stats: [312, 5, 5],
        },
      ],
    },
    {
      prompt: "find zero-days in payments service, patch and deploy to prod",
      steps: [
        {
          name: "DEEP SCAN",
          output: [
            "Scanning <span>524 files</span> in payments...",
            "Taint tracking across <span>9 API endpoints</span>",
          ],
          metrics: ["524 files", "2.1s"],
          feed: [
            { t: "[00:01] Payments service targeted...", c: "" },
            { t: "[00:01] 9 API endpoints mapped", c: "" },
          ],
          stats: [524, 0, 0],
        },
        {
          name: "FIND VULNS",
          output: [
            "<span>3 zero-day</span> | 6 high | 4 medium",
            "SSRF, Deserialization, Privilege Escalation",
          ],
          metrics: ["13 vulns", "3 zero-day"],
          feed: [
            { t: "[00:02] ZERO-DAY: SSRF in webhook.js:31", c: "crit" },
            { t: "[00:03] ZERO-DAY: Insecure deser in cart.js", c: "crit" },
          ],
          stats: [524, 3, 0],
        },
        {
          name: "AUTO-FIX",
          output: [
            "webhook.js → <span>URL allowlist</span> enforced",
            "cart.js → <span>safe deserialization</span>",
          ],
          metrics: ["3 fixes", "100% auto"],
          feed: [
            { t: "[00:04] Fixing SSRF → allowlist applied", c: "fix" },
            { t: "[00:05] All 3 zero-days patched", c: "fix" },
          ],
          stats: [524, 3, 3],
        },
        {
          name: "PR & TICKETS",
          output: [
            "PR <span>#189</span> opened with security review",
            "JIRA <span>SEC-3010</span> flagged P0",
          ],
          metrics: ["1 PR", "1 ticket"],
          feed: [
            { t: "[00:06] PR #189 created with full diff", c: "" },
            { t: "[00:06] P0 ticket SEC-3010 assigned", c: "" },
          ],
          stats: [524, 3, 3],
        },
        {
          name: "RUN TESTS",
          output: [
            "<span>203 tests passed</span> | Payment suite green",
            "PCI DSS validation: <span>all clear</span>",
          ],
          metrics: ["203 passed", "0 fail"],
          feed: [
            { t: "[00:07] Payment tests: 203/203 passed", c: "fix" },
            { t: "[00:07] PCI compliance verified", c: "fix" },
          ],
          stats: [524, 3, 3],
        },
        {
          name: "DEPLOY & NOTIFY",
          output: [
            "Hot-patched to <span>production</span>",
            "Pager: <span>@oncall</span> + Slack <span>#incidents</span>",
          ],
          metrics: ["prod", "alerted"],
          feed: [
            { t: "[00:08] Deployed to production", c: "fix" },
            { t: "[00:08] On-call team alerted", c: "" },
          ],
          stats: [524, 3, 3],
        },
      ],
    },
    {
      prompt:
        "scan entire monorepo, prioritize by crown jewels, generate executive summary",
      steps: [
        {
          name: "DEEP SCAN",
          output: [
            "Scanning <span>2,140 files</span> across 28 services...",
            "Crown jewel mapping: <span>auth, payments, PII</span>",
          ],
          metrics: ["2140 files", "3.8s"],
          feed: [
            { t: "[00:01] Monorepo scan initiated...", c: "" },
            { t: "[00:02] 28 microservices discovered", c: "" },
          ],
          stats: [2140, 0, 0],
        },
        {
          name: "FIND VULNS",
          output: [
            "<span>18 critical</span> | 24 high | 41 medium",
            "Top risk: PII exposure in user-service",
          ],
          metrics: ["83 vulns", "18 critical"],
          feed: [
            { t: "[00:03] CRITICAL: PII leak in user-svc:92", c: "crit" },
            { t: "[00:04] CRITICAL: RCE in admin-api:17", c: "crit" },
          ],
          stats: [2140, 18, 0],
        },
        {
          name: "AUTO-FIX",
          output: [
            "user-svc → <span>field-level encryption</span>",
            "admin-api → <span>sandbox execution</span>",
          ],
          metrics: ["18 fixes", "100% auto"],
          feed: [
            { t: "[00:05] Fixing PII exposure → encryption", c: "fix" },
            { t: "[00:06] 18 critical vulns resolved", c: "fix" },
          ],
          stats: [2140, 18, 14],
        },
        {
          name: "PR & TICKETS",
          output: [
            "<span>4 PRs</span> across affected services",
            "JIRA sprint <span>SEC-Q4</span> auto-populated",
          ],
          metrics: ["4 PRs", "12 tickets"],
          feed: [
            { t: "[00:07] 4 PRs created across services", c: "" },
            { t: "[00:07] Sprint SEC-Q4 populated", c: "" },
          ],
          stats: [2140, 18, 16],
        },
        {
          name: "RUN TESTS",
          output: [
            "<span>1,847 tests passed</span> | 0 regressions",
            "Integration suite: <span>all green</span>",
          ],
          metrics: ["1847 passed", "0 fail"],
          feed: [
            { t: "[00:08] Full test suite: 1847/1847 ✓", c: "fix" },
            { t: "[00:09] No regressions detected", c: "fix" },
          ],
          stats: [2140, 18, 18],
        },
        {
          name: "DEPLOY & NOTIFY",
          output: [
            "Executive summary: <span>sec1-report.pdf</span>",
            "Board deck updated | CISO <span>notified</span>",
          ],
          metrics: ["report", "sent"],
          feed: [
            { t: "[00:10] Executive summary generated", c: "fix" },
            { t: "[00:10] Report sent to CISO", c: "" },
          ],
          stats: [2140, 18, 18],
        },
      ],
    },
  ];
  let mIdx = 0,
    alive = !1,
    timers = [];
  function clearT() {
    timers.forEach((t) => clearTimeout(t));
    timers = [];
  }

  function wait(ms) {
    return new Promise((r) => {
      const t = setTimeout(r, ms);
      timers.push(t);
    });
  }

  function animC(el, target, dur) {
    const start = parseInt(el.textContent) || 0;
    const st = performance.now();
    function u(now) {
      const p = Math.min((now - st) / dur, 1);
      const e = 1 - Math.pow(1 - p, 3);
      el.textContent = Math.round(start + (target - start) * e);
      if (p < 1 && alive) requestAnimationFrame(u);
    }

    requestAnimationFrame(u);
  }

  function addFeed(text, cls) {
    const d = document.createElement("div");
    d.className = "ag2-feed-line " + (cls || "");
    d.textContent = text;
    feed.appendChild(d);
    requestAnimationFrame(() => d.classList.add("show"));
    while (feed.children.length > 12) feed.removeChild(feed.firstChild);
  }

  async function runMission(m) {
    if (!alive) return;
    const steps = timeline.querySelectorAll(".ag2-step");
    const dots = planDots.querySelectorAll(".ag2-plan-dot");
    feed.innerHTML = "";
    summary.classList.remove("vis");
    stage.classList.remove("thinking", "executing", "complete");
    steps.forEach((s) => {
      s.classList.remove("active", "done");
      const st = s.querySelector(".ag2-step-st");
      if (st) st.innerHTML = "";
      const out = s.querySelector(".ag2-step-out");
      if (out) out.innerHTML = "";
      const met = s.querySelector(".ag2-step-metrics");
      if (met) met.innerHTML = "";
    });

    dots.forEach((d) => {
      d.classList.remove("active", "done");
    });

    railFill.style.height = "0";
    energy.style.opacity = "0";
    energy.style.top = "0";
    filesStat.textContent = "0";
    vulnsStat.textContent = "0";
    fixedStat.textContent = "0";
    brainLabel.textContent = "";
    typed.textContent = "";
    for (let i = 0; i <= m.prompt.length; i++) {
      if (!alive) return;
      typed.textContent = m.prompt.slice(0, i);
      await wait(4 + Math.random() * 3);
    }

    if (!alive) return;
    enterKey.classList.add("flash");
    await wait(100);
    enterKey.classList.remove("flash");
    stage.classList.add("thinking");
    brainLabel.textContent = "ANALYZING CODEBASE...";
    await wait(200);
    if (!alive) return;
    brainLabel.textContent = "PLANNING EXECUTION GRAPH...";
    await wait(200);
    if (!alive) return;
    brainLabel.textContent = "READY — " + m.steps.length + " ACTIONS QUEUED";
    await wait(150);
    stage.classList.remove("thinking");
    stage.classList.add("executing");
    for (let i = 0; i < m.steps.length; i++) {
      if (!alive) return;
      const step = m.steps[i];
      const el = steps[i];
      const dot = dots[i];
      if (!el) continue;
      const nodeEl = el.querySelector(".ag2-step-node");
      const top = el.offsetTop + nodeEl.offsetHeight / 2;
      energy.style.top = top + "px";
      energy.style.opacity = "1";
      energy.style.background = [
        "var(--fire)",
        "var(--rose)",
        "var(--emerald)",
        "var(--violet)",
        "var(--amber)",
        "var(--cyan)",
      ][i];
      energy.style.boxShadow =
        "0 0 12px " +
        [
          "var(--fire)",
          "var(--rose)",
          "var(--emerald)",
          "var(--violet)",
          "var(--amber)",
          "var(--cyan)",
        ][i];
      railFill.style.height = ((i + 1) / m.steps.length) * 100 + "%";
      el.classList.add("active");
      if (dot) dot.classList.add("active");
      const st = el.querySelector(".ag2-step-st");
      if (st) st.innerHTML = '<span class="spinner"></span>';
      const out = el.querySelector(".ag2-step-out");
      if (out) {
        out.innerHTML = "";
        step.output.forEach((l) => {
          const d = document.createElement("div");
          d.innerHTML = l;
          out.appendChild(d);
        });
      }

      const met = el.querySelector(".ag2-step-metrics");
      if (met) {
        met.innerHTML = "";
        step.metrics.forEach((m2) => {
          const s = document.createElement("span");
          s.textContent = m2;
          met.appendChild(s);
        });
      }

      for (const fl of step.feed) {
        addFeed(fl.t, fl.c);
        await wait(60);
      }

      animC(filesStat, step.stats[0], 600);
      animC(vulnsStat, step.stats[1], 400);
      animC(fixedStat, step.stats[2], 400);
      await wait(250);
      if (!alive) return;
      el.classList.remove("active");
      el.classList.add("done");
      if (dot) {
        dot.classList.remove("active");
        dot.classList.add("done");
      }

      if (st) st.innerHTML = '<span class="check">&#10003;</span>';
    }

    energy.style.opacity = "0";
    stage.classList.remove("executing");
    stage.classList.add("complete");
    summary.classList.add("vis");
    addFeed("[DONE] All tasks completed autonomously", "fix");
    brainLabel.textContent = "MISSION COMPLETE";
    await wait(1500);
    if (!alive) return;
    mIdx = (mIdx + 1) % missions.length;
    runMission(missions[mIdx]);
  }

  function resetAll() {
    alive = !1;
    clearT();
    stage.classList.remove("vis", "thinking", "executing", "complete");
    summary.classList.remove("vis");
    typed.textContent = "";
    feed.innerHTML = "";
    const steps = timeline.querySelectorAll(".ag2-step");
    steps.forEach((s) => s.classList.remove("active", "done"));
    const dots = planDots.querySelectorAll(".ag2-plan-dot");
    dots.forEach((d) => d.classList.remove("active", "done"));
    energy.style.opacity = "0";
    railFill.style.height = "0";
    brainLabel.textContent = "";
    mIdx = 0;
  }

  const obs = new IntersectionObserver(
    (entries) => {
      entries.forEach((e) => {
        if (e.isIntersecting) {
          alive = !0;
          stage.classList.add("vis");
          runMission(missions[mIdx]);
        } else {
          resetAll();
        }
      });
    },
    { threshold: 0.08 },
  );
  obs.observe(stage);
})();

(function () {
  const riCards = document.querySelectorAll(".ri-card");
  if (!riCards.length) return;
  const riObs = new IntersectionObserver(
    (entries) => {
      entries.forEach((e) => {
        const card = e.target;
        const arc = card.querySelector(".ri-arc");
        const needle = card.querySelector(".ri-needle");
        const ringDraw = card.querySelector(".ri-ring-draw");
        if (e.isIntersecting) {
          card.classList.add("vis");
          if (arc) arc.style.strokeDasharray = "260 999";
          if (ringDraw) ringDraw.style.strokeDasharray = "346 346";
        } else {
          card.classList.remove("vis");
          if (arc) arc.style.strokeDasharray = "0 999";
          if (needle) needle.style.transform = "rotate(110deg)";
          if (ringDraw) ringDraw.style.strokeDasharray = "0 346";
        }
      });
    },
    { threshold: 0.2 },
  );
  riCards.forEach((c) => riObs.observe(c));
})();
document
  .querySelectorAll(
    ".feat-card,.num-card,.usp-card,.int-card,.ai-feat,.test-card,.ri-card,.roi-card,.price-card,.pl-card",
  )
  .forEach((card) => {
    const isLight = !!card.closest(".sec-light");
    card.addEventListener("mousemove", (e) => {
      const r = card.getBoundingClientRect();
      const x = e.clientX - r.left;
      const y = e.clientY - r.top;
      card.style.background = isLight
        ? `radial-gradient(280px circle at ${x}px ${y}px,rgba(255,74,20,.035),transparent),#fff`
        : `radial-gradient(280px circle at ${x}px ${y}px,rgba(255,74,20,.05),transparent),rgba(255,255,255,.015)`;
    });

    card.addEventListener("mouseleave", () => {
      card.style.background = "";
    });
  });

const heroC = document.querySelector(".hero");
if (heroC) {
  const glows = heroC.querySelectorAll(".hero-glow");
  heroC.addEventListener("mousemove", (e) => {
    const cx = window.innerWidth / 2;
    const cy = window.innerHeight / 2;
    const dx = (e.clientX - cx) / cx;
    const dy = (e.clientY - cy) / cy;
    glows.forEach((g, i) => {
      const f = (i + 1) * 8;
      g.style.transform = `translate(${dx * f}px,${dy * f}px)`;
    });
  });
}
document.querySelectorAll(".hero-stat").forEach((s) => {
  s.addEventListener("mousemove", (e) => {
    const r = s.getBoundingClientRect();
    const x = (e.clientX - r.left) / r.width - 0.5;
    const y = (e.clientY - r.top) / r.height - 0.5;
    s.style.transform = `translateY(-4px) perspective(600px) rotateY(${x * 6}deg) rotateX(${-y * 6}deg)`;
  });

  s.addEventListener("mouseleave", () => {
    s.style.transform = "";
  });
});
document.querySelectorAll(".btn-fire,.btn-lg").forEach((btn) => {
  btn.addEventListener("mousemove", (e) => {
    const r = btn.getBoundingClientRect();
    const x = (e.clientX - r.left - r.width / 2) * 0.15;
    const y = (e.clientY - r.top - r.height / 2) * 0.15;
    btn.style.transform = `translateY(-4px) translate(${x}px,${y}px)`;
  });

  btn.addEventListener("mouseleave", () => {
    btn.style.transform = "";
  });
});

(function () {
  const lsSection = document.getElementById("livescan");
  if (!lsSection) return;
  let animated = !1;
  const lsObs = new IntersectionObserver(
    (entries) => {
      entries.forEach((e) => {
        if (e.isIntersecting && !animated) {
          animated = !0;
          animateCounter("lsFiles", 0, 847, 4000);
          animateCounter("lsVulns", 0, 12, 3000);
          animateCounter("lsFixes", 0, 9, 3500);
          animateTime();
          startPhaseCycle();
        }

      });
    },
    { threshold: 0 },
  );
  lsObs.observe(lsSection);
  function animateCounter(id, start, end, duration) {
    const el = document.getElementById(id);
    if (!el) return;
    const startTime = performance.now();
    function update(now) {
      const elapsed = now - startTime;
      const progress = Math.min(elapsed / duration, 1);
      const eased = 1 - Math.pow(1 - progress, 3);
      el.textContent = Math.round(start + (end - start) * eased);
      if (progress < 1) requestAnimationFrame(update);
    }

    requestAnimationFrame(update);
  }

  function animateTime() {
    const el = document.getElementById("lsTime");
    if (!el) return;
    const startTime = performance.now();
    const duration = 4000;
    function update(now) {
      const elapsed = now - startTime;
      const progress = Math.min(elapsed / duration, 1);
      const eased = 1 - Math.pow(1 - progress, 3);
      const val = (4.2 * eased).toFixed(1);
      el.innerHTML = val + '<span style="font-size:.6em;opacity:.6">s</span>';
      if (progress < 1) requestAnimationFrame(update);
    }

    requestAnimationFrame(update);
  }

  const s_phs = [
    "DEEP TAINT ANALYSIS IN PROGRESS",
    "PARSING AST NODES",
    "TRACING DATA FLOW PATHS",
    "ANALYZING DEPENDENCY GRAPH",
    "CHECKING INJECTION VECTORS",
    "VALIDATING INPUT BOUNDARIES",
    "SCANNING AUTH PATTERNS",
    "EVALUATING CRYPTO USAGE",
    "MAPPING ATTACK SURFACE",
    "GENERATING FIX SUGGESTIONS",
  ];
  let p_idx = 0,
    p_tmr = null;
  function startPhaseCycle() {
    const el = document.getElementById("lsPhase");
    if (!el) return;
    p_idx = 0;
    el.textContent = s_phs[0];
    p_tmr = setInterval(() => {
      p_idx = (p_idx + 1) % s_phs.length;
      el.textContent = s_phs[p_idx];
    }, 1200);
  }

  function stopPhaseCycle() {
    clearInterval(p_tmr);
    const el = document.getElementById("lsPhase");
    if (el) el.textContent = s_phs[0];
  }

  const c_lns = document.querySelectorAll("#lsCodeLines .ls-line");
  let s_idx = 0;
  setInterval(() => {
    if (!animated) return;
    c_lns.forEach((l) => {
      if (l.classList.contains("scanning")) l.style.opacity = "";
    });

    if (
      c_lns[s_idx] &&
      !c_lns[s_idx].classList.contains("vuln") &&
      !c_lns[s_idx].classList.contains("safe")
    ) {
      c_lns[s_idx].style.opacity = "1";
      c_lns[s_idx].style.background = "rgba(255,74,20,.04)";
      c_lns[s_idx].style.borderLeft = "2px solid rgba(255,74,20,.3)";
    }

    s_idx = (s_idx + 1) % c_lns.length;
  }, 600);
})();
document.getElementById("d_mod")?.addEventListener("click", function (e) {
  if (e.target === this) this.style.display = "none";
});

document.getElementById("d_cls")?.addEventListener("click", function () {
  document.getElementById("d_mod").style.display = "none";
});

window.addEventListener("load", function () {
  var cf_id = 14077;
  var r_key = "6LdwzPQpAAAAABlVZlB18e68_1a-_ZD2V4yo2Vm9";
  var d_mod = document.getElementById("d_mod");
  var d_cls = document.getElementById("d_cls");
  if (d_mod)
    d_mod.addEventListener("click", function (e) {
      if (e.target === d_mod) d_mod.style.display = "none";
    });

  if (d_cls)
    d_cls.addEventListener("click", function () {
      if (d_mod) d_mod.style.display = "none";
    });

  if (typeof window.submitCF7Form === "undefined") {
    window.submitCF7Form = function (e, formId) {
      e.preventDefault();
      var form = document.getElementById(formId);
      var btn = form.querySelector('button[type="submit"]');
      var o_txt = btn.textContent;
      btn.textContent = "Submitting...";
      btn.disabled = !0;
      btn.style.opacity = "0.7";
      var cf7Id = form.getAttribute("data-cf7-id") || cf_id;
      grecaptcha.ready(function () {
        grecaptcha
          .execute(r_key, { action: "contact" })

          .then(function (token) {
            var r_inp = form.querySelector(
              'input[name="_wpcf7_recaptcha_response"]',
            );
            if (r_inp) r_inp.value = token;
            var f_dat = new FormData(form);
            f_dat.append("_wpcf7", cf7Id);
            f_dat.append("_wpcf7_version", "5.9.8");
            f_dat.append("_wpcf7_locale", "en_US");
            f_dat.append("_wpcf7_unit_tag", "wpcf7-f" + cf7Id + "-custom");
            fetch(
              "/wp-json/contact-form-7/v1/contact-forms/" + cf7Id + "/feedback",
              { method: "POST", body: f_dat },
            )
              .then(function (res) {
                return res.json();
              })

              .then(function (data) {
                if (data.status === "mail_sent") {
                  btn.textContent = "Thank you!";
                  btn.style.background = "#27C93F";
                  btn.style.opacity = "1";
                  form.reset();
                  if (typeof window.openThankYouModal === "function") {
                    window.openThankYouModal();
                  }
                } else {
                  btn.textContent = "Error. Try again.";
                  btn.style.background = "#FF3B30";
                  btn.style.opacity = "1";
                }

                setTimeout(function () {
                  btn.textContent = o_txt;
                  btn.style.background = "";
                  btn.disabled = !1;
                  btn.style.opacity = "1";
                }, 3000);
              })

              .catch(function () {
                btn.textContent = "Error. Try again.";
                btn.style.background = "#FF3B30";
                btn.style.opacity = "1";
                setTimeout(function () {
                  btn.textContent = o_txt;
                  btn.style.background = "";
                  btn.disabled = !1;
                  btn.style.opacity = "1";
                }, 3000);
              });
          });
      });
    };
  }

  var d_ovr = document.getElementById("demoModal");
  var d_cb = document.getElementById("demoModalClose");
  var t_ovr = document.getElementById("thankYouModal");
  var t_cb = document.getElementById("thankYouModalClose");
  var t_btn = document.getElementById("thankYouModalBtn");
  if (!d_ovr || !t_ovr) return;
  function openDemoModal(e) {
    if (e && e.preventDefault) e.preventDefault();
    d_ovr.classList.add("open");
    document.body.style.overflow = "hidden";
  }

  function closeDemoModal() {
    d_ovr.classList.remove("open");
    document.body.style.overflow = "";
    var panel = document.getElementById("ub-form-panel");
    var arrow = document.getElementById("ub-form-arrow");
    if (panel) panel.style.display = "none";
    if (arrow) arrow.style.transform = "rotate(0deg)";
  }

  function openThankYouModal() {
    closeDemoModal();
    setTimeout(function () {
      t_ovr.classList.add("open");
      document.body.style.overflow = "hidden";
    }, 300);
  }

  function closeThankYouModal() {
    t_ovr.classList.remove("open");
    document.body.style.overflow = "";
  }

  window.openThankYouModal = openThankYouModal;
  document
    .querySelectorAll(".js-open-demo, .js-open-contact")
    .forEach(function (a) {
      a.addEventListener("click", openDemoModal);
    });

  d_cb.addEventListener("click", closeDemoModal);
  d_ovr.addEventListener("click", function (e) {
    if (e.target === d_ovr) closeDemoModal();
  });

  t_cb.addEventListener("click", closeThankYouModal);
  t_btn.addEventListener("click", closeThankYouModal);
  t_ovr.addEventListener("click", function (e) {
    if (e.target === t_ovr) closeThankYouModal();
  });

  document.addEventListener("keydown", function (e) {
    if (e.key === "Escape") {
      if (t_ovr.classList.contains("open")) closeThankYouModal();
      else if (d_ovr.classList.contains("open")) closeDemoModal();
    }
  });
});
