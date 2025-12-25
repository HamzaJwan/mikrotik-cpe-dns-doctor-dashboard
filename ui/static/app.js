// ui/static/app.js
(function () {
  const qs = (sel, root) => (root || document).querySelector(sel);
  const qsa = (sel, root) => Array.from((root || document).querySelectorAll(sel));

  function escapeHtml(value) {
    return String(value || "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  function autoHideAlerts() {
    const alerts = qsa(".alert[data-autohide='true']");
    alerts.forEach((el) => {
      setTimeout(() => {
        el.classList.add("fade");
        setTimeout(() => el.remove(), 400);
      }, 2500);
    });
  }

  function parseParamList(params, key) {
    const values = [];
    params.getAll(key).forEach((v) => {
      String(v || "")
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean)
        .forEach((s) => values.push(s));
    });
    return Array.from(new Set(values));
  }

  function buildSummary(label, selected) {
    if (!selected.length) return `${label}: All`;
    if (selected.length <= 2) return `${label}: ${selected.join(", ")}`;
    return `${label}: ${selected.slice(0, 2).join(", ")} (+${selected.length - 2})`;
  }

  function buildMultiSelect(container, options, paramName, label, params) {
    const menu = qs(".js-filter-options", container);
    const labelBtn = qs(".js-filter-label", container);
    const allBox = qs(".js-filter-all", container);
    const clearBtn = qs(".js-filter-clear", container);
    if (!menu || !labelBtn) return;

    const selected = parseParamList(params, paramName);
    const selectedSet = new Set(selected);

    menu.innerHTML = "";
    const merged = Array.from(new Set([...(options || []), ...selected]));
    merged.forEach((opt, idx) => {
      const wrap = document.createElement("div");
      wrap.className = "form-check";

      const input = document.createElement("input");
      input.type = "checkbox";
      input.className = "form-check-input js-filter-item";
      input.name = paramName;
      input.value = opt;
      input.id = `${paramName}-${idx}`;
      input.checked = selectedSet.has(opt);

      const lbl = document.createElement("label");
      lbl.className = "form-check-label";
      lbl.htmlFor = input.id;
      lbl.textContent = opt;

      wrap.appendChild(input);
      wrap.appendChild(lbl);
      menu.appendChild(wrap);
    });

    function getSelected() {
      return qsa("input.js-filter-item:checked", menu).map((i) => i.value);
    }

    function updateSummary() {
      const values = getSelected();
      if (allBox) {
        allBox.checked = values.length === 0;
      }
      labelBtn.textContent = buildSummary(label, values);
    }

    if (allBox) {
      allBox.checked = selected.length === 0;
      allBox.addEventListener("change", () => {
        if (allBox.checked) {
          qsa("input.js-filter-item", menu).forEach((i) => (i.checked = false));
        }
        updateSummary();
      });
    }

    if (clearBtn) {
      clearBtn.addEventListener("click", () => {
        qsa("input.js-filter-item", menu).forEach((i) => (i.checked = false));
        if (allBox) allBox.checked = true;
        updateSummary();
      });
    }

    qsa("input.js-filter-item", menu).forEach((i) => {
      i.addEventListener("change", () => {
        if (allBox && i.checked) allBox.checked = false;
        updateSummary();
      });
    });

    updateSummary();
  }

  async function initFilters() {
    const containers = qsa(".js-filter");
    if (!containers.length) return;

    let options = { cities: [], statuses: [] };
    try {
      const res = await fetch(`/api/filters/options?t=${Date.now()}`, { cache: "no-store" });
      if (res.ok) {
        options = await res.json();
      }
    } catch (e) {
      // keep empty lists
    }

    const params = new URLSearchParams(window.location.search);
    containers.forEach((el) => {
      const kind = el.getAttribute("data-filter");
      if (kind === "city") {
        buildMultiSelect(el, options.cities || [], "city", "City", params);
      } else if (kind === "status") {
        buildMultiSelect(el, options.statuses || [], "status", "Status", params);
      }
    });
  }

  async function initRunCities() {
    const container = qs(".js-run-city");
    if (!container) return;

    let cities = [];
    try {
      const res = await fetch(`/api/run/cities?t=${Date.now()}`, { cache: "no-store" });
      if (res.ok) {
        const data = await res.json();
        cities = data.cities || [];
      }
    } catch (e) {
      cities = [];
    }

    buildMultiSelect(container, cities, "city", "City", new URLSearchParams());

    const allCities = qs("#allCities");
    const labelBtn = qs(".js-filter-label", container);
    const inputs = () => qsa("input.js-filter-item", container);

    function syncAllCities() {
      const disabled = allCities && allCities.checked;
      if (labelBtn) labelBtn.disabled = !!disabled;
      inputs().forEach((i) => {
        if (disabled) i.checked = false;
        i.disabled = !!disabled;
      });
      if (labelBtn && disabled) {
        labelBtn.textContent = "City: All";
      }
    }

    if (allCities) {
      allCities.addEventListener("change", syncAllCities);
      syncAllCities();
    }
  }

  function renderStatusBadge(status) {
    const st = String(status || "").toLowerCase();
    if (!st) return "<span class=\"text-muted\">-</span>";
    if (st === "ok") return "<span class=\"badge rounded-pill text-bg-success\">ok</span>";
    if (st === "reserved") return "<span class=\"badge rounded-pill text-bg-secondary\">reserved</span>";
    return `<span class="badge rounded-pill text-bg-danger">${escapeHtml(st)}</span>`;
  }

  function renderLoginBadge(value) {
    if (value === null || value === undefined) return "<span class=\"text-muted\">-</span>";
    if (Number(value) === 1) return "<span class=\"badge rounded-pill text-bg-success\">true</span>";
    return "<span class=\"badge rounded-pill text-bg-danger\">false</span>";
  }

  function renderFixBadge(value) {
    if (value === null || value === undefined) return "<span class=\"text-muted\">-</span>";
    if (Number(value) === 1) return "<span class=\"badge rounded-pill text-bg-success\">yes</span>";
    return "<span class=\"badge rounded-pill text-bg-secondary\">no</span>";
  }

  function renderOutcomeRow(row) {
    const action = row.action || "-";
    const username = row.pppoe_username || row.canonical_username || "-";
    return `
      <tr>
        <td>${escapeHtml(row.created_at || "-")}</td>
        <td class="fw-semibold">${escapeHtml(row.ip || "-")}</td>
        <td>${escapeHtml(username)}</td>
        <td>${escapeHtml(row.city || "-")}</td>
        <td><span class="badge rounded-pill text-bg-dark">${escapeHtml(action)}</span></td>
        <td>${renderStatusBadge(row.status)}</td>
        <td>${renderLoginBadge(row.login_success)}</td>
        <td>${escapeHtml(row.warning_count || 0)}</td>
        <td>${renderFixBadge(row.fix_applied)}</td>
      </tr>
    `;
  }

  function updateOutcomesTable(rows) {
    const body = qs("#jsOutcomesBody");
    if (!body) return;
    if (!Array.isArray(rows) || rows.length === 0) {
      body.innerHTML = "<tr><td colspan=\"9\" class=\"text-center text-muted py-4\">No outcomes yet.</td></tr>";
      return;
    }
    body.innerHTML = rows.map(renderOutcomeRow).join("");
  }

  function updateKpis(kpis) {
    if (!kpis) return;
    const set = (id, val) => {
      const el = qs(id);
      if (el) el.textContent = String(val ?? 0);
    };
    set("#jsKpiTotal", kpis.total ?? kpis.total_count ?? kpis.total_targets ?? "");
    set("#jsKpiOk", kpis.ok);
    set("#jsKpiFailed", kpis.failed);
    set("#jsKpiLoginFailed", kpis.login_failed);
    set("#jsKpiFixed", kpis.fix_applied ?? kpis.fixed);
    set("#jsKpiRebooted", kpis.rebooted);
  }

  function showToast(message) {
    const container = qs("#jsToastContainer") || (() => {
      const div = document.createElement("div");
      div.id = "jsToastContainer";
      div.className = "toast-container position-fixed bottom-0 end-0 p-3";
      document.body.appendChild(div);
      return div;
    })();

    const toast = document.createElement("div");
    toast.className = "toast align-items-center text-bg-primary border-0";
    toast.setAttribute("role", "alert");
    toast.setAttribute("aria-live", "assertive");
    toast.setAttribute("aria-atomic", "true");
    toast.innerHTML = `
      <div class="d-flex">
        <div class="toast-body">${escapeHtml(message)}</div>
        <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button>
      </div>
    `;
    container.appendChild(toast);

    if (window.bootstrap && window.bootstrap.Toast) {
      const inst = new window.bootstrap.Toast(toast, { delay: 5000 });
      toast.addEventListener("hidden.bs.toast", () => toast.remove());
      inst.show();
    } else {
      toast.classList.add("show");
      setTimeout(() => toast.remove(), 5000);
    }
  }

  function isFinalStatus(status) {
    const st = String(status || "").toLowerCase();
    return ["completed", "failed", "stopped", "cancelled"].includes(st);
  }

  function isActiveStatus(status) {
    const st = String(status || "").toLowerCase();
    return ["running", "reserved", "in_progress", "processing"].includes(st);
  }

  function initSessionPolling() {
    const el = qs(".js-session-progress");
    if (!el) return;
    const sessionId = el.getAttribute("data-session-id");
    if (!sessionId) return;

    const bar = qs("#jsProgressBar");
    const text = qs("#jsProgressText");
    const statusEl = qs("#jsSessionStatus");

    let stopped = false;
    let lastStatus = null;
    let toastShown = false;
    let timer = null;

    const baseParams = new URLSearchParams(window.location.search);
    baseParams.set("include_rows", "1");

    const schedule = (ms) => {
      if (stopped) return;
      if (timer) clearTimeout(timer);
      timer = setTimeout(tick, ms);
    };

    const tick = async () => {
      if (document.hidden) {
        schedule(1000);
        return;
      }
      try {
        const params = new URLSearchParams(baseParams.toString());
        params.set("t", Date.now().toString());
        const res = await fetch(`/api/sessions/${sessionId}/progress?${params.toString()}`, { cache: "no-store" });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();

        const total = data.total || 0;
        const processed = data.processed || 0;
        const reserved = data.reserved || 0;
        const pct = data.percent || 0;
        const sess = data.session || {};

        if (bar) {
          bar.style.width = `${pct}%`;
          bar.textContent = pct >= 15 ? `${pct}%` : "";
        }
        if (text) {
          text.textContent = `Processed ${processed}/${total} (reserved: ${reserved})`;
        }
        if (statusEl && sess.status && sess.status !== lastStatus) {
          statusEl.textContent = sess.status;
          lastStatus = sess.status;
        }

        updateKpis({
          total,
          ok: data.kpis ? data.kpis.ok : undefined,
          failed: data.kpis ? data.kpis.failed : undefined,
          login_failed: data.kpis ? data.kpis.login_failed : undefined,
          fixed: data.kpis ? data.kpis.fix_applied : undefined,
          rebooted: data.kpis ? data.kpis.rebooted : undefined,
        });

        if (data.rows) updateOutcomesTable(data.rows);

        const finished = sess.finished_at || isFinalStatus(sess.status) || (total > 0 && processed >= total);
        if (finished && !toastShown) {
          toastShown = true;
          showToast(`Session #${sessionId} finished (${sess.status || "done"})`);
          stopped = true;
          return;
        }

        const nextMs = isActiveStatus(sess.status) ? 1000 : 3000;
        schedule(nextMs);
      } catch (e) {
        if (text) text.textContent = `Progress unavailable: ${e}`;
        schedule(2000);
      }
    };

    document.addEventListener("visibilitychange", () => {
      if (!document.hidden && !stopped) schedule(0);
    });

    schedule(0);
  }

  document.addEventListener("DOMContentLoaded", () => {
    autoHideAlerts();
    initFilters();
    initRunCities();
    initSessionPolling();
  });
})();
