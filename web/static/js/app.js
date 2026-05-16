(() => {
  const state = {
    file: null,
    mode: "multithreaded",
    blockApps: new Set(),
    blockIps: [],
    blockDomains: [],
    lbs: 2,
    fps: 2,
  };

  const $ = (id) => document.getElementById(id);

  const dropzone = $("dropzone");
  const fileInput = $("fileInput");
  const fileName = $("fileName");
  const btnRun = $("btnRun");
  const btnSample = $("btnSample");
  const spinner = $("spinner");
  const emptyState = $("emptyState");
  const results = $("results");
  const errorBanner = $("errorBanner");
  const threadFields = $("threadFields");
  const threadCard = $("threadCard");

  async function loadApps() {
    const res = await fetch("/api/apps");
    const data = await res.json();
    const grid = $("appChips");
    grid.innerHTML = "";
    data.apps.forEach((app) => {
      const chip = document.createElement("button");
      chip.type = "button";
      chip.className = "chip";
      chip.textContent = app;
      chip.dataset.app = app;
      chip.addEventListener("click", () => {
        if (state.blockApps.has(app)) {
          state.blockApps.delete(app);
          chip.classList.remove("selected");
        } else {
          state.blockApps.add(app);
          chip.classList.add("selected");
        }
      });
      grid.appendChild(chip);
    });
  }

  function setFile(file) {
    state.file = file;
    fileName.textContent = file ? file.name : "No file selected";
    btnRun.disabled = !file;
  }

  dropzone.addEventListener("click", () => fileInput.click());
  fileInput.addEventListener("change", () => {
    if (fileInput.files[0]) setFile(fileInput.files[0]);
  });

  dropzone.addEventListener("dragover", (e) => {
    e.preventDefault();
    dropzone.classList.add("dragover");
  });
  dropzone.addEventListener("dragleave", () => dropzone.classList.remove("dragover"));
  dropzone.addEventListener("drop", (e) => {
    e.preventDefault();
    dropzone.classList.remove("dragover");
    const f = e.dataTransfer.files[0];
    if (f && (f.name.endsWith(".pcap") || f.name.endsWith(".cap"))) {
      setFile(f);
    }
  });

  document.querySelectorAll(".mode-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      document.querySelectorAll(".mode-btn").forEach((b) => b.classList.remove("active"));
      btn.classList.add("active");
      state.mode = btn.dataset.mode;
      threadFields.classList.toggle("hidden", state.mode === "simple");
    });
  });

  $("lbs").addEventListener("input", (e) => {
    state.lbs = +e.target.value;
    $("lbsVal").textContent = state.lbs;
  });
  $("fps").addEventListener("input", (e) => {
    state.fps = +e.target.value;
    $("fpsVal").textContent = state.fps;
  });

  function addTag(list, value, onRemove) {
    if (!value.trim()) return;
    const tags = $(list);
    const tag = document.createElement("span");
    tag.className = "tag";
    tag.innerHTML = `${escapeHtml(value)} <button type="button" aria-label="Remove">×</button>`;
    tag.querySelector("button").addEventListener("click", () => {
      tag.remove();
      onRemove(value);
    });
    tags.appendChild(tag);
  }

  function escapeHtml(s) {
    const d = document.createElement("div");
    d.textContent = s;
    return d.innerHTML;
  }

  $("btnAddIp").addEventListener("click", () => {
    const v = $("ipInput").value.trim();
    if (!v || state.blockIps.includes(v)) return;
    state.blockIps.push(v);
    addTag("ipTags", v, (x) => {
      state.blockIps = state.blockIps.filter((i) => i !== x);
    });
    $("ipInput").value = "";
  });

  $("btnAddDomain").addEventListener("click", () => {
    const v = $("domainInput").value.trim();
    if (!v || state.blockDomains.includes(v)) return;
    state.blockDomains.push(v);
    addTag("domainTags", v, (x) => {
      state.blockDomains = state.blockDomains.filter((d) => d !== x);
    });
    $("domainInput").value = "";
  });

  btnSample.addEventListener("click", async () => {
    btnSample.disabled = true;
    try {
      const meta = await fetch("/api/sample").then((r) => r.json());
      if (!meta.success) throw new Error(meta.error || "Sample unavailable");
      const blob = await fetch("/api/sample/file").then((r) => r.blob());
      setFile(new File([blob], meta.filename, { type: "application/vnd.tcpdump.pcap" }));
    } catch (err) {
      showError(err.message);
    } finally {
      btnSample.disabled = false;
    }
  });

  function showError(msg) {
    errorBanner.textContent = msg;
    errorBanner.classList.remove("hidden");
  }

  function hideError() {
    errorBanner.classList.add("hidden");
  }

  function renderReport(data) {
    emptyState.classList.add("hidden");
    results.classList.remove("hidden");

    const stats = [
      { label: "Packets", value: data.total_packets },
      { label: "Forwarded", value: data.forwarded, cls: "success" },
      { label: "Dropped", value: data.dropped, cls: "danger" },
      { label: "TCP", value: data.tcp_packets || "—" },
      { label: "UDP", value: data.udp_packets || "—" },
      { label: "Flows", value: data.active_flows || "—" },
    ];

    $("statsGrid").innerHTML = stats
      .map(
        (s) => `
      <div class="stat-card ${s.cls || ""}">
        <div class="value">${formatNum(s.value)}</div>
        <div class="label">${s.label}</div>
      </div>`
      )
      .join("");

    const maxCount = Math.max(...(data.apps || []).map((a) => a.count), 1);
    $("appChart").innerHTML = (data.apps || [])
      .map((app) => {
        const w = (app.count / maxCount) * 100;
        return `
        <div class="bar-row">
          <span class="name">${escapeHtml(app.name)}</span>
          <div class="bar-track"><div class="bar-fill" style="width:${w}%"></div></div>
          <span class="pct">${app.percent}%</span>
        </div>`;
      })
      .join("");

    if (data.threads && data.threads.length) {
      threadCard.classList.remove("hidden");
      $("threadGrid").innerHTML = data.threads
        .map(
          (t) => `
        <div class="thread-item">
          <span>${escapeHtml(t.label)}</span>
          <strong>${formatNum(t.value)}</strong>
        </div>`
        )
        .join("");
    } else {
      threadCard.classList.add("hidden");
    }

    $("sniBody").innerHTML = (data.snis || [])
      .map(
        (s) => `
      <tr><td>${escapeHtml(s.domain)}</td><td>${escapeHtml(s.app)}</td></tr>`
      )
      .join("");

    const dl = $("btnDownload");
    if (data.download_url) {
      dl.href = data.download_url;
      dl.classList.remove("hidden");
    } else {
      dl.classList.add("hidden");
    }
  }

  function formatNum(n) {
    if (n === undefined || n === null || n === "—") return "—";
    return Number(n).toLocaleString();
  }

  btnRun.addEventListener("click", async () => {
    if (!state.file) return;

    hideError();
    btnRun.disabled = true;
    spinner.classList.remove("hidden");
    $("resultsPanel").classList.add("running");

    const form = new FormData();
    form.append("pcap", state.file);
    form.append(
      "options",
      JSON.stringify({
        mode: state.mode,
        block_ips: state.blockIps,
        block_apps: [...state.blockApps],
        block_domains: state.blockDomains,
        lbs: state.lbs,
        fps: state.fps,
      })
    );

    try {
      const res = await fetch("/api/analyze", { method: "POST", body: form });
      const data = await res.json();
      if (!data.success) {
        showError(data.error || "Analysis failed");
        return;
      }
      renderReport(data);
    } catch (err) {
      showError(err.message || "Network error");
    } finally {
      btnRun.disabled = false;
      spinner.classList.add("hidden");
      $("resultsPanel").classList.remove("running");
    }
  });

  loadApps();
})();
