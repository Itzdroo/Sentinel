const state = {
  payload: null,
  mode: "sankey",
  svg: null,
  zoom: null,
  simulation: null,
};

const form = document.querySelector("#analyze-form");
const statusPill = document.querySelector("#status-pill");
const submitButton = document.querySelector("#submit-button");
const chart = document.querySelector("#chart");
const statsGrid = document.querySelector("#stats-grid");
const anomalyList = document.querySelector("#anomaly-list");
const warningList = document.querySelector("#warning-list");
const resetZoomButton = document.querySelector("#reset-zoom");
const modeButtons = Array.from(document.querySelectorAll("[data-mode]"));
const featureCards = Array.from(document.querySelectorAll("[data-profile]"));
const analysisProfileInput = document.querySelector("#analysis-profile");
const reportPanel = document.querySelector("#report-panel");
const exportReportButton = document.querySelector("#export-report");
const exportFormat = document.querySelector("#export-format");
const graphBanner = document.querySelector("#graph-banner");
const cacheInput = document.querySelector("#use-cache");
const cancelButton = document.querySelector("#cancel-button");

let activeRequest = null;

window.addEventListener("DOMContentLoaded", () => {
  if (window.lucide) {
    window.lucide.createIcons();
  }
});

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  await fetchAnalysis();
});

resetZoomButton.addEventListener("click", () => {
  if (state.svg && state.zoom) {
    state.svg.transition().duration(200).call(state.zoom.transform, d3.zoomIdentity);
  }
});

modeButtons.forEach((button) => {
  button.addEventListener("click", () => {
    state.mode = button.dataset.mode;
    modeButtons.forEach((item) => item.classList.toggle("active", item === button));
    if (state.payload) {
      renderChart(state.payload);
    }
  });
});

featureCards.forEach((button) => {
  button.addEventListener("click", () => {
    analysisProfileInput.value = button.dataset.profile;
    featureCards.forEach((item) => item.classList.toggle("active", item === button));
  });
});

exportReportButton.addEventListener("click", () => {
  if (!state.payload?.report) {
    return;
  }
  if (exportFormat.value === "pdf") {
    exportPdf(state.payload);
    return;
  }
  downloadJson(buildExportPackage(state.payload), reportFileName(state.payload));
});

cancelButton.addEventListener("click", () => {
  if (activeRequest) {
    activeRequest.abort();
  }
});

window.addEventListener("resize", debounce(() => {
  if (state.payload) {
    renderChart(state.payload);
  }
}, 180));

async function fetchAnalysis() {
  if (activeRequest) {
    activeRequest.abort();
  }
  activeRequest = new AbortController();

  const formData = new FormData(form);
  const params = new URLSearchParams();
  for (const [key, value] of formData.entries()) {
    params.set(key, String(value).trim());
  }
  params.set("use_cache", cacheInput.checked ? "true" : "false");

  setLoading(true);
  setStatus("Loading");
  try {
    const response = await fetch(`/api/analyze?${params.toString()}`, {
      headers: { Accept: "application/json" },
      signal: activeRequest.signal,
    });
    const data = await response.json();
    if (!response.ok) {
      const message = data.detail?.message || data.detail || "Analysis failed";
      throw new Error(message);
    }
    state.payload = data;
    exportReportButton.disabled = false;
    cancelButton.disabled = true;
    setStatus(data.metadata?.cache_status === "hit" ? "Cached" : "Ready");
    renderPayload(data);
  } catch (error) {
    if (error.name === "AbortError") {
      setStatus("Canceled");
      chart.className = "chart empty-state";
      chart.textContent = "Analysis canceled";
      return;
    }
    setStatus("Error", true);
    exportReportButton.disabled = true;
    chart.className = "chart empty-state";
    chart.textContent = error.message || "Analysis failed";
  } finally {
    activeRequest = null;
    setLoading(false);
    cancelButton.disabled = true;
  }
}

function renderPayload(payload) {
  renderStats(payload);
  renderReport(payload.report);
  renderFindings(payload.anomalies || []);
  renderWarnings(payload.metadata?.warnings || []);
  renderGraphBanner(payload);
  renderChart(payload);
}

function renderGraphBanner(payload) {
  const metadata = payload.metadata || {};
  const shownNodes = metadata.visible_graph_node_count || metadata.graph_node_count || 0;
  const fullNodes = metadata.full_graph_node_count || metadata.graph_node_count || shownNodes;
  const hiddenNodes = Math.max(0, fullNodes - shownNodes);
  const timelineStart = metadata.timeline_start_at ? new Date(metadata.timeline_start_at).toLocaleString() : null;
  const timelineEnd = metadata.timeline_end_at ? new Date(metadata.timeline_end_at).toLocaleString() : null;
  graphBanner.className = "graph-banner";
  graphBanner.replaceChildren();
  const title = document.createElement("strong");
  title.textContent = payload.report?.title || "Graph";
  const summary = document.createElement("span");
  const timelineText = timelineStart || timelineEnd ? ` Timeline: ${timelineStart || "start"} to ${timelineEnd || "end"}.` : "";
  summary.textContent = `${payload.report?.summary || "No summary available."}${timelineText} ${hiddenNodes ? `Showing ${shownNodes} clue nodes, hiding ${hiddenNodes} others.` : `Showing ${shownNodes} nodes.`}`;
  graphBanner.append(title, summary);
}

function renderReport(report) {
  if (!report) {
    reportPanel.className = "report-panel muted";
    reportPanel.textContent = "None";
    return;
  }
  reportPanel.className = "report-panel";
  const title = document.createElement("strong");
  title.textContent = report.title;
  const summary = document.createElement("p");
  summary.textContent = report.summary;
  const metricGrid = document.createElement("div");
  metricGrid.className = "mini-metrics";
  metricGrid.replaceChildren(...Object.entries(report.key_metrics || {}).map(([key, value]) => {
    const metric = document.createElement("div");
    const label = document.createElement("span");
    const strong = document.createElement("strong");
    label.textContent = titleCase(key);
    strong.textContent = value === null || value === undefined ? "n/a" : String(value);
    metric.append(label, strong);
    return metric;
  }));
  const highlights = document.createElement("div");
  highlights.className = "report-lines";
  highlights.replaceChildren(...(report.highlights || []).map((line) => {
    const item = document.createElement("p");
    item.textContent = line;
    return item;
  }));
  const actions = document.createElement("div");
  actions.className = "report-lines compact";
  actions.replaceChildren(...(report.recommended_actions || []).map((line) => {
    const item = document.createElement("p");
    item.textContent = line;
    return item;
  }));
  reportPanel.replaceChildren(title, summary, metricGrid, highlights, actions);
}

function renderStats(payload) {
  const metadata = payload.metadata || {};
  const stats = [
    ["Nodes", metadata.graph_node_count || 0],
    ["Links", metadata.graph_link_count || 0],
    ["Logs", metadata.raw_log_count || 0],
    ["Findings", (payload.anomalies || []).length],
  ];
  statsGrid.replaceChildren(...stats.map(([label, value]) => {
    const item = document.createElement("div");
    const strong = document.createElement("strong");
    const span = document.createElement("span");
    strong.textContent = Number(value).toLocaleString();
    span.textContent = label;
    item.append(strong, span);
    return item;
  }));
}

function renderFindings(findings) {
  if (!findings.length) {
    anomalyList.className = "finding-list muted";
    anomalyList.textContent = "None";
    return;
  }
  anomalyList.className = "finding-list";
  anomalyList.replaceChildren(...findings.map((finding) => {
    const item = document.createElement("article");
    item.className = `finding ${finding.severity}`;
    const title = document.createElement("strong");
    title.textContent = `${titleCase(finding.type)} - ${finding.severity}`;
    const description = document.createElement("div");
    description.textContent = finding.description;
    const path = document.createElement("code");
    path.textContent = finding.path?.length ? finding.path.join(" -> ") : finding.node || "";
    item.append(title, description, path);
    return item;
  }));
}

function renderWarnings(warnings) {
  if (!warnings.length) {
    warningList.className = "finding-list muted";
    warningList.textContent = "None";
    return;
  }
  warningList.className = "finding-list";
  warningList.replaceChildren(...warnings.map((warning) => {
    const item = document.createElement("article");
    item.className = "finding low";
    item.textContent = warning;
    return item;
  }));
}

function renderChart(payload) {
  if (!payload.nodes?.length || !payload.links?.length) {
    chart.className = "chart empty-state";
    chart.textContent = "No transfer flow found";
    return;
  }
  if (state.mode === "node-link") {
    renderNodeLink(payload);
    return;
  }
  renderSankey(payload);
}

function renderSankey(payload) {
  const { width, height } = chartSize();
  const { svg, viewport } = resetSvg(width, height);
  const nodes = payload.nodes.map((node) => ({ ...node }));
  const links = payload.links
    .filter((link) => link.value > 0 && nodes[link.source] && nodes[link.target])
    .map((link) => ({ ...link }));

  try {
    const layout = d3.sankey()
      .nodeWidth(18)
      .nodePadding(14)
      .nodeSort(null)
      .extent([[24, 24], [width - 24, height - 24]]);
    const graph = layout({ nodes, links });
    const maxValue = d3.max(graph.links, (link) => link.value) || 1;
    const linkColor = d3.scaleSequentialLog(d3.interpolatePuBuGn).domain([Math.max(maxValue, 1e-12), 1e-12]);
    const nodeColor = nodeColorScale();

    viewport.append("g")
      .attr("fill", "none")
      .selectAll("path")
      .data(graph.links)
      .join("path")
      .attr("class", "graph-link")
      .attr("d", d3.sankeyLinkHorizontal())
      .attr("stroke", (link) => linkColor(Math.max(link.value, 1e-12)))
      .attr("stroke-width", (link) => Math.max(1, link.width))
      .attr("stroke-opacity", 0.52)
      .append("title")
      .text((link) => linkTooltip(link));

    const node = viewport.append("g")
      .selectAll("g")
      .data(graph.nodes)
      .join("g");

    node.append("rect")
      .attr("x", (item) => item.x0)
      .attr("y", (item) => item.y0)
      .attr("height", (item) => Math.max(1, item.y1 - item.y0))
      .attr("width", (item) => item.x1 - item.x0)
      .attr("rx", 3)
      .attr("fill", (item) => nodeFill(item, nodeColor))
      .attr("stroke", "#1e2428")
      .attr("stroke-opacity", 0.18)
      .append("title")
      .text((item) => nodeTooltip(item));

    node.append("text")
      .attr("class", "node-label")
      .attr("x", (item) => item.x0 < width / 2 ? item.x1 + 8 : item.x0 - 8)
      .attr("y", (item) => (item.y0 + item.y1) / 2)
      .attr("dy", "0.35em")
      .attr("text-anchor", (item) => item.x0 < width / 2 ? "start" : "end")
      .text((item) => nodeLabel(item));
  } catch (error) {
    renderNodeLink(payload);
  }
}

function renderNodeLink(payload) {
  const { width, height } = chartSize();
  const { viewport } = resetSvg(width, height);
  const nodes = payload.nodes.map((node) => ({ ...node }));
  const links = payload.links
    .filter((link) => link.value > 0 && nodes[link.source] && nodes[link.target])
    .map((link) => ({
      ...link,
      source: nodes[link.source].id,
      target: nodes[link.target].id,
    }));
  const maxValue = d3.max(links, (link) => link.value) || 1;
  const widthScale = d3.scaleSqrt().domain([0, maxValue]).range([1, 9]);
  const nodeColor = nodeColorScale();

  const link = viewport.append("g")
    .attr("stroke", "#667077")
    .attr("stroke-opacity", 0.45)
    .selectAll("line")
    .data(links)
    .join("line")
    .attr("stroke-width", (item) => widthScale(item.value));

  link.append("title").text((item) => linkTooltip(item));

  const node = viewport.append("g")
    .selectAll("g")
    .data(nodes)
    .join("g")
    .call(dragSimulation());

  node.append("circle")
    .attr("r", (item) => Math.max(6, Math.min(18, Math.sqrt((item.total_in || 0) + (item.total_out || 0)) + 5)))
    .attr("fill", (item) => nodeFill(item, nodeColor))
    .attr("stroke", "#1e2428")
    .attr("stroke-opacity", 0.18);

  node.append("title")
    .text((item) => nodeTooltip(item));

  node.append("text")
    .attr("class", "node-label")
    .attr("x", 12)
    .attr("y", 4)
    .text((item) => nodeLabel(item));

  if (state.simulation) {
    state.simulation.stop();
  }

  const simulation = d3.forceSimulation(nodes)
    .force("link", d3.forceLink(links).id((item) => item.id).distance(120).strength(0.35))
    .force("charge", d3.forceManyBody().strength(-420))
    .force("center", d3.forceCenter(width / 2, height / 2))
    .force("collide", d3.forceCollide().radius(32))
    .on("tick", () => {
      link
        .attr("x1", (item) => item.source.x)
        .attr("y1", (item) => item.source.y)
        .attr("x2", (item) => item.target.x)
        .attr("y2", (item) => item.target.y);
      node.attr("transform", (item) => `translate(${item.x},${item.y})`);
    });
  state.simulation = simulation;

  function dragSimulation() {
    function dragstarted(event, item) {
      if (!event.active) {
        simulation.alphaTarget(0.3).restart();
      }
      item.fx = item.x;
      item.fy = item.y;
    }
    function dragged(event, item) {
      item.fx = event.x;
      item.fy = event.y;
    }
    function dragended(event, item) {
      if (!event.active) {
        simulation.alphaTarget(0);
      }
      item.fx = null;
      item.fy = null;
    }
    return d3.drag().on("start", dragstarted).on("drag", dragged).on("end", dragended);
  }
}

function resetSvg(width, height) {
  chart.className = "chart";
  chart.replaceChildren();
  if (state.simulation) {
    state.simulation.stop();
    state.simulation = null;
  }
  const svg = d3.select(chart)
    .append("svg")
    .attr("viewBox", [0, 0, width, height])
    .attr("role", "img");
  const viewport = svg.append("g");
  const zoom = d3.zoom()
    .scaleExtent([0.25, 5])
    .on("zoom", (event) => viewport.attr("transform", event.transform));
  svg.call(zoom);
  state.svg = svg;
  state.zoom = zoom;
  return { svg, viewport };
}

function chartSize() {
  const rect = chart.getBoundingClientRect();
  return {
    width: Math.max(640, Math.floor(rect.width || 640)),
    height: Math.max(420, Math.floor(rect.height || 420)),
  };
}

function linkTooltip(link) {
  const tx = link.tx_hashes?.length ? link.tx_hashes.slice(0, 5).join("\n") : link.tx_hash;
  return `${link.token} ${formatAmount(link.value)}\nTransfers: ${link.transfer_count}\n${tx}`;
}

function nodeColorScale() {
  return d3.scaleOrdinal(["#087f8c", "#bc7a00", "#4067b1", "#41734f", "#8758a8", "#c25d4c"]);
}

function nodeFill(item, nodeColor) {
  if (item.tags?.includes("anomaly_path")) {
    return "#b43c35";
  }
  if (item.role === "liquidity_pool_candidate") {
    return "#087f8c";
  }
  if (item.role === "swap_router_candidate") {
    return "#4067b1";
  }
  if (item.role === "dispersal_hub") {
    return "#bc7a00";
  }
  if (item.role === "collector_wallet") {
    return "#41734f";
  }
  return nodeColor(item.id);
}

function nodeTooltip(item) {
  const role = item.role ? `\nRole: ${titleCase(item.role)}` : "";
  const risk = item.risk_score ? `\nRisk: ${Math.round(item.risk_score * 100)}%` : "";
  return `${item.id}\nIn: ${formatAmount(item.total_in)}\nOut: ${formatAmount(item.total_out)}${role}${risk}`;
}

function nodeLabel(item) {
  if (!item.risk_score && !item.role) {
    return "";
  }
  if (item.role === "exchange_candidate") {
    return `${formatAddress(item.id)} [EX]`;
  }
  if (item.role) {
    return `${formatAddress(item.id)} [${roleShort(item.role)}]`;
  }
  return formatAddress(item.id);
}

function downloadJson(value, fileName) {
  const blob = new Blob([JSON.stringify(value, null, 2)], { type: "application/json" });
  const link = document.createElement("a");
  link.href = URL.createObjectURL(blob);
  link.download = fileName;
  document.body.append(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(link.href);
}

function reportFileName(payload) {
  const profile = payload.metadata?.analysis_profile || "analysis";
  const target = String(payload.metadata?.target || "target").slice(0, 12).replace(/[^a-zA-Z0-9]/g, "");
  return `${profile}-${target || "target"}-report`;
}

function buildExportPackage(payload) {
  return {
    metadata: payload.metadata,
    report: payload.report,
    anomalies: payload.anomalies,
    nodes: payload.nodes,
    links: payload.links,
  };
}

function exportPdf(payload) {
  const printWindow = window.open("", "_blank", "width=900,height=1200");
  if (!printWindow) {
    setStatus("Popup blocked", true);
    return;
  }
  const report = payload.report || {};
  const metadata = payload.metadata || {};
  const anomalies = payload.anomalies || [];
  const findingsHtml = anomalies.length
    ? anomalies.map((finding) => `<li><strong>${escapeHtml(titleCase(finding.type))}</strong>: ${escapeHtml(finding.description)}</li>`).join("")
    : "<li>No anomaly findings.</li>";
  const rolesHtml = (report.protocol_roles || [])
    .map((role) => `<li><strong>${escapeHtml(role.role)}</strong> - ${escapeHtml(role.address)} (${Math.round(role.confidence * 100)}%)</li>`)
    .join("") || "<li>No protocol roles identified.</li>";
  const warningsHtml = (metadata.warnings || [])
    .map((warning) => `<li>${escapeHtml(warning)}</li>`)
    .join("") || "<li>No warnings.</li>";
  printWindow.document.write(`
    <!doctype html>
    <html>
      <head>
        <meta charset="utf-8" />
        <title>${escapeHtml(report.title || "Investigation Report")}</title>
        <style>
          body { font-family: Arial, sans-serif; margin: 32px; color: #111; }
          h1, h2 { margin-bottom: 8px; }
          .meta, .section { margin-bottom: 20px; }
          ul { padding-left: 20px; }
          .kvs { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 8px; }
          .kv { border: 1px solid #ddd; padding: 8px; border-radius: 6px; }
          .kv span { display: block; color: #666; font-size: 12px; }
        </style>
      </head>
      <body>
        <h1>${escapeHtml(report.title || "Investigation Report")}</h1>
        <p>${escapeHtml(report.summary || "")}</p>
        <div class="meta">
          <div class="kvs">
            ${Object.entries(report.key_metrics || {}).map(([key, value]) => `<div class="kv"><span>${escapeHtml(titleCase(key))}</span>${escapeHtml(String(value))}</div>`).join("")}
          </div>
        </div>
        <div class="section">
          <h2>Highlights</h2>
          <ul>${(report.highlights || []).map((line) => `<li>${escapeHtml(line)}</li>`).join("")}</ul>
        </div>
        <div class="section">
          <h2>Recommended Actions</h2>
          <ul>${(report.recommended_actions || []).map((line) => `<li>${escapeHtml(line)}</li>`).join("")}</ul>
        </div>
        <div class="section">
          <h2>Protocol Roles</h2>
          <ul>${rolesHtml}</ul>
        </div>
        <div class="section">
          <h2>Anomalies</h2>
          <ul>${findingsHtml}</ul>
        </div>
        <div class="section">
          <h2>Warnings</h2>
          <ul>${warningsHtml}</ul>
        </div>
        <script>
          window.onload = () => { window.print(); };
        </script>
      </body>
    </html>
  `);
  printWindow.document.close();
}

function formatAmount(value) {
  const number = Number(value || 0);
  if (!Number.isFinite(number)) {
    return "0";
  }
  return new Intl.NumberFormat(undefined, { maximumFractionDigits: 6 }).format(number);
}

function formatAddress(address) {
  if (!address || address.length <= 12) {
    return address || "";
  }
  return `${address.slice(0, 6)}...${address.slice(-4)}`;
}

function titleCase(value) {
  return String(value || "")
    .replace(/_/g, " ")
    .replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function roleShort(role) {
  const value = String(role || "");
  if (value === "dispersal_hub") {
    return "DSP";
  }
  if (value === "collector_wallet") {
    return "COL";
  }
  if (value === "exchange_candidate") {
    return "EX";
  }
  if (value === "liquidity_pool_candidate") {
    return "LP";
  }
  if (value === "swap_router_candidate") {
    return "ROUTER";
  }
  return value.slice(0, 4).toUpperCase();
}

function setStatus(text, isError = false) {
  statusPill.textContent = text;
  statusPill.classList.toggle("error", isError);
}

function setLoading(isLoading) {
  submitButton.disabled = isLoading;
  submitButton.textContent = isLoading ? "Analyzing" : "Analyze Flow";
  cancelButton.disabled = !isLoading;
}

function debounce(callback, delay) {
  let timeoutId;
  return (...args) => {
    window.clearTimeout(timeoutId);
    timeoutId = window.setTimeout(() => callback(...args), delay);
  };
}
