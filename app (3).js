const form = document.getElementById("scan-form");
const resultBox = document.getElementById("result");
const emailInput = document.getElementById("email");
const promptRow = document.getElementById("prompt-row");
const runBtn = document.getElementById("run-btn");
const exampleBtn = document.getElementById("example-btn");

const EXAMPLES = ["test@example.com", "alice@example.com", "demo@test.com"];
let exampleIndex = 0;

function severityClass(sev) {
  return {
    low: "sev-low",
    medium: "sev-medium",
    high: "sev-high",
  }[sev] || "sev-medium";
}

function escapeHtml(str) {
  const div = document.createElement("div");
  div.textContent = str ?? "";
  return div.innerHTML;
}

function renderResult(data) {
  resultBox.hidden = false;

  if (data.error) {
    resultBox.innerHTML = `<p class="status-line error">${escapeHtml(data.error)}</p>`;
    return;
  }

  if (data.breach_count === 0) {
    resultBox.innerHTML = `
      <p class="status-line safe">clear — no exposure found in this dataset</p>
      <p class="note">${escapeHtml(data.note)}</p>
    `;
    return;
  }

  const entries = data.breaches.map(b => `
    <li class="log-entry ${severityClass(b.severity)}">
      <span class="name">${escapeHtml(b.name)}</span>
      <span class="date">${escapeHtml(b.date || "unknown date")}</span>
      <span class="data-classes">exposed: ${b.compromised_data.map(escapeHtml).join(", ")}</span>
    </li>
  `).join("");

  resultBox.innerHTML = `
    <p class="status-line risk">exposed in ${data.breach_count} breach${data.breach_count > 1 ? "es" : ""}</p>
    <ul class="log">${entries}</ul>
    <p class="note">${escapeHtml(data.note)}</p>
  `;
}

async function runScan(email) {
  promptRow.classList.add("is-scanning");
  runBtn.disabled = true;
  resultBox.hidden = true;

  try {
    const res = await fetch("/api/check", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email }),
    });
    const data = await res.json();
    renderResult(data);
  } catch (err) {
    resultBox.hidden = false;
    resultBox.innerHTML = `<p class="status-line error">Something went wrong. Please try again.</p>`;
  } finally {
    promptRow.classList.remove("is-scanning");
    runBtn.disabled = false;
  }
}

form.addEventListener("submit", (e) => {
  e.preventDefault();
  const email = emailInput.value.trim();
  if (email) runScan(email);
});

exampleBtn.addEventListener("click", () => {
  const email = EXAMPLES[exampleIndex % EXAMPLES.length];
  exampleIndex++;
  emailInput.value = email;
  runScan(email);
});
