
"use strict";
document.documentElement.classList.add("js");
const search = document.getElementById("text-filter");
const asset = document.getElementById("asset-filter");
const severity = document.getElementById("severity-filter");
const rows = Array.from(document.querySelectorAll("[data-filterable]"));
function filterReport() {
  const query = search.value.trim().toLowerCase();
  let visibleFindings = 0;
  let visibleObservations = 0;
  rows.forEach(row => {
    const isFinding = row.dataset.category === "finding";
    const matches = (!query || row.dataset.search.includes(query)) &&
      (!asset.value || row.dataset.asset === asset.value) &&
      (!isFinding || !severity.value || row.dataset.severity === severity.value);
    row.hidden = !matches;
    if (matches) {
      if (isFinding) visibleFindings++; else visibleObservations++;
    }
  });
  document.querySelectorAll(".filter-empty").forEach(empty => {
    const section = empty.closest("section");
    const members = Array.from(section.querySelectorAll("[data-filterable]"));
    empty.hidden = members.length === 0 || members.some(row => !row.hidden);
  });
  document.getElementById("filter-status").textContent =
    visibleFindings + " findings · " + visibleObservations +
    " inventory observations shown. Severity applies to findings; asset and search apply to both.";
}
search.addEventListener("input", filterReport);
asset.addEventListener("change", filterReport);
severity.addEventListener("change", filterReport);
document.getElementById("clear-filters").addEventListener("click", () => {
  search.value = "";
  asset.value = "";
  severity.value = "";
  filterReport();
});
document.getElementById("print-report").addEventListener("click", () => window.print());
let closedBeforePrint = [];
window.addEventListener("beforeprint", () => {
  closedBeforePrint = Array.from(document.querySelectorAll("details:not([open])"));
  closedBeforePrint.forEach(details => { details.open = true; });
});
window.addEventListener("afterprint", () => {
  closedBeforePrint.forEach(details => { details.open = false; });
  closedBeforePrint = [];
});
filterReport();
