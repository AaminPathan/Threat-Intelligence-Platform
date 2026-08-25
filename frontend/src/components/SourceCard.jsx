import "./SourceCard.css";

function statusLabel(status) {
  switch (status) {
    case "ok":
      return "Available";
    case "not_found":
      return "No intelligence found";
    case "not_configured":
      return "API key not configured";
    case "not_applicable":
      return "Not applicable";
    case "rate_limited":
      return "Rate limited";
    case "timeout":
      return "Request timed out";
    case "error":
      return "API unavailable";
    default:
      return status || "Unknown";
  }
}

function statusClass(status) {
  if (status === "ok") return "source-card__status--ok";
  if (status === "not_applicable" || status === "not_found") return "source-card__status--neutral";
  return "source-card__status--warn";
}

function renderFields(name, data) {
  if (!data || data.status !== "ok") return null;
  const rows = [];

  if (name === "abuseipdb") {
    rows.push(["Confidence score", data.abuseConfidenceScore != null ? `${data.abuseConfidenceScore}%` : "—"]);
    rows.push(["Total reports", data.totalReports ?? "—"]);
    rows.push(["Country", data.countryCode ?? "—"]);
    rows.push(["ISP", data.isp ?? "—"]);
    rows.push(["Tor exit node", data.isTor ? "Yes" : "No"]);
  } else if (name === "virustotal") {
    rows.push(["Malicious", data.malicious ?? 0]);
    rows.push(["Suspicious", data.suspicious ?? 0]);
    rows.push(["Harmless", data.harmless ?? 0]);
    rows.push(["Total engines", data.totalEngines ?? 0]);
    if (data.reputation != null) rows.push(["Reputation", data.reputation]);
  } else if (name === "otx") {
    rows.push(["Pulse count", data.pulseCount ?? 0]);
    if (data.pulseNames?.length) rows.push(["Pulses", data.pulseNames.join(", ")]);
    if (data.tags?.length) rows.push(["Tags", data.tags.join(", ")]);
  }

  return rows;
}

export default function SourceCard({ name, label, data }) {
  const status = data?.status;
  const rows = renderFields(name, data);

  return (
    <div className="source-card">
      <div className="source-card__header">
        <h3>{label}</h3>
        <span className={`source-card__status ${statusClass(status)}`}>{statusLabel(status)}</span>
      </div>

      {status === "ok" && rows && (
        <dl className="source-card__fields">
          {rows.map(([key, val]) => (
            <div key={key} className="source-card__field">
              <dt>{key}</dt>
              <dd>{String(val)}</dd>
            </div>
          ))}
        </dl>
      )}

      {status && status !== "ok" && data?.error && <p className="source-card__error">{data.error}</p>}
    </div>
  );
}