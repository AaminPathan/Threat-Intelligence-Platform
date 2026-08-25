import "./RiskSummary.css";

const SEVERITY_COLORS = {
  LOW: "#4ade80",
  MEDIUM: "#fbbf24",
  HIGH: "#f97316",
  CRITICAL: "#ef4444",
};

export default function RiskSummary({ indicator, iocType, risk }) {
  if (!risk) return null;
  const color = SEVERITY_COLORS[risk.severity] || "#9ca3af";

  return (
    <div className="risk-summary">
      <div className="risk-summary__header">
        <div>
          <p className="risk-summary__indicator">{indicator}</p>
          <p className="risk-summary__type">{iocType?.toUpperCase()}</p>
        </div>
        <div className="risk-summary__score" style={{ borderColor: color }}>
          <span className="risk-summary__score-value" style={{ color }}>
            {risk.score}
          </span>
          <span className="risk-summary__severity" style={{ color }}>
            {risk.severity}
          </span>
        </div>
      </div>

      <ul className="risk-summary__reasons">
        {risk.reasons.map((reason, i) => (
          <li key={i}>{reason}</li>
        ))}
      </ul>

      <p className="risk-summary__methodology">{risk.methodology}</p>
    </div>
  );
}