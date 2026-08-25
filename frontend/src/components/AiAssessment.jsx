import "./AiAssessment.css";

export default function AiAssessment({ assessment }) {
  if (!assessment) return null;

  if (!assessment.available) {
    return (
      <div className="ai-assessment ai-assessment--unavailable">
        <h3>AI Analyst Assessment</h3>
        <p>{assessment.summary || "AI analysis unavailable"}</p>
      </div>
    );
  }

  return (
    <div className="ai-assessment">
      <h3>AI Analyst Assessment</h3>
      <p className="ai-assessment__summary">{assessment.summary}</p>

      {assessment.key_evidence?.length > 0 && (
        <div className="ai-assessment__section">
          <h4>Key Evidence</h4>
          <ul>
            {assessment.key_evidence.map((item, i) => (
              <li key={i}>{item}</li>
            ))}
          </ul>
        </div>
      )}

      {assessment.recommended_investigation?.length > 0 && (
        <div className="ai-assessment__section">
          <h4>Recommended Investigation Steps</h4>
          <ul>
            {assessment.recommended_investigation.map((item, i) => (
              <li key={i}>{item}</li>
            ))}
          </ul>
        </div>
      )}

      {assessment.suggested_next_actions?.length > 0 && (
        <div className="ai-assessment__section">
          <h4>Suggested Next Actions</h4>
          <ul>
            {assessment.suggested_next_actions.map((item, i) => (
              <li key={i}>{item}</li>
            ))}
          </ul>
        </div>
      )}

      {assessment.confidence_statement && (
        <p className="ai-assessment__confidence">{assessment.confidence_statement}</p>
      )}
    </div>
  );
}