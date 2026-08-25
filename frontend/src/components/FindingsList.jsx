import "./FindingsList.css";

export default function FindingsList({ findings }) {
  if (!findings?.length) return null;

  return (
    <div className="findings-list">
      <h3>Findings</h3>
      <ul>
        {findings.map((finding, i) => (
          <li key={i}>{finding}</li>
        ))}
      </ul>
    </div>
  );
}