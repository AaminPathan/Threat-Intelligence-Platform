import { useState } from "react";
import SearchBar from "./components/SearchBar";
import RiskSummary from "./components/RiskSummary";
import SourceCard from "./components/SourceCard";
import FindingsList from "./components/FindingsList";
import AiAssessment from "./components/AiAssessment";
import { analyzeIndicator } from "./api/client";
import "./App.css";

const SOURCE_LABELS = {
  virustotal: "VirusTotal",
  abuseipdb: "AbuseIPDB",
  otx: "AlienVault OTX",
};

export default function App() {
  const [result, setResult] = useState(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState("");

  const handleAnalyze = async (indicator) => {
    setIsLoading(true);
    setError("");
    setResult(null);

    try {
      const data = await analyzeIndicator(indicator);

      if (!data.valid) {
        setError(data.error || "This does not look like a valid IOC.");
        return;
      }

      setResult(data);
    } catch (err) {
      setError("Could not reach the backend. Make sure the API server is running and try again.");
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="app">
      <header className="app__header">
        <h1>Threat Intelligence Platform</h1>
        <p>Investigate IPs, domains, URLs, and file hashes across multiple threat-intel sources.</p>
      </header>

      <SearchBar onAnalyze={handleAnalyze} isLoading={isLoading} />

      {isLoading && <p className="app__status">Analyzing indicator...</p>}
      {error && <p className="app__status app__status--error">{error}</p>}

      {result && (
        <div className="app__results">
          <RiskSummary indicator={result.indicator} iocType={result.ioc_type} risk={result.risk} />

          <div className="app__source-cards">
            {Object.entries(SOURCE_LABELS).map(([key, label]) => (
              <SourceCard key={key} name={key} label={label} data={result.sources?.[key]} />
            ))}
          </div>

          <FindingsList findings={result.findings} />
          <AiAssessment assessment={result.ai_assessment} />
        </div>
      )}
    </div>
  );
}