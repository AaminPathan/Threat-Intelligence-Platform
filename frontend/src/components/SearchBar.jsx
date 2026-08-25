import { useState } from "react";
import "./SearchBar.css";

export default function SearchBar({ onAnalyze, isLoading }) {
  const [value, setValue] = useState("");
  const [localError, setLocalError] = useState("");

  const handleSubmit = (e) => {
    e.preventDefault();
    const trimmed = value.trim();
    if (!trimmed) {
      setLocalError("Please enter an IP, domain, URL, or file hash.");
      return;
    }
    setLocalError("");
    onAnalyze(trimmed);
  };

  return (
    <form className="search-bar" onSubmit={handleSubmit}>
      <input
        type="text"
        className="search-bar__input"
        placeholder="Enter IP, domain, URL or file hash"
        value={value}
        onChange={(e) => setValue(e.target.value)}
        disabled={isLoading}
      />
      <button type="submit" className="search-bar__button" disabled={isLoading}>
        {isLoading ? "Analyzing..." : "Analyze Indicator"}
      </button>
      {localError && <p className="search-bar__error">{localError}</p>}
    </form>
  );
}