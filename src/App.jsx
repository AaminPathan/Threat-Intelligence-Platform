import { useEffect, useState } from "react";
import "./App.css";

function App() {
  const [message, setMessage] = useState("Loading...");

  useEffect(() => {
    fetch("http://localhost:8000/")
      .then((res) => res.json())
      .then((data) => setMessage(data.message))
      .catch(() => setMessage("Could not reach the API"));
  }, []);

  return (
    <div className="app">
      <h1>Threat Intelligence Platform</h1>
      <p className="status">{message}</p>
    </div>
  );
}

export default App;