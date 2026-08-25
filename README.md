# AI-Powered Threat Intelligence Platform

A full-stack tool for investigating Indicators of Compromise (IOCs) — IPs, domains,
URLs, and file hashes — by correlating data from multiple threat-intelligence
sources and generating a deterministic risk score plus an AI-written analyst summary.

## Architecture

- **Backend:** Python + FastAPI, async I/O via httpx
- **Frontend:** React + Vite
- **Risk scoring:** deterministic Python heuristic (not AI-driven)
- **AI analyst:** explains already-collected evidence — never invents facts or sets the score