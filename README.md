# Threat Intelligence Platform

A minimal foundation for an AI-Powered Threat Intelligence Platform, built with a FastAPI backend and a React (Vite) frontend.

## Tech Stack

- **Backend:** Python, FastAPI
- **Frontend:** React, Vite
- **Environment:** Windows development setup

## Getting Started

### Backend
```
cd backend
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
uvicorn main:app --reload
```
Runs at http://localhost:8000

### Frontend
```
cd frontend
npm install
npm run dev
```
Runs at http://localhost:5173