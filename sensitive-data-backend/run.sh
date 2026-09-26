#!/usr/bin/env bash
set -e
python3 -m uvicorn app.main:app --reload --port 8000
