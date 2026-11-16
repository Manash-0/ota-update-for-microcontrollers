#!/usr/bin/env bash
# gen_keys.sh - Shell wrapper to invoke Python key generator
set -e
cd "$(dirname "$0")"
python gen_keys.py

