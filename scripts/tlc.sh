#!/usr/bin/env bash
set -euo pipefail
jar="${TLA2TOOLS_JAR:-}"
if [ -z "$jar" ] && [ -f "../_tools/tla2tools.jar" ]; then
  jar="../_tools/tla2tools.jar"
fi
if [ -z "$jar" ] && [ -f "tools/tla2tools.jar" ]; then
  jar="tools/tla2tools.jar"
fi
if command -v java >/dev/null 2>&1 && [ -n "$jar" ] && [ -f "$jar" ]; then
  java -XX:+UseParallelGC -cp "$jar" tlc2.TLC -workers auto -config specs/DenyByDefault.cfg specs/DenyByDefault.tla
else
  echo "SKIP TLC: java or tla2tools.jar not found"
fi
