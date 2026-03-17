FROM ollama/ollama:latest

RUN if command -v apt-get > /dev/null 2>&1; then \
      apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*; \
    elif command -v apk > /dev/null 2>&1; then \
      apk add --no-cache curl; \
    else \
      echo "No supported package manager found to install curl" && exit 1; \
    fi