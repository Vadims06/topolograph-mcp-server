FROM python:3.13-slim

WORKDIR /app

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy your MCP server code
COPY schemas.py .
COPY mcp-server.py .

# Expose port
EXPOSE 8000

# Run your MCP server
CMD ["python", "mcp-server.py"]
