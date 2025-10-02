# Topolograph MCP Server

A Model Context Protocol (MCP) server that provides access to Topolograph API for OSPF/IS-IS network analysis.

## Overview

This MCP server enables AI agents to interact with Topolograph API to analyze network topologies, monitor events, and perform path calculations for OSPF and IS-IS protocols. MCP (Model Context Protocol) is essential for connecting Large Language Models (LLMs) to network infrastructure, allowing AI agents to query and analyze network data in real-time.

This MCP server is included in the [topolograph-docker](https://github.com/Vadims06/topolograph-docker) repository and is available via the provided `docker-compose.yml` file.

## Features

- **Graph Management**: Retrieve and upload network graphs
- **Network Analysis**: Query network information by IP, node ID, or network mask
- **Event Monitoring**: Track network and adjacency events with time filtering
- **Path Calculation**: Calculate shortest paths between nodes with backup path support
- **Status Monitoring**: Check graph connectivity and health status
- **Node/Edge Queries**: Retrieve detailed node and edge information from diagrams

## Installation

```bash
pip install -r requirements.txt
```

## Configuration

Set the required environment variable:

```bash
export TOPOLOGRAPH_API_BASE="https://your-topolograph-api-url"
```

Optional authentication:

```bash
export TOPOLOGRAPH_API_TOKEN="your-api-token"
```

## Usage

Start the MCP server:

```bash
python mcp-server.py
```

The server runs on `http://0.0.0.0:8000/mcp` by default.

### Docker Compose Integration

This MCP server is included in the [topolograph-docker](https://github.com/Vadims06/topolograph-docker) repository. To use it as part of the complete Topolograph stack:

```bash
git clone https://github.com/Vadims06/topolograph-docker.git
cd topolograph-docker
docker-compose pull
docker-compose up -d
```

The MCP server will be available at `http://localhost:8000/mcp` and automatically connects to the Flask API.

## Available Tools

- `get_all_graphs`: List available graphs with filtering options
- `get_graph_by_time`: Fetch specific graph by time
- `get_network_by_graph_time`: Query network information
- `get_graph_status`: Check graph health and connectivity
- `get_network_events`: Retrieve network up/down events
- `get_adjacency_events`: Get node/host and link events
- `get_nodes`: Query diagram nodes
- `get_edges`: Query diagram edges
- `get_shortest_path`: Calculate shortest paths between nodes
- `upload_graph`: Upload new graphs to the API

## License

See LICENSE file for details.
