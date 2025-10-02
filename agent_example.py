import os
import logging

def call_mcp_server(url, input_text, api_token=None):
    """Calls the MCP server with the given URL and input."""
    # Get token from environment if not provided
    if not api_token:
        api_token = os.getenv("TOPOLOGRAPH_API_TOKEN")
    
    # Prepare headers for authentication
    headers = {}
    if api_token:
        headers["Authorization"] = f"Bearer {api_token}"
        headers["Accept"] = "application/json, text/event-stream"
        headers["Content-Type"] = "application/json"
    
    logging.debug(f"MCP Server URL: {url}/mcp")
    logging.debug(f"Using API Token: {'Yes' if api_token else 'No'}")
    logging.debug(
        f"Request payload: {{'model': 'gpt-4o-mini', 'tools': "
        f"[{{'type': 'mcp', 'server_label': 'OSPF_Analyser', 'server_url': "
        f"'{url}/mcp', 'require_approval': 'never'}}], 'input': '{input_text}'}}"
    )
    
    try:
        # Configure MCP server with authentication headers
        mcp_config = {
            "type": "mcp",
            "server_label": "OSPF_Analyser",
            "server_url": f"{url}/mcp",
            "require_approval": "never",
        }
        
        # Add headers if token is available
        if headers:
            mcp_config["headers"] = headers
        
        response = client.responses.create(
            model="gpt-4o-mini",
            tools=[mcp_config],
            input=input_text,
        )
        logging.debug(f"Response: {response.output_text}")
        logging.debug(f"Input tokens: {response.usage.input_tokens}")
        logging.debug(f"Output tokens: {response.usage.output_tokens}")
        logging.debug(f"Total tokens: {response.usage.total_tokens}")
        return response.output_text
    except Exception as e:
        logging.exception(f"An error occurred: {e}")
        return f"An error occurred: {e}"

# Alternative implementation using direct HTTP requests
def call_mcp_server_direct(url, input_text, api_token=None):
    """Calls the MCP server directly using HTTP requests."""
    import requests
    import json
    
    # Get token from environment if not provided
    if not api_token:
        raise ValueError("API token is required")
    
    # Prepare headers for authentication
    headers = {
        "Accept": "application/json, text/event-stream",
        "Content-Type": "application/json"
    }
    
    if api_token:
        headers["Authorization"] = f"Bearer {api_token}"
    
    # MCP JSON-RPC request
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "get_all_graphs",  # Example tool call
            "arguments": {}
        }
    }
    
    mcp_url = f"{url}/mcp"
    logging.debug(f"MCP Server URL: {mcp_url}")
    logging.debug(f"Using API Token: {'Yes' if api_token else 'No'}")
    logging.debug(f"Request payload: {json.dumps(payload, indent=2)}")
    
    try:
        response = requests.post(
            mcp_url,
            headers=headers,
            json=payload,
            timeout=30
        )
        response.raise_for_status()
        
        # Handle Server-Sent Events response
        if response.headers.get('content-type') == 'text/event-stream':
            # Parse SSE response
            lines = response.text.strip().split('\n')
            for line in lines:
                if line.startswith('data: '):
                    data = json.loads(line[6:])  # Remove 'data: ' prefix
                    logging.debug(f"MCP Response: {json.dumps(data, indent=2)}")
                    return data
        else:
            # Regular JSON response
            data = response.json()
            logging.debug(f"MCP Response: {json.dumps(data, indent=2)}")
            return data
            
    except requests.exceptions.RequestException as e:
        logging.exception(f"HTTP request failed: {e}")
        return f"HTTP request failed: {e}"
    except json.JSONDecodeError as e:
        logging.exception(f"JSON decode error: {e}")
        return f"JSON decode error: {e}"
    except Exception as e:
        logging.exception(f"An error occurred: {e}")
        return f"An error occurred: {e}"

# Example usage
if __name__ == "__main__":
    # Set up logging
    logging.basicConfig(level=logging.DEBUG)
    
    # Example usage
    url = "http://localhost:8080"
    input_text = "Get all available graphs"
    api_token = os.getenv("TOPOLOGRAPH_API_TOKEN")
    
    print("Testing MCP server call...")
    result = call_mcp_server_direct(url, input_text, api_token)
    print(f"Result: {result}")


