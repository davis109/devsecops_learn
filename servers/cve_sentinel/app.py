"""
CVE Sentinel FastAPI Application
"""

import os
from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
from contextlib import asynccontextmanager

from helios.mcp_protocol import MCPRequest, MCPResponse
from servers.cve_sentinel.server import CVESentinelServer
from helios.logging_config import get_logger

logger = get_logger(__name__)

# Initialize MCP server
mcp_server: CVESentinelServer | None = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifecycle management"""
    global mcp_server
    
    nvd_api_key = os.getenv("NVD_API_KEY")
    github_token = os.getenv("GITHUB_TOKEN")
    
    mcp_server = CVESentinelServer(
        nvd_api_key=nvd_api_key,
        github_token=github_token
    )
    logger.info("CVE Sentinel MCP Server started")
    
    yield
    
    logger.info("CVE Sentinel MCP Server shutting down")


app = FastAPI(
    title="CVE Sentinel MCP Server",
    description="Monitors vulnerability databases and analyzes CVE reports",
    version="1.0.0",
    lifespan=lifespan
)


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "server": "cve-sentinel"}


@app.post("/mcp")
async def handle_mcp_request(request: MCPRequest) -> MCPResponse:
    """Handle MCP JSON-RPC requests"""
    if not mcp_server:
        raise HTTPException(status_code=500, detail="MCP server not initialized")
    
    try:
        response = await mcp_server.handle_request(request)
        return response
    except Exception as e:
        logger.error(f"Error handling MCP request: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/tools")
async def list_tools():
    """List available tools"""
    if not mcp_server:
        raise HTTPException(status_code=500, detail="MCP server not initialized")
    
    tools = mcp_server.tool_registry.list_tools()
    return {"tools": [tool.model_dump() for tool in tools]}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app:app",
        host="0.0.0.0",
        port=8001,
        log_level="info",
        reload=False
    )
