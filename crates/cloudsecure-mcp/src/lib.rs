//! CloudSecure Model Context Protocol (MCP) Shared Foundation
//!
//! Standard JSON-RPC 2.0 types and protocol dispatcher for Model Context Protocol
//! stdio servers integrated into CloudSecure applications.

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum McpError {
    #[error("Parse error (-32700): {0}")]
    ParseError(String),
    #[error("Invalid request (-32600): {0}")]
    InvalidRequest(String),
    #[error("Method not found (-32601): {0}")]
    MethodNotFound(String),
    #[error("Invalid params (-32602): {0}")]
    InvalidParams(String),
    #[error("Internal error (-32603): {0}")]
    InternalError(String),
    #[error("Tool execution failed: {0}")]
    ToolExecutionFailed(String),
}

impl McpError {
    pub fn error_code(&self) -> i32 {
        match self {
            Self::ParseError(_) => -32700,
            Self::InvalidRequest(_) => -32600,
            Self::MethodNotFound(_) => -32601,
            Self::InvalidParams(_) => -32602,
            Self::InternalError(_) => -32603,
            Self::ToolExecutionFailed(_) => -32000,
        }
    }
}

/// JSON-RPC 2.0 Request structure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpRequest {
    pub jsonrpc: String,
    pub id: Option<serde_json::Value>,
    pub method: String,
    #[serde(default)]
    pub params: Option<serde_json::Value>,
}

/// JSON-RPC 2.0 Response structure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpResponse {
    pub jsonrpc: String,
    pub id: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<McpResponseError>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpResponseError {
    pub code: i32,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

/// MCP Server Info metadata returned upon initialization.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpServerInfo {
    pub name: String,
    pub version: String,
}

/// Description of an executable tool exposed over MCP.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpTool {
    pub name: String,
    pub description: String,
    #[serde(rename = "inputSchema")]
    pub input_schema: serde_json::Value,
}

/// Content payload block returned by tools/call.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpContent {
    #[serde(rename = "type")]
    pub content_type: String,
    pub text: String,
}

impl McpContent {
    pub fn text(content: impl Into<String>) -> Self {
        Self {
            content_type: "text".into(),
            text: content.into(),
        }
    }
}

/// Standard success response builder for an MCP initialization handshake.
pub fn make_initialize_response(id: Option<serde_json::Value>, server_name: &str, version: &str) -> McpResponse {
    McpResponse {
        jsonrpc: "2.0".into(),
        id,
        result: Some(serde_json::json!({
            "protocolVersion": "2024-11-05",
            "capabilities": { "tools": {} },
            "serverInfo": {
                "name": server_name,
                "version": version
            }
        })),
        error: None,
    }
}

/// Standard error response builder.
pub fn make_error_response(id: Option<serde_json::Value>, err: McpError) -> McpResponse {
    McpResponse {
        jsonrpc: "2.0".into(),
        id,
        result: None,
        error: Some(McpResponseError {
            code: err.error_code(),
            message: err.to_string(),
            data: None,
        }),
    }
}

/// Standard tool call result builder.
pub fn make_tool_result_response(id: Option<serde_json::Value>, content_text: String) -> McpResponse {
    McpResponse {
        jsonrpc: "2.0".into(),
        id,
        result: Some(serde_json::json!({
            "content": [
                {
                    "type": "text",
                    "text": content_text
                }
            ]
        })),
        error: None,
    }
}
