"""
LangGraph-based autonomous AI agent for analyzing security scan data using Gemini's native function calling.

The agent autonomously decides which tools to invoke and when to terminate, without workflow restrictions.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any, TypedDict

from langgraph.graph import StateGraph, START, END

from ai_module.schemas import AnalyzeRequest, AnalyzeResponse
from ai_module.tools import TOOLS
from ai_module import thresholds


class ToolInvocation(TypedDict):
    """Record of a tool call and its result."""
    tool_name: str
    tool_args: dict[str, Any]
    result: dict[str, Any]


class AgentState(TypedDict):
    """State maintained across agent execution."""
    scan_data: AnalyzeRequest
    tool_calls: list[ToolInvocation]  # History of tool invocations
    observations: dict[str, Any]  # Aggregated tool results
    risk_assessment: dict[str, Any]  # Agent's risk analysis
    iteration_count: int
    final_decision: dict[str, Any] | None  # Final decision with classify, reason, etc.
    termination_reason: str


def get_gemini_tool_definitions() -> list[dict[str, Any]]:
    """
    Return Gemini-compatible function calling definitions for all tools.
    These are passed to Gemini API via the 'tools' parameter.
    """
    return [
        {
            "name": "call_auth_summary",
            "description": "Validate and summarize email authentication (SPF, DKIM, DMARC) results.",
            "parameters": {
                "type": "object",
                "properties": {},
                "required": [],
            },
        },
        {
            "name": "call_email_signal",
            "description": "Analyze email phishing and fraud signals including risk scores and labels.",
            "parameters": {
                "type": "object",
                "properties": {},
                "required": [],
            },
        },
        {
            "name": "call_file_signal",
            "description": "Analyze attachment malware and risk signals. Can optionally scan specific file indices.",
            "parameters": {
                "type": "object",
                "properties": {
                    "file_indices": {
                        "type": "array",
                        "items": {"type": "integer"},
                        "description": "Optional: specific attachment indices to analyze (0-based). If omitted, analyzes all.",
                    }
                },
                "required": [],
            },
        },
        {
            "name": "call_web_signal",
            "description": "Analyze URL threat intel and web-borne risk signals. Can optionally scan specific URLs.",
            "parameters": {
                "type": "object",
                "properties": {
                    "urls": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Optional: specific URLs to analyze. If omitted, analyzes all.",
                    }
                },
                "required": [],
            },
        },
        {
            "name": "call_url_domains",
            "description": "Extract unique domains from URLs for threat analysis. Complements web_signal analysis.",
            "parameters": {
                "type": "object",
                "properties": {
                    "urls": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Optional: specific URLs to extract domains from. If omitted, extracts from all.",
                    }
                },
                "required": [],
            },
        },
        {
            "name": "call_risk_rollup",
            "description": "Aggregate all collected signals into a composite risk score and final assessment.",
            "parameters": {
                "type": "object",
                "properties": {},
                "required": [],
            },
        },
    ]


def _map_tool_call_to_function(tool_name: str) -> str:
    """Map Gemini tool call name back to function name."""
    mapping = {
        "call_auth_summary": "auth_summary",
        "call_email_signal": "email_signal",
        "call_file_signal": "file_signal",
        "call_web_signal": "web_signal",
        "call_url_domains": "url_domains",
        "call_risk_rollup": "risk_rollup",
    }
    return mapping.get(tool_name, tool_name)


async def router_node(state: AgentState) -> AgentState:
    """
    Router node: LLM (Gemini) decides next action using native function calling.
    Returns the updated state with LLM decision about which tool to call next or whether to terminate.
    """
    # NOTE: In real implementation, this would call Gemini API with function calling.
    # For now, this returns a structured response that would come from the LLM.
    # The actual Gemini integration happens in GeminiProvider.analyze()
    
    # This is a placeholder - the actual implementation will be called from GeminiProvider
    # which handles the Gemini HTTP calls with the tools parameter
    return state


async def execute_tools_node(state: AgentState) -> AgentState:
    """
    Execute tools node: runs the requested tool and captures its output.
    Tool names come from the LLM's function call decisions.
    """
    # This node will be integrated into the async generator pattern for streaming responses
    # For now, tools are executed synchronously as they don't do async I/O
    return state


async def analyze_results_node(state: AgentState) -> AgentState:
    """
    Analyze results node: aggregates tool outputs into observations and prepares context for next routing decision.
    """
    # Aggregate observations from latest tool calls
    for invocation in state["tool_calls"]:
        tool_name = invocation["tool_name"]
        result = invocation["result"]
        if tool_name not in state["observations"]:
            state["observations"][tool_name] = result
        else:
            # For duplicate tools, merge results (if applicable)
            if isinstance(state["observations"][tool_name], dict) and isinstance(result, dict):
                state["observations"][tool_name].update(result)
            else:
                state["observations"][tool_name] = result
    
    return state


async def terminate_node(state: AgentState) -> AgentState:
    """
    Terminate node: formats final decision and prepares response.
    This is invoked when the LLM decides to conclude the analysis.
    """
    # The final decision should already be set by the LLM's final output
    # This node just marks termination
    if state["final_decision"] is None:
        # Fallback: if no decision was made, create a default one
        state["final_decision"] = {
            "classify": "suspicious",
            "reason": "Analysis inconclusive - marking as suspicious for review.",
            "summary": "Agent terminated without clear conclusion.",
            "risk_factors": [],
            "danger_reasons": [],
            "safe_reasons": [],
            "confidence_percent": 40,
            "should_escalate": True,
        }
    
    return state


class LangGraphAgent:
    """
    Autonomous agent using LangGraph for orchestrating Gemini-based security analysis.
    
    The agent uses LangGraph's state machine to manage:
    - Tool selection and execution
    - State transitions (route -> execute -> analyze -> route or terminate)
    - Iteration limits and timeouts
    
    Gemini makes autonomous decisions via native function calling - no hard workflow constraints.
    """
    
    def __init__(self, max_iterations: int = 10, timeout_seconds: float = 60.0):
        """
        Initialize the LangGraph agent.
        
        Args:
            max_iterations: Maximum loop iterations before forced termination (safety limit)
            timeout_seconds: Maximum execution time in seconds
        """
        self.max_iterations = max_iterations
        self.timeout_seconds = timeout_seconds
        self._graph: Any = None
    
    def build_graph(self) -> Any:
        """
        Build and return the compiled LangGraph state machine.
        
        State flow:
          START -> router_node
          router_node -> (execute_tools_node | terminate_node)
          execute_tools_node -> analyze_results_node -> router_node
          terminate_node -> END
        """
        if self._graph is not None:
            return self._graph
        
        graph = StateGraph(AgentState)
        
        # Add nodes
        graph.add_node("router", router_node)
        graph.add_node("execute_tools", execute_tools_node)
        graph.add_node("analyze_results", analyze_results_node)
        graph.add_node("terminate", terminate_node)
        
        # Add edges
        graph.add_edge(START, "router")
        
        # Router decides: call tools or terminate
        # In real implementation, conditional edges would be based on LLM output
        # For now, structurally: router -> execute_tools -> analyze -> back to router, or router -> terminate
        graph.add_edge("router", "execute_tools")
        graph.add_edge("execute_tools", "analyze_results")
        graph.add_edge("analyze_results", "router")
        graph.add_edge("router", "terminate")
        graph.add_edge("terminate", END)
        
        self._graph = graph.compile()
        return self._graph
    
    def get_tool_definitions(self) -> list[dict[str, Any]]:
        """Return Gemini-compatible tool definitions."""
        return get_gemini_tool_definitions()
    
    def execute_tool(self, tool_name: str, tool_args: dict[str, Any], scan_data: AnalyzeRequest) -> dict[str, Any]:
        """
        Execute a tool synchronously and return its result.
        
        Args:
            tool_name: Name of the tool (from Gemini's function call)
            tool_args: Arguments to pass to the tool
            scan_data: The AnalyzeRequest payload
        
        Returns:
            Tool execution result
        """
        # Map Gemini's function call name to internal tool name
        func_name = _map_tool_call_to_function(tool_name)
        
        if func_name not in TOOLS:
            return {"error": f"Unknown tool: {func_name}"}
        
        try:
            tool_func = TOOLS[func_name]
            result = tool_func(scan_data, tool_args)
            return result
        except Exception as e:
            return {"error": f"Tool execution failed: {str(e)}", "tool": func_name}
    
    async def invoke(self, scan_data: AnalyzeRequest) -> dict[str, Any]:
        """
        Invoke the agent with scan data.
        NOTE: This is a simplified sync version. Real version would be async with streaming.
        
        Args:
            scan_data: The AnalyzeRequest to analyze
        
        Returns:
            Final analysis result
        """
        initial_state: AgentState = {
            "scan_data": scan_data,
            "tool_calls": [],
            "observations": {},
            "risk_assessment": {},
            "iteration_count": 0,
            "final_decision": None,
            "termination_reason": "pending",
        }
        
        # This is where the actual LLM loop would happen in a real async implementation
        # For now, this returns the structure to be populated by GeminiProvider
        return initial_state


def create_langgraph_agent(max_iterations: int = 10, timeout_seconds: float = 60.0) -> LangGraphAgent:
    """
    Factory function to create a LangGraph agent.
    
    Args:
        max_iterations: Safety limit on loop iterations
        timeout_seconds: Timeout for total execution
    
    Returns:
        Configured LangGraphAgent instance
    """
    return LangGraphAgent(max_iterations=max_iterations, timeout_seconds=timeout_seconds)
