import os
import json
import sqlite3
from typing import Dict, List, Any, Optional, TypedDict
from datetime import datetime, timedelta
from dotenv import load_dotenv

# LangChain imports
from langchain_core.messages import HumanMessage, AIMessage, RemoveMessage
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import JsonOutputParser

# LangChain Google imports
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_openai import ChatOpenAI

# LangGraph imports
from langgraph.graph import StateGraph, END, START, MessagesState
from langgraph.checkpoint.memory import MemorySaver
from langgraph.types import interrupt, Command
from logger import setup_logger
logger = setup_logger('server.log')
logger.info("User logged in.")

from db import initialize_database

# Ensure DB is initialized at startup
initialize_database()


# Load environment
load_dotenv()
if not os.environ.get("GOOGLE_API_KEY"):
    os.environ["GOOGLE_API_KEY"] = os.getenv("GOOGLE_API_KEY")
llm = ChatGoogleGenerativeAI(
    model="gemini-2.5-flash",
    temperature=0,
    max_tokens=None,
    timeout=None,
    max_retries=2,
)

# Instantiate the in-memory checkpointer
checkpointer = MemorySaver()

class State(MessagesState):
    summary: str

# Define the workflow state
class SecurityState(TypedDict):
    # Input data
    logs: str
    
    # Level 2: Data Processing & Detection
    parsed_logs: List[Dict[str, Any]]
    alerts: List[Dict[str, Any]]
    
    # Level 3: Contextual Enrichment & Investigation
    investigation_results: Dict[str, Any]
    threat_intel_data: Optional[Dict[str, Any]]
    context_data: Optional[Dict[str, Any]]
    correlation_results: Optional[Dict[str, Any]]
    
    # Level 4: Validation & Explanation
    fact_checker_results: Optional[Dict[str, Any]]
    explanation: Optional[str]
    
    # Level 5: Decision & Response
    decision: Optional[Dict[str, Any]]
    remediation_plan: Optional[List[Dict[str, Any]]]
    human_feedback: Optional[str]  
    remediation_actions: Optional[List[Dict[str, Any]]]
    rollback_status: Optional[Dict[str, Any]]
    
    # Level 6: Monitoring & Feedback
    trust_scores: Optional[Dict[str, Any]]
    training_signals: Optional[Dict[str, Any]]
    behavioral_memory: Optional[Dict[str, Any]]
    
    # Level 7: Support & Management
    case_summary: Optional[str]
    summary: Optional[str]  # Store conversation summary
    
    # Workflow management
    messages: Optional[List[Any]]  # Store conversation history
    needs_human_feedback: Optional[bool]

# -------------------------------
# LEVEL 1: ORCHESTRATION
# -------------------------------


# -------------------------------
# LEVEL 2: DATA PROCESSING & DETECTION
# -------------------------------
def parse_logs(logs: str) -> List[Dict[str, Any]]:
    """Data Collection Agent: Parses raw logs and structures them into the defined schema."""
    parsed = []
    for line in logs.strip().splitlines():
        if not line.strip():
            continue
        try:
            parsed.append(json.loads(line))
        except json.JSONDecodeError:
            parts = line.split()
            if len(parts) >= 3:
                ts = parts[0] + " " + parts[1]
                msg = " ".join(parts[2:])
                
                # Better IP extraction - look for patterns like ip=192.168.1.100
                ip = None
                for part in parts:
                    if part.startswith("ip="):
                        ip = part.split("=")[1]
                        break
                
                # Extract username from user=john.smith@example.com pattern
                user = None
                for part in parts:
                    if part.startswith("user="):
                        user = part.split("=")[1]
                        break
                
                # Extract action type
                action = None
                for part in parts:
                    if part.startswith("action="):
                        action = part.split("=")[1]
                        break
                
                parsed.append({
                    "timestamp": ts,
                    "message": msg,
                    "ip_address": ip,
                    "username": user,
                    "action": action,  # Added action extraction
                    "raw": line
                })
    logger.info("Data collection agent: logs parsed successfully :%s",parsed)
    return parsed

def detection_agent(state: SecurityState) -> SecurityState:
    """Detection Agent: Analyzes structured logs for anomalies and suspicious patterns."""
    # Check if we have conversation summary and include it
    summary = state.get("summary", "")
    system_prompt = """You are a Detection Agent responsible for identifying suspicious activities in log data.
    Analyze the logs provided and flag any suspicious events such as:
    1. Authentication attempts from unusual locations
    2. Multiple failed login attempts
    3. Access to sensitive resources
    4. Unusual user behavior
    5. Known malicious signatures"""
        
    if summary:
        system_prompt += f"\n\nSummary of previous analysis for this user: {summary}"
        
    system_prompt += """\n\nReturn only JSON with the following structure:
    {{
        "alerts": [
            {{
                "alert_id": "unique_id",
                "severity": "high/medium/low",
                "description": "Description of the suspicious activity",
                "related_log_entries": [indices],
                "source_ip": "IP if available",
                "username": "Username if available",
                "timestamp": "When this occurred"
            }}
        ]
    }}"""

    prompt = ChatPromptTemplate.from_messages([
        ("system", system_prompt),
        ("human", "Here are the logs to analyze:\n{parsed_logs}")
    ])
    parser = JsonOutputParser()
    chain = prompt | llm | parser

    # Add to messages
    if "messages" not in state:
        state["messages"] = []
    
    human_message = HumanMessage(content=f"Please analyze these logs:\n{json.dumps(state.get('parsed_logs', []), indent=2)}")
    state["messages"].append(human_message)

    out = chain.invoke({
        "parsed_logs": json.dumps(state.get("parsed_logs", []), indent=2)
    })
    
    # Add AI response to messages
    ai_message = AIMessage(content=f"Alert analysis complete. Found {len(out.get('alerts', []))} suspicious activities.")
    state["messages"].append(ai_message)
    
    state["alerts"] = out.get("alerts", [])
    logger.info("Detection agent: alerts found successfully :%s",state["alerts"])
    return state

# -------------------------------
# LEVEL 3: CONTEXTUAL ENRICHMENT & INVESTIGATION
# -------------------------------

def investigation_agent(state: SecurityState) -> SecurityState:
    """Investigation Agent: Gathers alert context (logs, user history, geolocation)."""
    if not state["alerts"]:
        state["investigation_results"] = {
            "conclusion": "No alerts to investigate",
            "details": {},
            "threat_level": "none"
        }
        return state

    # Include summary if available
    summary = state.get("summary", "")
    system_prompt = """You are an Investigation Agent responsible for conducting deeper analysis on security alerts.
    For each alert, examine:
    1. Context around the event
    2. Historical patterns
    3. GeoIP information
    4. User behavior history
    5. Entity behavior analytics"""

    if summary:
        system_prompt += f"\n\nSummary of previous analysis for this user: {summary}"
        
    system_prompt += """\n\nReturn only JSON with the following structure:
    {{
        "conclusion": "Brief summary of findings",
        "details": {{
            "alert_id_1": {{
                "is_threat": true/false,
                "confidence": 0-100,
                "geolocation": {{"country": "name", "city": "name", "is_unusual": true/false}},
                "context": "Additional information",
                "entities_involved": ["users", "systems", "affected"]
            }}
        }},
        "threat_level": "critical/high/medium/low/none"
    }}"""

    prompt = ChatPromptTemplate.from_messages([
        ("system", system_prompt),
        ("human", """Here are the logs to analyze:
            {parsed_logs}

            And here are the alerts that need investigation:
            {alerts}
        """)
    ])
    parser = JsonOutputParser()
    chain = prompt | llm | parser

    # Add to messages
    human_message = HumanMessage(content=f"Please investigate these alerts:\n{json.dumps(state['alerts'], indent=2)}")
    state["messages"].append(human_message)

    out = chain.invoke({
        "parsed_logs": json.dumps(state["parsed_logs"], indent=2),
        "alerts":     json.dumps(state["alerts"],     indent=2)
    })
    
    # Add AI response to messages
    ai_message = AIMessage(content=f"Investigation complete. Threat level: {out.get('threat_level', 'unknown')}")
    state["messages"].append(ai_message)
    
    state["investigation_results"] = out
    logger.info("Investigation agent: results found successfully :%s",state["investigation_results"])
    return state

def threat_intelligence_agent(state: SecurityState) -> SecurityState:
    """Threat Intelligence Agent: Queries external feeds for IOC verification."""
    if state["investigation_results"].get("threat_level") == "none":
        state["threat_intel_data"] = {"result": "No threats identified that require external intelligence"}
        return state
    
    # Include summary if available
    summary = state.get("summary", "")
    system_prompt = """You are a Threat Intelligence Agent responsible for enriching security alerts with external threat data.
    For each finding from the investigation, query relevant external threat data sources such as:
    1. MITRE ATT&CK framework
    2. VirusTotal for known malicious indicators
    3. Known threat actor TTPs
    4. Industry threat feeds
    
    Correlate the findings with known attack patterns and provide context."""
    
    if summary:
        system_prompt += f"\n\nSummary of previous analysis for this user: {summary}"
        
    system_prompt += """\n\nReturn only JSON with the following structure:
    {{
        "intel_results": {{
            "alert_id_1": {{
                "matched_iocs": ["ioc1", "ioc2"],
                "mitre_techniques": ["T1234", "T5678"],
                "threat_actors": ["APT29", "Lazarus Group"],
                "confidence": 0-100,
                "recommendations": ["action1", "action2"]
            }}
        }},
        "overall_assessment": "Summary of threat intelligence findings"
    }}"""

    prompt = ChatPromptTemplate.from_messages([
        ("system", system_prompt),
        ("human", """Here are the investigation results that need threat intelligence enrichment:
            {investigation_results}
            
            Based on these results, provide threat intelligence context.
        """)
    ])
    parser = JsonOutputParser()
    chain = prompt | llm | parser

    # Add to messages
    human_message = HumanMessage(content=f"Please provide threat intelligence for these findings:\n{json.dumps(state['investigation_results'], indent=2)}")
    state["messages"].append(human_message)

    out = chain.invoke({
        "investigation_results": json.dumps(state["investigation_results"], indent=2)
    })
    
    # Add AI response to messages
    ai_message = AIMessage(content=f"Threat intelligence gathered: {out.get('overall_assessment', 'No significant matches')}")
    state["messages"].append(ai_message)
    
    state["threat_intel_data"] = out
    logger.info("Threat Intelligence agent: data gathered successfully :%s",state["threat_intel_data"])
    return state

def context_agent(state: SecurityState) -> SecurityState:
    """Context Agent: Fetches historical incidents and semantic memory for situational awareness."""
    if state["investigation_results"].get("threat_level") == "none":
        state["context_data"] = {"result": "No context needed for this level of threat"}
        return state
    
    # Include summary if available
    summary = state.get("summary", "")
    system_prompt = """You are a Context Agent responsible for providing historical and semantic context to security incidents.
    Examine the current investigation and:
    1. Identify similar past incidents for this user/system
    2. Provide normal behavior patterns
    3. Give organizational context relevant to this incident
    4. Supply environmental factors that might be relevant
    
    Use this historical context to help determine if this is an anomaly or part of a normal pattern."""
    
    if summary:
        system_prompt += f"\n\nSummary of previous analysis for this user: {summary}"
        
    system_prompt += """\n\nReturn only JSON with the following structure:
    {{
        "historical_context": {{
            "similar_past_incidents": ["incident1", "incident2"],
            "normal_behavior_pattern": "Description of normal patterns",
            "organizational_context": "Relevant business context",
            "is_anomalous": true/false
        }},
        "semantic_context": "Overall meaning and implications of this event in context"
    }}"""

    prompt = ChatPromptTemplate.from_messages([
        ("system", system_prompt),
        ("human", """Here are the investigation results that need historical context:
            {investigation_results}
            
            Based on these results, provide historical and semantic context.
        """)
    ])
    parser = JsonOutputParser()
    chain = prompt | llm | parser

    # Add to messages
    human_message = HumanMessage(content=f"Please provide historical context for these findings:\n{json.dumps(state['investigation_results'], indent=2)}")
    state["messages"].append(human_message)

    out = chain.invoke({
        "investigation_results": json.dumps(state["investigation_results"], indent=2)
    })
    
    # Add AI response to messages
    ai_message = AIMessage(content=f"Context analysis complete: {out.get('semantic_context', 'No significant context')}")
    state["messages"].append(ai_message)
    
    state["context_data"] = out
    logger.info("Context agent: historical context gathered successfully :%s",state["context_data"])
    return state

def correlation_agent(state: SecurityState) -> SecurityState:
    """Correlation Agent: Links multiple low-level alerts into cohesive threat narratives."""
    if state["investigation_results"].get("threat_level") == "none":
        state["correlation_results"] = {"result": "No alerts to correlate"}
        return state
    
    # Include summary if available
    summary = state.get("summary", "")
    system_prompt = """You are a Correlation Agent responsible for linking related security alerts into cohesive threat narratives.
    Review all the available data and:
    1. Identify connections between separate alerts
    2. Discover attack patterns across multiple events
    3. Construct a timeline of the potential attack
    4. Build a comprehensive threat storyline
    
    Look for subtle connections that might indicate a coordinated attack rather than isolated incidents."""
    
    if summary:
        system_prompt += f"\n\nSummary of previous analysis for this user: {summary}"
        
    system_prompt += """\n\nReturn only JSON with the following structure:
    {{
        "correlated_events": [
            {{
                "alert_ids": ["id1", "id2"],
                "correlation_type": "Description of how these alerts are related",
                "confidence": 0-100,
                "narrative": "Description of what this correlation reveals"
            }}
        ],
        "attack_timeline": [
            {{
                "timestamp": "time",
                "event": "description",
                "significance": "why this matters"
            }}
        ],
        "threat_storyline": "Overall narrative of what appears to be happening"
    }}"""

    prompt = ChatPromptTemplate.from_messages([
        ("system", system_prompt),
        ("human", """Here are the investigation results, context and threat intelligence to correlate:
            Investigation: {investigation_results}
            Threat Intel: {threat_intel_data}
            Context: {context_data}
            
            Based on all this information, provide correlation analysis.
        """)
    ])
    parser = JsonOutputParser()
    chain = prompt | llm | parser

    # Add to messages
    human_message = HumanMessage(content=f"Please correlate these findings into a cohesive threat narrative.")
    state["messages"].append(human_message)

    out = chain.invoke({
        "investigation_results": json.dumps(state["investigation_results"], indent=2),
        "threat_intel_data": json.dumps(state.get("threat_intel_data", {}), indent=2),
        "context_data": json.dumps(state.get("context_data", {}), indent=2)
    })
    
    # Add AI response to messages
    ai_message = AIMessage(content=f"Correlation complete: {out.get('threat_storyline', 'No significant correlation')}")
    state["messages"].append(ai_message)
    
    state["correlation_results"] = out
    logger.info("Correlation agent: threat narratives constructed successfully :%s",state["correlation_results"])
    return state

# -------------------------------
# LEVEL 4: VALIDATION & EXPLANATION
# -------------------------------

def fact_checker_agent(state: SecurityState) -> SecurityState:
    """Fact-Checker Agent: Verifies AI outputs against raw logs and ground truth to prevent hallucinations."""
    if state["investigation_results"].get("threat_level") == "none":
        state["fact_checker_results"] = {"result": "No facts to check"}
        return state
    
    # Include summary if available
    summary = state.get("summary", "")
    system_prompt = """You are a Fact-Checker Agent responsible for validating security findings against raw data.
    Review the findings from investigation and correlation, then verify them against the original logs to:
    1. Identify any inconsistencies between findings and raw data
    2. Detect potential AI hallucinations or overinterpretations
    3. Validate that all key assertions are firmly grounded in evidence
    4. Rate the confidence level of each finding
    
    Be skeptical and only confirm findings that are clearly supported by the raw logs."""
    
    if summary:
        system_prompt += f"\n\nSummary of previous analysis for this user: {summary}"
        
    system_prompt += """\n\nReturn only JSON with the following structure:
    {{
        "verified_findings": [
            {{
                "finding": "The original claim",
                "verification_status": "confirmed/partially_confirmed/refuted/insufficient_evidence",
                "evidence": "Raw log entries supporting or contradicting this finding",
                "confidence": 0-100,
                "notes": "Any discrepancies or caveats"
            }}
        ],
        "hallucinations_detected": [
            {{
                "finding": "The questionable claim",
                "issue": "Why this appears to be a hallucination"
            }}
        ],
        "overall_assessment": "Assessment of the overall factual reliability of the analysis"
    }}"""

    prompt = ChatPromptTemplate.from_messages([
        ("system", system_prompt),
        ("human", """Here are the raw logs and findings to fact-check:
            Raw logs: {parsed_logs}
            Investigation results: {investigation_results}
            Correlation results: {correlation_results}
            
            Please verify these findings against the raw data.
        """)
    ])
    parser = JsonOutputParser()
    chain = prompt | llm | parser

    # Add to messages
    human_message = HumanMessage(content=f"Please fact-check our findings against the raw logs.")
    state["messages"].append(human_message)

    out = chain.invoke({
        "parsed_logs": json.dumps(state["parsed_logs"], indent=2),
        "investigation_results": json.dumps(state["investigation_results"], indent=2),
        "correlation_results": json.dumps(state.get("correlation_results", {}), indent=2)
    })
    
    # Add AI response to messages
    ai_message = AIMessage(content=f"Fact-checking complete: {out.get('overall_assessment', 'Findings verified')}")
    state["messages"].append(ai_message)
    
    state["fact_checker_results"] = out
    logger.info("Fact-checker agent: findings verified successfully :%s",state["fact_checker_results"])
    return state

def explainability_agent(state: SecurityState) -> SecurityState:
    """Explainability Agent: Converts AI decisions to human-readable reasoning."""
    if state["investigation_results"].get("threat_level") == "none":
        state["explanation"] = "No significant security issues detected in the analyzed logs."
        return state
    
    # Include summary if available
    summary = state.get("summary", "")
    system_prompt = """You are an Explainability Agent responsible for making AI security analysis human-readable.
    Create clear, concise explanations of:
    1. What was detected (in non-technical terms)
    2. Why it matters (security implications)
    3. How confident we are (evidence quality)
    4. What steps are recommended (action items)
    
    Avoid jargon and technical details unless necessary. Focus on making the analysis accessible to security professionals 
    of varying technical backgrounds."""
    
    if summary:
        system_prompt += f"\n\nSummary of previous analysis for this user: {summary}"

    prompt = ChatPromptTemplate.from_messages([
        ("system", system_prompt),
        ("human", """Here's all the security analysis to explain:
            Investigation: {investigation_results}
            Correlation: {correlation_results}
            Fact-checking: {fact_checker_results}
            
            Please create a human-readable explanation of these findings.
        """)
    ])
    chain = prompt | llm

    # Add to messages
    human_message = HumanMessage(content=f"Please create a human-readable explanation of our findings.")
    state["messages"].append(human_message)

    response = chain.invoke({
        "investigation_results": json.dumps(state["investigation_results"], indent=2),
        "correlation_results": json.dumps(state.get("correlation_results", {}), indent=2),
        "fact_checker_results": json.dumps(state.get("fact_checker_results", {}), indent=2)
    })
    
    # Add AI response to messages
    ai_message = AIMessage(content=f"Explanation created.")
    state["messages"].append(ai_message)
    
    state["explanation"] = response.content
    logger.info("Explainability agent: human-readable explanation created successfully :%s",state["explanation"])
    return state

# -------------------------------
# LEVEL 5: DECISION & RESPONSE
# -------------------------------

def remediation_strategy_agent(state: SecurityState) -> SecurityState:
    """Remediation Strategy Agent: Suggests cost-risk-optimized response strategies."""
    if state["investigation_results"].get("threat_level") == "none":
        state["decision"] = {"action": "monitor", "justification": "No threats", "reasoning_path": []}
        return state

    # Include summary if available
    summary = state.get("summary", "")
    system_prompt = """You are a Remediation Strategy Agent responsible for making security incident response decisions using Tree-of-Thought reasoning.
    Given the security alerts and investigation results, determine the appropriate response action.

    Step 1: Consider all possible response actions:
    - Monitor only
    - Increase logging
    - Isolate host
    - Block IP
    - Force password reset
    - Disable account
    - Other specific actions

    Step 2: For each action, evaluate:
    - Benefits
    - Risks
    - Business impact
    - False positive consequences

    Step 3: Make a final decision with justification"""

    if summary:
        system_prompt += f"\n\nSummary of previous analysis for this user: {summary}"
        
    system_prompt += """\n\nReturn only JSON with the following structure:
    {{
            "action": "chosen_action",
            "parameters": {{"param1": "value1"}},
            "justification": "Reason for this decision",
            "reasoning_path": [
                {{"thought": "Consideration 1", "pros": ["a", "b"], "cons": ["c", "d"]}},
                {{"thought": "Consideration 2", "pros": ["e", "f"], "cons": ["g", "h"]}},
                {{"thought": "Consideration 3", "pros": ["i", "j"], "cons": ["k", "l"]}}
            ]
    }}"""

    prompt = ChatPromptTemplate.from_messages([
        ("system", system_prompt),
        ("human", """Here are the investigation results and fact-checked findings:
            Investigation: {investigation_results}
            Fact-checking: {fact_checker_results}
            Explanation: {explanation}

            Based on these results, determine the appropriate response action using tree-of-thought reasoning.
        """)
    ])
    parser = JsonOutputParser()
    chain = prompt | llm | parser

    # Add to messages
    human_message = HumanMessage(content=f"Please determine appropriate action for these results.")
    state["messages"].append(human_message)

    out = chain.invoke({
        "investigation_results": json.dumps(state["investigation_results"], indent=2),
        "fact_checker_results": json.dumps(state.get("fact_checker_results", {}), indent=2),
        "explanation": state.get("explanation", "")
    })
    
    # Add AI response to messages
    ai_message = AIMessage(content=f"Decision made: {out.get('action', 'unknown')}")
    state["messages"].append(ai_message)
    
    state["decision"] = out
    logger.info("Remediation Strategy agent: decision made successfully :%s",state["decision"])
    return state

def response_orchestration_agent(state: SecurityState) -> SecurityState:
    """Response Orchestration Agent: Executes approved remediation steps via security APIs."""
    if state["decision"]["action"] == "monitor":
        state["remediation_plan"] = []
        return state

    # Include summary if available
    summary = state.get("summary", "")
    system_prompt = """You are a Response Orchestration Agent responsible for planning security response actions.
    Given the decision from the Remediation Strategy Agent, translate this into concrete API calls to security tools.

    For this example, you can use the following API endpoints:
    1. POST /api/security/isolate_host - Isolate a host
    2. POST /api/security/block_ip - Block an IP address
    3. POST /api/security/reset_password - Force a password reset
    4. POST /api/security/disable_account - Disable a user account
    5. POST /api/security/increase_monitoring - Increase monitoring on a user or system
    6. POST /api/security/escalate_alert - Escalate to Tier 2 SOC team"""

    if summary:
        system_prompt += f"\n\nSummary of previous remediation for this user: {summary}"
        
    system_prompt += """\n\nReturn only JSON with the following structure:
    {{
        "actions": [
            {{
                "api_endpoint": "/api/endpoint",
                "method": "POST/GET/etc",
                "parameters": {{"key": "value"}},
                "expected_outcome": "Description of what this should accomplish",
                "rollback_procedure": "How to reverse this action if needed"
            }}
        ]
    }}"""

    prompt = ChatPromptTemplate.from_messages([
        ("system", system_prompt),
        ("human", """Here is the decision that needs to be implemented:
                {decision}

                Based on this decision, determine the specific API calls needed to implement the remediation.
         """)
    ])
    parser = JsonOutputParser()
    chain = prompt | llm | parser

    # Add to messages
    human_message = HumanMessage(content=f"Please create a remediation plan for this decision:\n{json.dumps(state['decision'], indent=2)}")
    state["messages"].append(human_message)

    plan = chain.invoke({
        "decision": json.dumps(state["decision"], indent=2)
    }).get("actions", [])

    state["remediation_plan"] = plan
    logger.info("Response Orchestration agent: remediation plan created successfully :%s",state["remediation_plan"])
    return state

def human_feedback_node(state: SecurityState) -> SecurityState:
    """Human in the loop to approve remediation plan or choose manual intervention"""
    # Show the remediation plan to the human and ask for approval
    human_response = interrupt({
        "task": "Review and approve remediation plan",
        "remediation_plan": state.get("remediation_plan", []),
        "alerts": state.get("alerts", []),
        "investigation_results": state.get("investigation_results", {}),
        "decision": state.get("decision", {}),
        "explanation": state.get("explanation", "No explanation available")
    })
    
    # Store the human's feedback in the state
    if human_response == "approve":
        state["human_feedback"] = "approved"
    else:  # Any other response is treated as manual intervention
        state["human_feedback"] = "manual"
    
    logger.info(f"Human feedback received: {state['human_feedback']}")
    return state

def execute_remediation(state: SecurityState) -> SecurityState:
    """Execute approved remediation plan"""
    # Check if there's a plan and if it's been approved
    if not state.get("remediation_plan") or state.get("human_feedback") != "approved":
        state["remediation_actions"] = []
        logger.info("Response Orchestration agent: no remediation actions to execute")
        return state
        
    plan = state.get("remediation_plan", [])
    executed = []
    for act in plan:
        executed.append({
            **act,
            "execution_status": "success",
            "execution_time": datetime.utcnow().isoformat(),
            "response": {"status": "completed"}
        })
    
    # Add AI response to messages
    ai_message = AIMessage(content=f"Remediation complete. Executed {len(executed)} actions.")
    state["messages"].append(ai_message)
    
    state["remediation_actions"] = executed
    logger.info("Response Orchestration agent: remediation actions executed successfully :%s",state["remediation_actions"])
    return state

def one_click_rollback_agent(state: SecurityState) -> SecurityState:
    """One-Click Rollback Agent: Provides instant rollback of executed actions if needed."""
    # Check if remediation was executed and if rollback is needed
    # For this example, we'll just set up the rollback capability but not actually roll back
    if not state.get("remediation_actions"):
        state["rollback_status"] = {"status": "No actions to roll back"}
        return state
    
    # Prepare rollback information
    rollback = {
        "available": True,
        "actions": [
            {
                "original_action": action,
                "rollback_command": f"ROLLBACK:{action['api_endpoint']}",
                "rollback_parameters": action.get("parameters", {}),
                "status": "ready"
            }
            for action in state.get("remediation_actions", [])
        ],
        "expiry_time": (datetime.utcnow() + timedelta(hours=24)).isoformat()
    }
    
    state["rollback_status"] = rollback
    logger.info("One-click Rollback agent: rollback capability prepared")
    return state


# -------------------------------
# LEVEL 6: MONITORING & FEEDBACK (continued)
# -------------------------------

def trust_calibration_agent(state: SecurityState) -> SecurityState:
    """Trust Calibration Agent: Tracks AI decision outcomes, calculates trust scores for autonomy adjustments."""
    # Calculate trust scores based on fact-checker validation
    fact_check = state.get("fact_checker_results", {})
    
    # Initialize default scores
    trust_scores = {
        "detection_trust": 95,
        "investigation_trust": 95,
        "remediation_trust": 95,
        "overall_trust": 95,
        "autonomy_level": "high",
        "last_updated": datetime.utcnow().isoformat()
    }

    if fact_check and state["investigation_results"].get("threat_level") != "none":
        confirmed = sum(1 for f in fact_check.get("verified_findings", []) 
                     if f.get("verification_status") == "confirmed")
        total = len(fact_check.get("verified_findings", []))
        
        # Calculate accuracy score (80% weight)
        accuracy = (confirmed / total) * 100 if total > 0 else 100
        # Hallucination penalty (20% weight)
        hallucination_penalty = len(fact_check.get("hallucinations_detected", [])) * 5
        
        overall_score = max(0, min(100, 
            (accuracy * 0.8) - hallucination_penalty
        ))
        
        trust_scores.update({
            "detection_trust": max(70, overall_score - 5),
            "investigation_trust": overall_score,
            "remediation_trust": min(100, overall_score + 5),
            "overall_trust": overall_score,
            "autonomy_level": "high" if overall_score >= 85 else 
                            "medium" if overall_score >= 70 else "low"
        })
    
    state["trust_scores"] = trust_scores
    logger.info("Trust Calibration agent: scores updated :%s",state["trust_scores"])
    return state

def simulation_training_agent(state: SecurityState) -> SecurityState:
    """Simulation Training Feedback Agent: Analyzes attack results and retrains models."""
    training_data = {
        "timestamp": datetime.utcnow().isoformat(),
        "incident_data": {
            "alerts": state.get("alerts", []),
            "investigation": state.get("investigation_results", {}),
            "remediation": state.get("remediation_actions", [])
        },
        "performance_metrics": {
            "detection_accuracy": state["trust_scores"]["detection_trust"],
            "response_effectiveness": state["trust_scores"]["remediation_trust"],
            "false_positives": len([f for f in state.get("fact_checker_results", {}).get("hallucinations_detected", [])])
        }
    }
    
    # Generate training signals (in real implementation, this would update detection policies)
    system_prompt = """You are a Simulation Training Agent. Analyze this incident to improve detection models:
    1. Identify detection gaps
    2. Suggest new detection rules
    3. Propose model retraining priorities
    4. Update investigation workflows"""
    
    prompt = ChatPromptTemplate.from_messages([
        ("system", system_prompt),
        ("human", "Incident data: {incident_data}")
    ])
    chain = prompt | llm
    
    training_signals = chain.invoke({
        "incident_data": json.dumps(training_data, indent=2)
    }).content
    
    state["training_signals"] = {
        "raw_data": training_data,
        "improvement_recommendations": training_signals
    }
    logger.info("Simulation Training agent: models updated :%s",state["training_signals"])
    return state

def behavioral_memory_agent(state: SecurityState) -> SecurityState:
    """Behavioral Memory Agent: Monitors long-term user/system patterns and flags deviations."""
    # Initialize memory if not exists
    if state.get("behavioral_memory") is None:
        state["behavioral_memory"] = {}

    # Extract all users from logs to process each one
    users = set(log.get("username") for log in state["parsed_logs"] if log.get("username"))
    
    for user in users:
        # Get logs related to this user
        user_logs = [log for log in state["parsed_logs"] if log.get("username") == user]
        
        # Extract behavior patterns for this user
        user_ips = set(log.get("ip_address") for log in user_logs if log.get("ip_address"))
        
        # Extract actions and count their frequencies
        actions = []
        for log in user_logs:
            # Get action from dedicated field or parse from message
            action = log.get("action")
            if not action and "message" in log:
                # Try to find action= in the message
                msg_parts = log["message"].split()
                for part in msg_parts:
                    if part.startswith("action="):
                        action = part.split("=")[1]
                        break
            
            if action:
                actions.append(action)
        
        # Create or update user profile
        if user not in state["behavioral_memory"]:
            state["behavioral_memory"][user] = {
                "normal_ips": set(),
                "common_actions": {},
                "alert_history": [],
                "last_update": None
            }
        
        # Update IP patterns
        for ip in user_ips:
            state["behavioral_memory"][user]["normal_ips"].add(ip)
        
        # Update action frequencies
        for action in actions:
            state["behavioral_memory"][user]["common_actions"][action] = \
                state["behavioral_memory"][user]["common_actions"].get(action, 0) + 1
        
        # Set last update timestamp
        from datetime import datetime
        state["behavioral_memory"][user]["last_update"] = datetime.utcnow().isoformat()
    
    # Convert sets to lists for JSON serialization
    for user in state["behavioral_memory"]:
        state["behavioral_memory"][user]["normal_ips"] = \
            list(state["behavioral_memory"][user]["normal_ips"])
    
    logger.info(f"Behavioral Memory agent: patterns updated for {len(users)} users")
    return state

# -------------------------------
# LEVEL 7: SUPPORT & MANAGEMENT
# -------------------------------

def analyst_copilot_agent(state: SecurityState) -> SecurityState:
    """Analyst Copilot Agent: Assists SOC analysts with NL queries during investigations."""
    if state.get("human_feedback") == "manual":
        system_prompt = """You are an Analyst Copilot. Assist with:
        1. Incident investigation
        2. Querying system state
        3. Explaining security concepts
        4. Generating investigation hypotheses
        
        Current incident context:
        {context}"""
        
        prompt = ChatPromptTemplate.from_messages([
            ("system", system_prompt),
            ("human", "{query}")
        ])
        
        # Get last analyst question from messages
        analyst_questions = [m.content for m in state.get("messages", []) 
                           if isinstance(m, HumanMessage) and "Copilot Query:" in m.content]
        
        if analyst_questions:
            last_query = analyst_questions[-1]
            chain = prompt | llm
            response = chain.invoke({
                "context": json.dumps(state["investigation_results"], indent=2),
                "query": last_query.replace("Copilot Query:", "")
            })
            
            state["messages"].append(AIMessage(
                content=f"Copilot Assistance:\n{response.content}"
            ))
    
    logger.info("Analyst Copilot agent: assistance provided")
    return state


def case_summary_agent(state: SecurityState) -> SecurityState:
    """Case Summary Agent: Generates comprehensive case documentation using all investigation layers"""
    system_prompt = """You are a Case Summary Agent. Create a detailed incident report including:
    1. Detection Overview - Initial alerts and detection methodology
    2. Threat Context - Intelligence findings and correlation analysis  
    3. Investigation Details - Validation results and behavioral patterns
    4. Response Actions - Executed remediation and rollback status
    5. Post-Incident Analysis - Trust metrics and improvement recommendations
    
    Structure the report for both technical staff and management review."""

    prompt = ChatPromptTemplate.from_messages([
        ("system", system_prompt),
        ("human", """Compile incident report from these components:
            
            === DETECTION DATA ===
            Alerts: {alerts}
            
            === THREAT INTELLIGENCE === 
            {threat_intel}
            
            === INVESTIGATION FINDINGS ===
            {investigation}
            Context: {context}
            Correlation: {correlation}
            
            === VALIDATION RESULTS ===
            Fact Checking: {fact_check}
            Explanation: {explanation}
            
            === RESPONSE ACTIONS ===
            Decision: {decision}
            Plan: {remediation_plan}
            Executed: {remediation_actions}
            Rollback: {rollback}
            
            === POST-INCIDENT METRICS ===
            Trust Scores: {trust_scores}
            Behavioral Patterns: {behavioral_memory}
        """)
    ])
    
    chain = prompt | llm
    
    state["messages"].append(HumanMessage(content="Generating comprehensive case summary..."))
    
    response = chain.invoke({
        "alerts": json.dumps(state["alerts"], indent=2),
        "threat_intel": json.dumps(state.get("threat_intel_data", {}), indent=2),
        "investigation": json.dumps(state["investigation_results"], indent=2),
        "context": json.dumps(state.get("context_data", {}), indent=2),
        "correlation": json.dumps(state.get("correlation_results", {}), indent=2),
        "fact_check": json.dumps(state.get("fact_checker_results", {}), indent=2),
        "explanation": state.get("explanation", "No explanation available"),
        "decision": json.dumps(state.get("decision", {}), indent=2),
        "remediation_plan": json.dumps(state.get("remediation_plan", []), indent=2),
        "remediation_actions": json.dumps(state.get("remediation_actions", []), indent=2),
        "rollback": json.dumps(state.get("rollback_status", {}), indent=2),
        "trust_scores": json.dumps(state.get("trust_scores", {}), indent=2),
        "behavioral_memory": json.dumps(state.get("behavioral_memory", {}), indent=2)
    })
    
    state["case_summary"] = response.content
    state["messages"].append(AIMessage(content="Comprehensive case summary generated"))
    logger.info("Case Summary agent: generated full-spectrum incident report :%s", state["case_summary"])
    
    return state


def summarize_conversation(state: SecurityState) -> SecurityState:
    """Summarize the conversation history when it gets too long"""
    messages = state.get("messages", [])
    
    # Get existing summary if any
    summary = state.get("summary", "")
    
    # Create summary prompt
    if summary:
        summary_message = (
            f"This is summary of the security analysis to date: {summary}\n\n"
            "Extend the summary by taking into account the new messages above:"
        )
    else:
        summary_message = "Create a summary of the security analysis conversation above:"

    # Add the summary prompt to the messages for the LLM
    prompt_messages = messages + [HumanMessage(content=summary_message)]
    
    # Call the LLM to generate a summary
    response = llm.invoke(prompt_messages)
    [RemoveMessage(id=m.id) for m in messages]
    
    logger.info("conversation summarized successfully :%s", response.content)
    return {
        **state,
        "summary": response.content,
        "messages": []
    }


# -------------------------------
# Helper Functions
# -------------------------------

def get_username_from_logs(parsed_logs):
    """Extract username from parsed logs for thread_id"""
    for log in parsed_logs:
        if log.get("username"):
            return log.get("username")
    return "unknown_user"  # Fallback


def get_latest_workflow_result(username: str) -> Optional[Dict[str, Any]]:
    """Retrieve the latest workflow result for a given username."""
    conn = sqlite3.connect('security_workflow.db')
    cursor = conn.cursor()
    
    cursor.execute(
        "SELECT result_json FROM workflow_results WHERE username = ? ORDER BY timestamp DESC LIMIT 1",
        (username,)
    )
    
    row = cursor.fetchone()
    conn.close()
    
    if row:
        return json.loads(row[0])
    return None


def run_security_workflow(logs: str, initial_state: SecurityState = None):
    # Build graph with in-memory checkpointing (state type + saver)
    workflow = StateGraph(SecurityState, checkpointer)

    # Level 2: Data Processing & Detection
    workflow.add_node("data_collection", lambda s: {**s, "parsed_logs": parse_logs(s.get("logs", ""))})
    workflow.add_node("detection", detection_agent)
    
    # Level 3: Contextual Enrichment & Investigation
    workflow.add_node("investigation", investigation_agent)
    workflow.add_node("threat_intel", threat_intelligence_agent)
    workflow.add_node("context", context_agent)
    workflow.add_node("correlation", correlation_agent)
    
    # Level 4: Validation & Explanation
    workflow.add_node("fact_checker", fact_checker_agent)
    workflow.add_node("explainability", explainability_agent)

    # Level 5: Decision & Response
    workflow.add_node("remediation_strategy", remediation_strategy_agent)
    workflow.add_node("response_orchestration", response_orchestration_agent)
    workflow.add_node("get_human_feedback", human_feedback_node)
    workflow.add_node("get_execute_remediation", execute_remediation)

    # Level 6: Monitoring & Feedback
    workflow.add_node("trust_calibration", trust_calibration_agent)
    workflow.add_node("simulation_training", simulation_training_agent)
    workflow.add_node("get_behavioral_memory", behavioral_memory_agent)
    workflow.add_node("case", case_summary_agent)
    workflow.add_node("summarize_conversation", summarize_conversation)

    # Connect edges
    workflow.add_edge(START, "data_collection")
    workflow.add_edge("data_collection", "detection")
    workflow.add_edge("detection", "investigation")
    workflow.add_edge("investigation", "threat_intel")
    workflow.add_edge("threat_intel", "context")
    workflow.add_edge("context", "correlation")
    workflow.add_edge("correlation", "fact_checker")
    workflow.add_edge("fact_checker", "explainability")
    workflow.add_edge("explainability", "remediation_strategy")
    workflow.add_edge("remediation_strategy", "response_orchestration")
    workflow.add_edge("response_orchestration", "get_human_feedback")
    workflow.add_edge("get_human_feedback", "get_execute_remediation")
    workflow.add_edge("get_execute_remediation", "trust_calibration")
    workflow.add_edge("trust_calibration", "simulation_training")
    workflow.add_edge("simulation_training", "get_behavioral_memory")
    workflow.add_edge("get_behavioral_memory", "case")
    workflow.add_edge("case", "summarize_conversation")
    workflow.add_edge("summarize_conversation", END)
    workflow.set_entry_point("data_collection")
    app = workflow.compile(checkpointer=checkpointer)

    # Initialize state
    if initial_state:
        current_state = initial_state
        current_state["logs"] = logs
    else:
        current_state = {
            "logs": logs,
            "parsed_logs": [],
            "alerts": [],
            "investigation_results": {},
            "threat_intel_data": None,
            "context_data": None,
            "correlation_results": None,
            "fact_checker_results": None,
            "explanation": None,
            "decision": None,
            "remediation_plan": None,
            "remediation_actions": None,
            "rollback_status": None,
            "trust_scores": None,
            "behavioral_memory": None,
            "case_summary": None,
            "human_feedback": None,
            "summary": None,
            "messages": [],
            "needs_human_feedback": False
        }

    # Get parsed logs (use existing or parse new)
    if not current_state.get("parsed_logs"):
        current_state["parsed_logs"] = parse_logs(logs)
    
    username = get_username_from_logs(current_state["parsed_logs"])
    config = {"configurable": {"thread_id": username}}

    latest_result =  get_latest_workflow_result(username)
    print(f"Latest result: {latest_result}")

    if latest_result:
        current_state["summary"] = latest_result.get("summary")
        logger.info(f"Summary from existing checkpoint: {current_state['summary']}")

    # Check for existing checkpoint only for new workflows
    if not initial_state:
        try:
            existing_state = app.get_state(config)
            logger.info(f"existing_state: {existing_state}")
        except Exception as e:
            logger.info(f"No existing checkpoint: {str(e)}")

    # Run the workflow - using invoke method to get __interrupt__ info
    result = app.invoke(current_state, config=config)
    
    # Check if we have an interrupt
    if "__interrupt__" in result:
        # Workflow paused at human feedback node
        logger.info("Workflow paused for human input")
        return result
    
    # No interrupt, return the final state
    return result

workflow_app = None

def initialize_workflow():
    global workflow_app
    if workflow_app is None:
        workflow = StateGraph(SecurityState, checkpointer)
    
        # Level 2: Data Processing & Detection
        workflow.add_node("data_collection", lambda s: {**s, "parsed_logs": parse_logs(s.get("logs", ""))})
        workflow.add_node("detection", detection_agent)
        
        # Level 3: Contextual Enrichment & Investigation
        workflow.add_node("investigation", investigation_agent)
        workflow.add_node("threat_intel", threat_intelligence_agent)
        workflow.add_node("context", context_agent)
        workflow.add_node("correlation", correlation_agent)
        
        # Level 4: Validation & Explanation
        workflow.add_node("fact_checker", fact_checker_agent)
        workflow.add_node("explainability", explainability_agent)

        # Level 5: Decision & Response
        workflow.add_node("remediation_strategy", remediation_strategy_agent)
        workflow.add_node("response_orchestration", response_orchestration_agent)
        workflow.add_node("get_human_feedback", human_feedback_node)
        workflow.add_node("get_execute_remediation", execute_remediation)

        # Level 6: Monitoring & Feedback
        workflow.add_node("trust_calibration", trust_calibration_agent)
        workflow.add_node("simulation_training", simulation_training_agent)
        workflow.add_node("get_behavioral_memory", behavioral_memory_agent)
        workflow.add_node("case", case_summary_agent)
        workflow.add_node("summarize_conversation", summarize_conversation)

        # Connect edges
        workflow.add_edge(START, "data_collection")
        workflow.add_edge("data_collection", "detection")
        workflow.add_edge("detection", "investigation")
        workflow.add_edge("investigation", "threat_intel")
        workflow.add_edge("threat_intel", "context")
        workflow.add_edge("context", "correlation")
        workflow.add_edge("correlation", "fact_checker")
        workflow.add_edge("fact_checker", "explainability")
        workflow.add_edge("explainability", "remediation_strategy")
        workflow.add_edge("remediation_strategy", "response_orchestration")
        workflow.add_edge("response_orchestration", "get_human_feedback")
        workflow.add_edge("get_human_feedback", "get_execute_remediation")
        workflow.add_edge("get_execute_remediation", "trust_calibration")
        workflow.add_edge("trust_calibration", "simulation_training")
        workflow.add_edge("simulation_training", "get_behavioral_memory")
        workflow.add_edge("get_behavioral_memory", "case")
        workflow.add_edge("case", "summarize_conversation")
        workflow.add_edge("summarize_conversation", END)
        workflow.set_entry_point("data_collection")
        app = workflow.compile(checkpointer=checkpointer)
    
    return app

# Example of how to handle the interrupt and resume the workflow
def resume_workflow_with_human_input(state, human_input):
    workflow_app = initialize_workflow() 
    
    username = get_username_from_logs(state.get("parsed_logs", []))
    config = {"configurable": {"thread_id": username}}
    
    return workflow_app.invoke(
        Command(resume=human_input),
        config=config,
    )


def save_workflow_result(username: str, result: Dict[str, Any]):
    """Save workflow result to SQLite database with username and timestamp."""
    conn = sqlite3.connect('security_workflow.db')
    cursor = conn.cursor()
    
    # Convert non-serializable objects and clean the result for storage
    clean_result = {k: v for k, v in result.items() if k not in ["__interrupt__"]}
    result_json = json.dumps(clean_result, default=str)
    
    # Get current timestamp in ISO format
    timestamp = datetime.now().isoformat()
    
    # Insert the record
    cursor.execute(
        "INSERT INTO workflow_results (username, timestamp, result_json) VALUES (?, ?, ?)",
        (username, timestamp, result_json)
    )
    
    conn.commit()
    conn.close()
    
    print(f"Workflow result saved for user '{username}' at {timestamp}")



# Main function
if __name__ == "__main__":
    # Sample Azure SecurityEvent logs (simulated)
    sample_logs = """
        2025-07-06T14:10:55Z user=admin@example.com action=login status=success ip=10.0.0.4 location=Berlin,DE device=windows event_id=4624
        2025-07-06T14:12:33Z user=admin@example.com action=access_resource resource=VM-Prod ip=10.0.0.4 location=Berlin,DE event_id=4672
        2025-07-06T14:18:22Z user=admin@example.com action=login status=failed ip=104.78.22.9 location=Kyiv,UA reason=bad_password attempt=1 event_id=4625
        2025-07-06T14:19:10Z user=admin@example.com action=login status=failed ip=104.78.22.9 location=Kyiv,UA reason=bad_password attempt=2 event_id=4625
        2025-07-06T14:19:59Z user=admin@example.com action=login status=success ip=104.78.22.9 location=Kyiv,UA device=unknown event_id=4624
        2025-07-06T14:22:05Z user=admin@example.com action=download file=prod-db-backup.bak ip=104.78.22.9 location=Kyiv,UA event_id=4663
        2025-07-06T14:25:42Z user=admin@example.com action=access_admin_panel ip=104.78.22.9 location=Kyiv,UA event_id=4672
    """

    # Run the workflow
    result = run_security_workflow(sample_logs, initial_state=None)

    if "__interrupt__" in result:
        print("\nWorkflow paused for human input. Here's the remediation plan to review:")
        interrupt_info = result["__interrupt__"][0].value
        print(json.dumps(interrupt_info, indent=2))

        user_choice = input("\nType 'approve' to approve the plan or anything else for manual intervention: ")
        username = get_username_from_logs(result.get("parsed_logs", []))
        config = {"configurable": {"thread_id": username}}

        final_result = resume_workflow_with_human_input(result, user_choice)

        print("\n\nFINAL STATE AFTER HUMAN INPUT:")
        print(json.dumps({k: v for k, v in final_result.items() if k not in ["logs", "parsed_logs", "messages"]}, indent=2))

        save_workflow_result(username, final_result)
        with open("final_state.json", "w") as f:
            json.dump(final_result, f, indent=2)
    else:
        print("\n\nFINAL STATE:", result)
        with open("final_state.json", "w") as f:
            json.dump(result, f, indent=2)

        
