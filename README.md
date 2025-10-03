# EventraAI - Intelligent Security Operations Assistant

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue)](https://python.org)
[![Streamlit](https://img.shields.io/badge/Streamlit-1.46.1-red)](https://streamlit.io)
[![LangChain](https://img.shields.io/badge/LangChain-0.3.26-green)](https://langchain.com)
[![LangGraph](https://img.shields.io/badge/LangGraph-0.5.1-purple)](https://langchain-ai.github.io/langgraph/)

EventraAI is an advanced AI-powered Security Operations Center (SOC) assistant that automates security incident analysis, investigation, and response through intelligent multi-agent workflows. Built with cutting-edge AI technologies, it provides comprehensive threat detection, investigation, and remediation capabilities with human-in-the-loop validation.

## 🚀 Key Features

### 🔍 **Intelligent Log Analysis**
- Automated parsing and structuring of security logs
- Advanced anomaly detection using AI agents
- Multi-dimensional threat assessment

### 🤖 **Multi-Agent Security Workflow**
- **7-Layer Architecture**: Orchestration → Detection → Investigation → Validation → Response → Monitoring → Management
- **12+ Specialized AI Agents**: Each designed for specific security tasks
- **Human-in-the-Loop**: Critical decisions require human validation

### 🧠 **Advanced AI Capabilities**
- **LangGraph Orchestration**: Complex workflow management with state persistence
- **Google Gemini Integration**: Powered by Gemini-2.5-Flash for intelligent analysis
- **Tree-of-Thought Reasoning**: Multi-step decision making process
- **Fact-Checking**: AI hallucination prevention and validation

### 🛡️ **Comprehensive Security Features**
- Real-time threat intelligence correlation
- MITRE ATT&CK framework integration
- Behavioral memory and pattern recognition
- Automated remediation with rollback capabilities
- Trust calibration and confidence scoring

### 📊 **Interactive Dashboard**
- Modern Streamlit-based web interface
- Historical case management and analytics
- Real-time workflow monitoring
- Exportable incident reports

## 🏗️ Architecture Overview

EventraAI employs a sophisticated 7-layer architecture:

```
┌─────────────────────────────────────────────────────────────┐
│                    LEVEL 1: ORCHESTRATION                  │
├─────────────────────────────────────────────────────────────┤
│               LEVEL 2: DATA PROCESSING & DETECTION         │
│  • Data Collection Agent    • Detection Agent              │
├─────────────────────────────────────────────────────────────┤
│            LEVEL 3: CONTEXTUAL ENRICHMENT & INVESTIGATION  │
│  • Investigation Agent      • Threat Intelligence Agent    │
│  • Context Agent           • Correlation Agent             │
├─────────────────────────────────────────────────────────────┤
│                LEVEL 4: VALIDATION & EXPLANATION           │
│  • Fact-Checker Agent     • Explainability Agent          │
├─────────────────────────────────────────────────────────────┤
│                  LEVEL 5: DECISION & RESPONSE              │
│  • Remediation Strategy    • Response Orchestration        │
│  • Human Feedback         • Execution Agent                │
├─────────────────────────────────────────────────────────────┤
│                LEVEL 6: MONITORING & FEEDBACK              │
│  • Trust Calibration      • Simulation Training            │
│  • Behavioral Memory      • One-Click Rollback             │
├─────────────────────────────────────────────────────────────┤
│                LEVEL 7: SUPPORT & MANAGEMENT               │
│  • Analyst Copilot        • Case Summary                   │
│  • Conversation Summary                                     │
└─────────────────────────────────────────────────────────────┘
```

## 🛠️ Installation

### Prerequisites
- Python 3.8 or higher
- Google AI API key (for Gemini integration)

### Setup Instructions

1. **Clone the repository**
```bash
git clone https://github.com/SyedAffan10/Eventra-AI.git
cd Eventra-AI/code
```

2. **Install dependencies**
```bash
pip install -r requirements.txt
```

3. **Environment Configuration**
Create a `.env` file in the root directory:
```env
GOOGLE_API_KEY=your_google_api_key_here
```

4. **Initialize Database**
```bash
python db.py
```

5. **Run the Application**
```bash
streamlit run app.py
```

The application will be available at `http://localhost:8501`

## 📖 Usage Guide

### 🔍 **Log Analysis**
1. Navigate to the "Log Analysis" tab
2. Paste your security logs or upload a log file
3. Click "Analyze Logs" to start the AI workflow
4. Review the automated analysis and alerts
5. Approve or modify the recommended remediation actions

### 📚 **Historical Cases**
- View past security incidents and their analysis
- Filter cases by user, threat level, or date range
- Export case data for compliance reporting
- Learn from past incidents to improve detection

### ⚙️ **System Settings**
- Configure API keys and system parameters
- Manage database operations
- Monitor system health and performance
- Access debug and maintenance tools

## 🔧 Core Components

### `app.py`
Main Streamlit application providing the web interface for:
- Interactive log analysis
- Historical case management
- System configuration and monitoring

### `agents.py`
Core AI agent implementations featuring:
- Multi-agent security workflow orchestration
- LangGraph-based state management
- Intelligent decision-making with human validation
- Comprehensive threat analysis pipeline

### `db.py`
Database management system for:
- SQLite-based case storage
- Workflow result persistence
- Historical data analytics

### `logger.py`
Centralized logging system with:
- Rotating file handlers
- Configurable log levels
- Performance monitoring

## 🤝 Agent Workflow

The system processes security incidents through specialized AI agents:

1. **Data Collection Agent**: Parses and structures raw security logs
2. **Detection Agent**: Identifies suspicious activities and anomalies
3. **Investigation Agent**: Conducts deep analysis with geolocation and context
4. **Threat Intelligence Agent**: Correlates with external threat feeds
5. **Context Agent**: Provides historical and behavioral context
6. **Correlation Agent**: Links related events into threat narratives
7. **Fact-Checker Agent**: Validates findings against raw data
8. **Explainability Agent**: Generates human-readable explanations
9. **Remediation Strategy Agent**: Determines appropriate response actions
10. **Response Orchestration Agent**: Plans and executes remediation
11. **Trust Calibration Agent**: Monitors AI decision accuracy
12. **Case Summary Agent**: Generates comprehensive incident reports

## 🎯 Use Cases

- **SOC Automation**: Reduce analyst workload with intelligent triage
- **Incident Response**: Automated investigation and remediation planning
- **Threat Hunting**: Proactive threat detection and correlation
- **Compliance Reporting**: Automated documentation and case management
- **Training**: Learn from AI analysis to improve security practices

## 🔒 Security Features

- **Human-in-the-Loop**: Critical decisions require human approval
- **Fact Checking**: Built-in validation to prevent AI hallucinations
- **Rollback Capability**: One-click reversal of automated actions
- **Trust Scoring**: Confidence metrics for AI recommendations
- **Audit Trail**: Complete logging of all decisions and actions

## 📊 Technologies Used

- **AI/ML**: LangChain, LangGraph, Google Gemini AI
- **Frontend**: Streamlit, Pandas, Altair
- **Backend**: Python, SQLite
- **APIs**: Google AI Generative Language
- **Security**: Azure integration capabilities, MITRE ATT&CK framework
