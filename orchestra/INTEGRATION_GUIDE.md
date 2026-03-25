"""
Enhanced Pipeline Integration Guide
This module shows how to integrate new persistence layer into execute_pipeline.
Apply these patterns to orchestra/pipeline.py and orchestra/pipeline_deepdive.py
"""

# ============================================================================
# STEP 1: Import additions at top of pipeline.py
# ============================================================================

"""
In orchestra/pipeline.py, add these imports:

from uuid import uuid4
from orchestra.db_utils import DatabasePersistenceManager
from orchestra.models import (
    FileAnalysisStage,
    RiskLevel,
    FileType,
    ThreatSource,
    EntityOperation,
)
from orchestra.redis_client import EnhancedRedisClient
"""


# ============================================================================
# STEP 2: Update PipelineDependencies dataclass
# ============================================================================

"""
Update PipelineDependencies in pipeline.py:

@dataclass
class PipelineDependencies:
    settings: Settings
    email_client: AgentClient
    file_client: AgentClient
    web_client: AgentClient
    threat_scanner: ThreatIntelScanner
    protocol_verifier: ProtocolVerifier
    redis_client: EnhancedRedisClient  # ← ADD THIS
    db_manager: DatabasePersistenceManager  # ← ADD THIS
"""


# ============================================================================
# STEP 3: Add correlation_id generation at start of execute_pipeline
# ============================================================================

async def execute_pipeline_enhanced(email_path: str, session, deps, user_accepts_danger=False):
    # Generate correlation ID for end-to-end tracing
    correlation_id = str(uuid4())
    
    # Create pipeline execution record
    execution_id = await deps.db_manager.create_pipeline_execution(
        session=session,
        email_id=None,  # Will update after email row created
        correlation_id=correlation_id,
    )
    
    # ... rest of pipeline code ...


# ============================================================================
# STEP 4: Store agent responses after each agent call
# ============================================================================

"""
After Email Agent call (around line 161), add:

if email_resp:
    await deps.db_manager.store_agent_response(
        session=session,
        email_id=email_row.id,  # Available after flush
        correlation_id=correlation_id,
        agent_type="email_agent",
        response_payload=email_resp,
        status_code=200,
        latency_ms=None,  # Calculate if timing available
    )
    
    # Alternative: Cache in Redis for fast lookups
    deps.redis_client.cache_file_analysis(
        file_hash=f"agent_response:{correlation_id}:email_agent",
        analysis_data=email_resp
    )
"""


# ============================================================================
# STEP 5: Store file analysis results
# ============================================================================

"""
After File Agent call (around line 190), add:

for file_hash, path in attachment_hashes:
    if file_resp:
        # Store analysis result in database
        analysis_id = await deps.db_manager.store_file_analysis(
            session=session,
            file_hash=file_hash,
            email_id=email_row.id,
            correlation_id=correlation_id,
            analysis_stage=FileAnalysisStage.xgboost,
            status="completed",
        )
        
        # Store xgboost classification
        risk_level = RiskLevel(file_resp.get("risk_level", "low"))
        await deps.db_manager.store_xgboost_results(
            session=session,
            file_analysis_id=analysis_id,
            risk_level=risk_level,
            confidence=float(file_resp.get("confidence", 0.0)),
            probabilities=file_resp.get("probabilities"),
            model_version=file_resp.get("model_version"),
        )
        
        # Cache in Redis for future lookups (7-day TTL)
        deps.redis_client.cache_file_analysis(
            file_hash=file_hash,
            analysis_data=file_resp
        )
        
        # Log prediction for model monitoring
        await deps.db_manager.log_model_prediction(
            session=session,
            model_id=f"xgboost_v{file_resp.get('model_version', '1')}",
            email_id=email_row.id,
            predicted_label=file_resp.get("risk_level", "low"),
            confidence=float(file_resp.get("confidence", 0.0)),
        )
"""


# ============================================================================
# STEP 6: Store URL analysis results
# ============================================================================

"""
After Web Agent call (around line 230), add:

if url_analysis and isinstance(url_analysis, list):
    for item in url_analysis:
        if not isinstance(item, dict):
            continue
            
        url = str(item.get("input_url") or item.get("url") or "")
        url_hash = _hash_url(url)
        
        # Store URL analysis
        await deps.db_manager.store_url_analysis(
            session=session,
            url_hash=url_hash,
            email_id=email_row.id,
            correlation_id=correlation_id,
            risk_score=float(item.get("risk_score", 0.0)),
            label=str(item.get("label", "safe")).lower(),
            confidence=float(item.get("confidence", 0.0)),
            phishing_indicators=item.get("phishing_indicators"),
            brand_target=item.get("brand_target"),
        )
        
        # Track threat history
        if str(item.get("label", "safe")).lower() in {"malicious", "phishing"}:
            await deps.db_manager.store_url_threat_history(
                session=session,
                url_hash=url_hash,
                risk_score=float(item.get("risk_score", 0.0)),
                label=str(item.get("label", "safe")).lower(),
                source=ThreatSource.web_agent,
            )
            
            # Add to threat cache (24h)
            deps.redis_client.add_threat(
                entity=url,
                entity_type="url",
                threat_data=item
            )
        else:
            # Add to whitelist (24h)
            deps.redis_client.add_to_whitelist(
                entity=url,
                entity_type="url",
                metadata=item
            )
"""


# ============================================================================
# STEP 7: Store pipeline completion
# ============================================================================

"""
Before returning ScanResponse (around line 270), add:

# Update pipeline execution completion
duration_ms = int((datetime.utcnow() - start_time).total_seconds() * 1000)
await deps.db_manager.complete_pipeline_execution(
    session=session,
    execution_id=execution_id,
    duration_ms=duration_ms,
    status="completed" if final_status != "DANGER" else "completed_quarantine",
)

# Store domain reputation history
if email_row.sender:
    domain = email_row.sender.split("@")[-1] if "@" in email_row.sender else email_row.sender
    await deps.db_manager.store_domain_reputation_history(
        session=session,
        domain=domain,
        status=final_status.lower(),
        reputation_score=email_row.total_risk_score,
        source="orchestrator",
    )
"""


# ============================================================================
# STEP 8: Deep-dive LLM analysis integration
# ============================================================================

"""
In orchestra/pipeline_deepdive.py, after AI Agent call, add:

if ai_response:
    # Store AI analysis
    await deps.db_manager.store_ai_analysis(
        session=session,
        email_id=email_row.id,
        correlation_id=correlation_id,
        model_id=ai_response.get("model_id", "gemini-unknown"),
        provider=ai_response.get("provider", "gemini"),
        classification=AiClassification(ai_response.get("classify", "safe")),
        confidence_percent=float(ai_response.get("confidence_percent", 0.0)),
        reasoning_text=ai_response.get("reason"),
        tool_use_trace=ai_response.get("tool_trace"),
        escalation_flag=ai_response.get("should_escalate", False),
    )
    
    # Log for model performance tracking
    await deps.db_manager.log_model_prediction(
        session=session,
        model_id=ai_response.get("model_id"),
        email_id=email_row.id,
        predicted_label=ai_response.get("classify", "safe"),
        confidence=float(ai_response.get("confidence_percent", 0.0)) / 100.0,
    )

    # Store in Redis for rapid retrieval (7 days)
    deps.redis_client.cache_file_analysis(
        file_hash=f"ai_analysis:{correlation_id}",
        analysis_data=ai_response
    )
"""


# ============================================================================
# STEP 9: Threat intelligence tracking (periodic task)
# ============================================================================

"""
For threat list updates from Web Agent, create a periodic task:

async def track_threat_list_updates(session: AsyncSession, redis_client: EnhancedRedisClient):
    '''Called periodically (e.g., hourly) to log TI changes'''
    
    # Example: Log new malicious domains detected
    update_id = await db_manager.create_threat_list_update(
        session=session,
        list_name="malicious_domains",
        update_source=ThreatSource.threat_feed,
        added_count=100,
        removed_count=5,
        changed_count=0,
    )
    
    # Log each domain addition
    for domain in new_malicious_domains:
        await db_manager.log_threat_change(
            session=session,
            update_id=update_id,
            entity_type="domain",
            entity_value=domain,
            operation=EntityOperation.add,
            new_value={"source": "TI_feed", "timestamp": datetime.utcnow().isoformat()},
        )
        
        # Add to Redis threat cache
        redis_client.add_threat(
            entity=domain,
            entity_type="domain",
            threat_data={"source": "threat_feed", "added_at": datetime.utcnow().isoformat()}
        )
"""


# ============================================================================
# STEP 10: Create initialization helper in main.py
# ============================================================================

"""
In orchestra/main.py, update the app initialization:

from orchestra.db_utils import DatabasePersistenceManager
from orchestra.redis_client import EnhancedRedisClient

app = FastAPI(...)

# Initialize Redis client
redis_client = EnhancedRedisClient(
    host=settings.redis_host,
    port=settings.redis_port,
    db=0,
    password=settings.redis_password,
)

# Initialize DB manager
db_manager = DatabasePersistenceManager()

# Add to dependencies
@app.post("/api/v1/scan")
async def scan_endpoint(email_path: str, session: AsyncSession = Depends(get_session)):
    deps = PipelineDependencies(
        settings=settings,
        email_client=email_agent_client,
        file_client=file_agent_client,
        web_client=web_agent_client,
        threat_scanner=threat_scanner,
        protocol_verifier=protocol_verifier,
        redis_client=redis_client,
        db_manager=db_manager,
    )
    
    result = await execute_pipeline_enhanced(email_path, session, deps)
    return result
"""


# ============================================================================
# QUERYING EXAMPLES
# ============================================================================

"""
Query examples for threat hunting and analytics:

1. Find all emails from a suspicious sender:
   SELECT e.* FROM emails e WHERE e.sender = 'attacker@evil.com' ORDER BY e.processed_at DESC;

2. Get all files with HIGH risk in the last 7 days:
   SELECT f.*, fa.* FROM file_analyses fa
   JOIN files f ON f.file_hash = fa.file_hash
   WHERE fa.status = 'completed' AND 
         (SELECT xr.risk_level FROM file_xgboost_results xr WHERE xr.file_analysis_id = fa.analysis_id LIMIT 1) = 'high'
   AND fa.created_at > NOW() - INTERVAL '7 days';

3. Trend analysis: Risk scores over time by domain:
   SELECT e.sender, EXTRACT(DATE FROM e.processed_at) as date, 
          COUNT(*) as email_count, AVG(e.total_risk_score) as avg_risk
   FROM emails e
   GROUP BY EXTRACT(DATE FROM e.processed_at), e.sender
   ORDER BY date DESC, avg_risk DESC;

4. Model accuracy tracking:
   SELECT md.model_id, md.version, 
          COUNT(*) as predictions,
          COUNT(CASE WHEN mpl.predicted_label = mpl.actual_label THEN 1 END) as correct,
          ROUND(100.0 * COUNT(CASE WHEN mpl.predicted_label = mpl.actual_label THEN 1 END) / COUNT(*), 2) as accuracy_pct
   FROM model_predictions_log mpl
   JOIN model_deployments md ON mpl.model_id = md.model_id
   WHERE mpl.actual_label IS NOT NULL
   GROUP BY md.model_id, md.version;

5. Threat intelligence audit trail:
   SELECT *, tlu.list_name, COUNT(tlc.change_id) as changes_count
   FROM threat_list_updates tlu
   LEFT JOIN threat_list_changes tlc ON tlu.update_id = tlc.update_id
   WHERE tlu.created_at > NOW() - INTERVAL '30 days'
   GROUP BY tlu.update_id
   ORDER BY tlu.timestamp DESC;
"""
