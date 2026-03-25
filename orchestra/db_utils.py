"""
Database utility functions for enhanced schema persistence.
Provides high-level API for storing pipeline execution, agent responses, and analysis results.
"""

from datetime import datetime
from typing import Any
from uuid import uuid4

from sqlalchemy.ext.asyncio import AsyncSession

from orchestra.models import (
    AgentResponse,
    FileAnalysis,
    FileAnalysisStage,
    FileHashTriage,
    FileStaticAnalysis,
    FileSandboxResults,
    FileXgboostResults,
    UrlAnalysis,
    UrlThreatHistory,
    DomainReputationHistory,
    AiAnalysis,
    AiClassification,
    ModelDeployment,
    ModelAgentType,
    ModelPredictionsLog,
    ThreatListUpdate,
    ThreatListChange,
    ThreatSource,
    EntityOperation,
    PipelineExecution,
    RiskLevel,
    FileType,
)


class DatabasePersistenceManager:
    """High-level API for persisting analysis results and pipeline execution."""

    @staticmethod
    async def create_pipeline_execution(
        session: AsyncSession,
        email_id: int,
        correlation_id: str,
    ) -> str:
        """Create pipeline execution record. Returns execution_id."""
        execution_id = str(uuid4())
        execution = PipelineExecution(
            execution_id=execution_id,
            email_id=email_id,
            correlation_id=correlation_id,
            execution_status="processing",
            started_at=datetime.utcnow(),
        )
        session.add(execution)
        await session.flush()
        return execution_id

    @staticmethod
    async def complete_pipeline_execution(
        session: AsyncSession,
        execution_id: str,
        duration_ms: int,
        status: str = "completed",
    ) -> None:
        """Mark pipeline execution as completed."""
        execution = await session.get(PipelineExecution, execution_id)
        if execution:
            execution.execution_status = status
            execution.completed_at = datetime.utcnow()
            execution.total_duration_ms = duration_ms

    @staticmethod
    async def store_agent_response(
        session: AsyncSession,
        email_id: int,
        correlation_id: str,
        agent_type: str,
        response_payload: dict[str, Any],
        status_code: int | None = None,
        latency_ms: int | None = None,
    ) -> str:
        """Store agent response. Returns response_id."""
        response_id = str(uuid4())
        response = AgentResponse(
            response_id=response_id,
            email_id=email_id,
            correlation_id=correlation_id,
            agent_type=agent_type,
            response_payload=response_payload,
            status_code=status_code,
            latency_ms=latency_ms,
            created_at=datetime.utcnow(),
        )
        session.add(response)
        await session.flush()
        return response_id

    # =====================================================================
    # FILE ANALYSIS PERSISTENCE
    # =====================================================================

    @staticmethod
    async def store_file_analysis(
        session: AsyncSession,
        file_hash: str,
        email_id: int,
        correlation_id: str,
        analysis_stage: FileAnalysisStage = FileAnalysisStage.hash_triage,
        status: str = "completed",
    ) -> str:
        """Create file analysis record. Returns analysis_id."""
        analysis_id = str(uuid4())
        analysis = FileAnalysis(
            analysis_id=analysis_id,
            file_hash=file_hash,
            email_id=email_id,
            correlation_id=correlation_id,
            analysis_stage=analysis_stage,
            status=status,
            timestamp=datetime.utcnow(),
            created_at=datetime.utcnow(),
        )
        session.add(analysis)
        await session.flush()
        return analysis_id

    @staticmethod
    async def store_hash_triage(
        session: AsyncSession,
        file_hash: str,
        sha256: str | None = None,
        md5: str | None = None,
        sha1: str | None = None,
        size_bytes: int | None = None,
        clamav_verdict: str | None = None,
        ioc_db_hits: dict | None = None,
        cache_hit: bool = False,
    ) -> str:
        """Store hash triage results. Returns triage_id."""
        triage_id = str(uuid4())
        triage = FileHashTriage(
            triage_id=triage_id,
            file_hash=file_hash,
            sha256=sha256,
            md5=md5,
            sha1=sha1,
            size_bytes=size_bytes,
            clamav_verdict=clamav_verdict,
            ioc_db_hits=ioc_db_hits,
            cache_hit=cache_hit,
            created_at=datetime.utcnow(),
        )
        session.add(triage)
        await session.flush()
        return triage_id

    @staticmethod
    async def store_static_analysis(
        session: AsyncSession,
        file_analysis_id: str,
        file_type: FileType,
        has_macros: bool | None = None,
        obfuscation_score: float | None = None,
        packing_detected: bool | None = None,
        suspicious_imports: dict | None = None,
        entropy_score: float | None = None,
        yara_matches: dict | None = None,
    ) -> str:
        """Store static analysis results. Returns analysis_id."""
        analysis_id = str(uuid4())
        analysis = FileStaticAnalysis(
            analysis_id=analysis_id,
            file_analysis_id=file_analysis_id,
            file_type=file_type,
            has_macros=has_macros,
            obfuscation_score=obfuscation_score,
            packing_detected=packing_detected,
            suspicious_imports=suspicious_imports,
            entropy_score=entropy_score,
            yara_matches=yara_matches,
            created_at=datetime.utcnow(),
        )
        session.add(analysis)
        await session.flush()
        return analysis_id

    @staticmethod
    async def store_sandbox_results(
        session: AsyncSession,
        file_analysis_id: str,
        dns_queries: dict | None = None,
        http_requests: dict | None = None,
        registry_changes: dict | None = None,
        dropped_files: dict | None = None,
        c2_indicators: dict | None = None,
        behavioral_score: float | None = None,
        runtime_seconds: int | None = None,
    ) -> str:
        """Store sandbox execution results. Returns sandbox_id."""
        sandbox_id = str(uuid4())
        sandbox = FileSandboxResults(
            sandbox_id=sandbox_id,
            file_analysis_id=file_analysis_id,
            dns_queries=dns_queries,
            http_requests=http_requests,
            registry_changes=registry_changes,
            dropped_files=dropped_files,
            c2_indicators=c2_indicators,
            behavioral_score=behavioral_score,
            runtime_seconds=runtime_seconds,
            created_at=datetime.utcnow(),
        )
        session.add(sandbox)
        await session.flush()
        return sandbox_id

    @staticmethod
    async def store_xgboost_results(
        session: AsyncSession,
        file_analysis_id: str,
        risk_level: RiskLevel,
        confidence: float,
        probabilities: dict | None = None,
        top_features: dict | None = None,
        model_version: str | None = None,
    ) -> str:
        """Store XGBoost model results. Returns xgboost_id."""
        xgboost_id = str(uuid4())
        xgboost = FileXgboostResults(
            xgboost_id=xgboost_id,
            file_analysis_id=file_analysis_id,
            risk_level=risk_level,
            confidence=confidence,
            probabilities=probabilities,
            top_features=top_features,
            model_version=model_version,
            created_at=datetime.utcnow(),
        )
        session.add(xgboost)
        await session.flush()
        return xgboost_id

    # =====================================================================
    # URL ANALYSIS PERSISTENCE
    # =====================================================================

    @staticmethod
    async def store_url_analysis(
        session: AsyncSession,
        url_hash: str,
        email_id: int,
        correlation_id: str,
        risk_score: float,
        label: str,
        confidence: float | None = None,
        phishing_indicators: dict | None = None,
        brand_target: str | None = None,
    ) -> str:
        """Store URL analysis results. Returns url_analysis_id."""
        url_analysis_id = str(uuid4())
        analysis = UrlAnalysis(
            url_analysis_id=url_analysis_id,
            url_hash=url_hash,
            email_id=email_id,
            correlation_id=correlation_id,
            risk_score=risk_score,
            confidence=confidence,
            label=label,
            phishing_indicators=phishing_indicators,
            brand_target=brand_target,
            detected_at=datetime.utcnow(),
            created_at=datetime.utcnow(),
        )
        session.add(analysis)
        await session.flush()
        return url_analysis_id

    @staticmethod
    async def store_url_threat_history(
        session: AsyncSession,
        url_hash: str,
        risk_score: float,
        label: str,
        source: ThreatSource,
    ) -> str:
        """Track URL threat changes over time. Returns history_id."""
        history_id = str(uuid4())
        history = UrlThreatHistory(
            history_id=history_id,
            url_hash=url_hash,
            risk_score=risk_score,
            label=label,
            source=source,
            updated_at=datetime.utcnow(),
            created_at=datetime.utcnow(),
        )
        session.add(history)
        await session.flush()
        return history_id

    @staticmethod
    async def store_domain_reputation_history(
        session: AsyncSession,
        domain: str,
        status: str,
        reputation_score: float | None = None,
        source: str | None = None,
    ) -> str:
        """Track domain reputation changes. Returns history_id."""
        history_id = str(uuid4())
        history = DomainReputationHistory(
            history_id=history_id,
            domain=domain,
            status=status,
            reputation_score=reputation_score,
            source=source,
            updated_at=datetime.utcnow(),
            created_at=datetime.utcnow(),
        )
        session.add(history)
        await session.flush()
        return history_id

    # =====================================================================
    # AI ANALYSIS & MODEL TRACKING
    # =====================================================================

    @staticmethod
    async def store_ai_analysis(
        session: AsyncSession,
        email_id: int,
        correlation_id: str,
        model_id: str,
        provider: str,
        classification: AiClassification,
        confidence_percent: float,
        reasoning_text: str | None = None,
        tool_use_trace: dict | None = None,
        escalation_flag: bool = False,
    ) -> str:
        """Store AI LLM analysis results. Returns analysis_id."""
        analysis_id = str(uuid4())
        analysis = AiAnalysis(
            analysis_id=analysis_id,
            email_id=email_id,
            correlation_id=correlation_id,
            model_id=model_id,
            provider=provider,
            classification=classification,
            confidence_percent=confidence_percent,
            reasoning_text=reasoning_text,
            tool_use_trace=tool_use_trace,
            escalation_flag=escalation_flag,
            created_at=datetime.utcnow(),
        )
        session.add(analysis)
        await session.flush()
        return analysis_id

    @staticmethod
    async def register_model_deployment(
        session: AsyncSession,
        model_id: str,
        agent_type: ModelAgentType,
        version: str,
        provider: str | None = None,
        accuracy_baseline: float | None = None,
        notes: str | None = None,
    ) -> None:
        """Register a new model deployment."""
        # Check if already exists
        existing = await session.get(ModelDeployment, model_id)
        if not existing:
            deployment = ModelDeployment(
                model_id=model_id,
                agent_type=agent_type,
                version=version,
                provider=provider,
                deployment_date=datetime.utcnow(),
                accuracy_baseline=accuracy_baseline,
                notes=notes,
                created_at=datetime.utcnow(),
            )
            session.add(deployment)
            await session.flush()

    @staticmethod
    async def log_model_prediction(
        session: AsyncSession,
        model_id: str | None,
        email_id: int,
        predicted_label: str,
        confidence: float | None = None,
        actual_label: str | None = None,
        feedback_source: str | None = None,
    ) -> str:
        """Log a model prediction for training/evaluation. Returns prediction_id."""
        prediction_id = str(uuid4())
        log = ModelPredictionsLog(
            prediction_id=prediction_id,
            model_id=model_id,
            email_id=email_id,
            predicted_label=predicted_label,
            confidence=confidence,
            actual_label=actual_label,
            feedback_source=feedback_source,
            created_at=datetime.utcnow(),
        )
        session.add(log)
        await session.flush()
        return prediction_id

    # =====================================================================
    # THREAT INTELLIGENCE AUDIT TRAIL
    # =====================================================================

    @staticmethod
    async def create_threat_list_update(
        session: AsyncSession,
        list_name: str,
        update_source: ThreatSource,
        added_count: int = 0,
        removed_count: int = 0,
        changed_count: int = 0,
        update_hash: str | None = None,
    ) -> str:
        """Create threat list update record. Returns update_id."""
        update_id = str(uuid4())
        update = ThreatListUpdate(
            update_id=update_id,
            list_name=list_name,
            update_source=update_source,
            timestamp=datetime.utcnow(),
            added_count=added_count,
            removed_count=removed_count,
            changed_count=changed_count,
            update_hash=update_hash,
            created_at=datetime.utcnow(),
        )
        session.add(update)
        await session.flush()
        return update_id

    @staticmethod
    async def log_threat_change(
        session: AsyncSession,
        update_id: str,
        entity_type: str,
        entity_value: str,
        operation: EntityOperation,
        old_value: dict | None = None,
        new_value: dict | None = None,
    ) -> str:
        """Log granular threat list change. Returns change_id."""
        change_id = str(uuid4())
        change = ThreatListChange(
            change_id=change_id,
            update_id=update_id,
            entity_type=entity_type,
            entity_value=entity_value,
            operation=operation,
            old_value=old_value,
            new_value=new_value,
            created_at=datetime.utcnow(),
        )
        session.add(change)
        await session.flush()
        return change_id
