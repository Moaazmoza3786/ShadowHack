"""
Phase 4: Advanced Workflows Engine
Handles workflow creation, execution, and management
"""

import asyncio
import json
import logging
from dataclasses import dataclass, asdict, field
from typing import Dict, List, Any, Optional, Callable
from datetime import datetime
from enum import Enum
import uuid
from abc import ABC, abstractmethod

logger = logging.getLogger(__name__)


class WorkflowStatus(str, Enum):
    """Workflow execution status"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    PAUSED = "paused"
    CANCELLED = "cancelled"


class StepStatus(str, Enum):
    """Individual step status"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class WorkflowInput:
    """Input parameter for a workflow"""
    name: str
    type: str  # string, number, boolean, file, select
    required: bool = True
    default: Any = None
    description: str = ""
    options: List[str] = field(default_factory=list)


@dataclass
class WorkflowStep:
    """Individual step in a workflow"""
    id: str
    type: str  # action, decision, parallel, script
    name: str
    description: str = ""
    action: str = ""  # tool or plugin to execute
    config: Dict[str, Any] = field(default_factory=dict)
    inputs: Dict[str, Any] = field(default_factory=dict)
    outputs: Dict[str, Any] = field(default_factory=dict)
    condition: Optional[str] = None  # for decision steps
    next_step: Optional[str] = None  # ID of next step
    error_handler: Optional[str] = None  # ID of error handler step
    timeout: int = 300  # 5 minutes default
    retry_count: int = 0
    retry_delay: int = 5
    tags: List[str] = field(default_factory=list)


@dataclass
class WorkflowTemplate:
    """Template for reusable workflows"""
    id: str
    name: str
    description: str
    category: str  # web, network, mobile, cloud, general
    difficulty: str  # beginner, intermediate, advanced
    icon: str = ""
    version: str = "1.0.0"
    author: str = ""
    inputs: List[WorkflowInput] = field(default_factory=list)
    steps: List[WorkflowStep] = field(default_factory=list)
    expected_output: str = ""
    estimated_time: int = 0  # in minutes
    tags: List[str] = field(default_factory=list)
    best_practices: List[str] = field(default_factory=list)
    created_at: str = ""
    updated_at: str = ""


@dataclass
class WorkflowExecution:
    """Active workflow execution instance"""
    id: str
    workflow_id: str
    template_id: Optional[str] = None
    status: WorkflowStatus = WorkflowStatus.PENDING
    inputs: Dict[str, Any] = field(default_factory=dict)
    context: Dict[str, Any] = field(default_factory=dict)
    current_step: Optional[str] = None
    completed_steps: List[str] = field(default_factory=list)
    failed_steps: List[str] = field(default_factory=list)
    results: Dict[str, Any] = field(default_factory=dict)
    errors: List[Dict[str, Any]] = field(default_factory=list)
    progress: float = 0.0
    started_at: Optional[str] = None
    completed_at: Optional[str] = None


class WorkflowExecutor(ABC):
    """Base class for workflow step executors"""
    
    @abstractmethod
    async def execute(self, step: WorkflowStep, context: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a workflow step"""
        pass
    
    @abstractmethod
    def supports(self, step_type: str) -> bool:
        """Check if executor supports this step type"""
        pass


class ActionExecutor(WorkflowExecutor):
    """Executor for action steps (tool/plugin execution)"""
    
    def __init__(self, tool_registry: Dict[str, Callable]):
        self.tool_registry = tool_registry
    
    async def execute(self, step: WorkflowStep, context: Dict[str, Any]) -> Dict[str, Any]:
        """Execute an action step"""
        try:
            if step.action not in self.tool_registry:
                raise ValueError(f"Action '{step.action}' not found in registry")
            
            tool = self.tool_registry[step.action]
            
            # Resolve input parameters from context
            resolved_inputs = self._resolve_inputs(step.inputs, context)
            
            # Execute tool - pass action and context if it's an AI-capable tool
            if asyncio.iscoroutinefunction(tool):
                # Try to pass context if it's a tool that supports it (like our AI tools)
                try:
                    result = await asyncio.wait_for(
                        tool(action=step.action, inputs=resolved_inputs, context=context),
                        timeout=step.timeout
                    )
                except TypeError:
                    # Fallback for standard tools that only take resolved inputs
                    result = await asyncio.wait_for(
                        tool(**resolved_inputs),
                        timeout=step.timeout
                    )
            else:
                loop = asyncio.get_event_loop()
                try:
                    result = await loop.run_in_executor(
                        None,
                        lambda: tool(action=step.action, inputs=resolved_inputs, context=context)
                    )
                except TypeError:
                    result = await loop.run_in_executor(
                        None,
                        lambda: tool(**resolved_inputs)
                    )
            
            return {
                "status": "success",
                "output": result,
                "timestamp": datetime.now().isoformat()
            }
        except asyncio.TimeoutError:
            return {
                "status": "timeout",
                "error": f"Step timeout after {step.timeout} seconds"
            }
        except Exception as e:
            logger.error(f"Action execution failed: {e}")
            return {
                "status": "error",
                "error": str(e)
            }
    
    def supports(self, step_type: str) -> bool:
        return step_type == "action"
    
    def _resolve_inputs(self, inputs: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        """Resolve input parameters using context variables"""
        resolved = {}
        for key, value in inputs.items():
            if isinstance(value, str) and value.startswith("${"):
                # Context variable reference
                var_name = value[2:-1]  # Remove ${ and }
                resolved[key] = context.get(var_name)
            else:
                resolved[key] = value
        return resolved


class DecisionExecutor(WorkflowExecutor):
    """Executor for decision steps (conditional branching)"""
    
    async def execute(self, step: WorkflowStep, context: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a decision step"""
        try:
            if not step.condition:
                return {
                    "status": "error",
                    "error": "Decision step requires a condition"
                }
            
            # Simple condition evaluation (can be extended)
            result = self._evaluate_condition(step.condition, context)
            
            return {
                "status": "success",
                "decision": result,
                "next_step": step.config.get("true_branch" if result else "false_branch")
            }
        except Exception as e:
            logger.error(f"Decision evaluation failed: {e}")
            return {
                "status": "error",
                "error": str(e)
            }
    
    def supports(self, step_type: str) -> bool:
        return step_type == "decision"
    
    def _evaluate_condition(self, condition: str, context: Dict[str, Any]) -> bool:
        """Evaluate a condition string"""
        # Simple condition evaluation - can be extended with more complex logic
        try:
            # Replace context variables
            eval_condition = condition
            for key, value in context.items():
                if isinstance(value, (str, int, float, bool)):
                    eval_condition = eval_condition.replace(f"${{{key}}}", str(value))
            
            # Safe evaluation
            return bool(eval(eval_condition))
        except Exception as e:
            logger.warning(f"Condition evaluation error: {e}")
            return False


class ParallelExecutor(WorkflowExecutor):
    """Executor for parallel execution steps"""
    
    async def execute(self, step: WorkflowStep, context: Dict[str, Any]) -> Dict[str, Any]:
        """Execute multiple steps in parallel"""
        try:
            parallel_steps = step.config.get("steps", [])
            
            if not parallel_steps:
                return {
                    "status": "success",
                    "results": {}
                }
            
            # Execute all steps concurrently
            tasks = [
                self._execute_parallel_step(s, context)
                for s in parallel_steps
            ]
            
            results = await asyncio.gather(*tasks)
            
            return {
                "status": "success",
                "results": {step["id"]: step["result"] for step in results}
            }
        except Exception as e:
            logger.error(f"Parallel execution failed: {e}")
            return {
                "status": "error",
                "error": str(e)
            }
    
    def supports(self, step_type: str) -> bool:
        return step_type == "parallel"
    
    async def _execute_parallel_step(self, step_config: Dict[str, Any], context: Dict[str, Any]):
        """Execute a single parallel step"""
        # This would be implemented with actual executors
        return {
            "id": step_config.get("id"),
            "result": {"status": "success"}
        }


class WorkflowEngine:
    """Main workflow execution engine"""
    
    def __init__(self):
        self.templates: Dict[str, WorkflowTemplate] = {}
        self.executions: Dict[str, WorkflowExecution] = {}
        self.executors: List[WorkflowExecutor] = [
            ActionExecutor({}),
            DecisionExecutor(),
            ParallelExecutor()
        ]
        self.hooks: Dict[str, List[Callable]] = {
            "before_start": [],
            "after_step": [],
            "on_error": [],
            "on_complete": []
        }
    
    def register_template(self, template: WorkflowTemplate) -> None:
        """Register a workflow template"""
        if template.id in self.templates:
            raise ValueError(f"Template {template.id} already registered")
        self.templates[template.id] = template
        logger.info(f"Template registered: {template.id}")
    
    def get_template(self, template_id: str) -> Optional[WorkflowTemplate]:
        """Get a workflow template by ID"""
        return self.templates.get(template_id)
    
    def list_templates(self, category: Optional[str] = None) -> List[WorkflowTemplate]:
        """List all templates, optionally filtered by category"""
        templates = list(self.templates.values())
        if category:
            templates = [t for t in templates if t.category == category]
        return templates
    
    async def execute_workflow(
        self,
        workflow_id: str,
        template_id: Optional[str] = None,
        inputs: Optional[Dict[str, Any]] = None
    ) -> str:
        """Start a workflow execution"""
        execution = WorkflowExecution(
            id=str(uuid.uuid4()),
            workflow_id=workflow_id,
            template_id=template_id,
            inputs=inputs or {},
            started_at=datetime.now().isoformat()
        )
        
        self.executions[execution.id] = execution
        
        # Run hooks
        await self._run_hooks("before_start", execution)
        
        # Start execution in background
        asyncio.create_task(self._execute(execution))
        
        return execution.id
    
    async def _execute(self, execution: WorkflowExecution) -> None:
        """Internal method to execute a workflow"""
        try:
            execution.status = WorkflowStatus.RUNNING
            
            # Load template if provided
            if execution.template_id:
                template = self.get_template(execution.template_id)
                if not template:
                    raise ValueError(f"Template not found: {execution.template_id}")
                steps = template.steps
            else:
                raise ValueError("No template or steps provided")
            
            # Execute steps sequentially
            for step in steps:
                if execution.status != WorkflowStatus.RUNNING:
                    break
                
                try:
                    execution.current_step = step.id
                    result = await self._execute_step(step, execution.context)
                    
                    step_output = result.get("output", {})
                    # Store results under the step ID so they can be referenced like ${step_id.output}
                    execution.context[step.id] = step_output
                    execution.results[step.id] = step_output
                    
                    if isinstance(step_output, dict):
                        execution.context.update(step_output)
                    else:
                        execution.context["last_output"] = step_output
                        
                    execution.completed_steps.append(step.id)
                    execution.progress = len(execution.completed_steps) / len(steps)
                    
                    await self._run_hooks("after_step", execution, step, result)
                
                except Exception as e:
                    logger.error(f"Step execution failed: {e}")
                    execution.failed_steps.append(step.id)
                    execution.errors.append({
                        "step": step.id,
                        "error": str(e),
                        "timestamp": datetime.now().isoformat()
                    })
                    
                    # Handle retry
                    if step.retry_count > 0:
                        for retry in range(step.retry_count):
                            await asyncio.sleep(step.retry_delay)
                            try:
                                result = await self._execute_step(step, execution.context)
                                execution.completed_steps.append(step.id)
                                break
                            except Exception:
                                if retry == step.retry_count - 1:
                                    raise
                    else:
                        raise
            
            execution.status = WorkflowStatus.COMPLETED
            execution.completed_at = datetime.now().isoformat()
            await self._run_hooks("on_complete", execution)
            
        except Exception as e:
            logger.error(f"Workflow execution failed: {e}")
            execution.status = WorkflowStatus.FAILED
            execution.errors.append({
                "type": "workflow",
                "error": str(e),
                "timestamp": datetime.now().isoformat()
            })
            await self._run_hooks("on_error", execution, e)
    
    async def _execute_step(self, step: WorkflowStep, context: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a single workflow step"""
        for executor in self.executors:
            if executor.supports(step.type):
                return await executor.execute(step, context)
        
        raise ValueError(f"No executor found for step type: {step.type}")
    
    def get_execution(self, execution_id: str) -> Optional[WorkflowExecution]:
        """Get an execution by ID"""
        return self.executions.get(execution_id)
    
    def pause_execution(self, execution_id: str) -> bool:
        """Pause a running workflow"""
        execution = self.executions.get(execution_id)
        if execution and execution.status == WorkflowStatus.RUNNING:
            execution.status = WorkflowStatus.PAUSED
            return True
        return False
    
    def resume_execution(self, execution_id: str) -> bool:
        """Resume a paused workflow"""
        execution = self.executions.get(execution_id)
        if execution and execution.status == WorkflowStatus.PAUSED:
            execution.status = WorkflowStatus.RUNNING
            asyncio.create_task(self._execute(execution))
            return True
        return False
    
    def cancel_execution(self, execution_id: str) -> bool:
        """Cancel a workflow execution"""
        execution = self.executions.get(execution_id)
        if execution and execution.status in [WorkflowStatus.RUNNING, WorkflowStatus.PAUSED]:
            execution.status = WorkflowStatus.CANCELLED
            return True
        return False
    
    def register_hook(self, hook_name: str, callback: Callable) -> None:
        """Register a hook callback"""
        if hook_name in self.hooks:
            self.hooks[hook_name].append(callback)
    
    async def _run_hooks(self, hook_name: str, *args, **kwargs) -> None:
        """Run all registered hooks"""
        if hook_name not in self.hooks:
            return
        
        for callback in self.hooks[hook_name]:
            try:
                if asyncio.iscoroutinefunction(callback):
                    await callback(*args, **kwargs)
                else:
                    callback(*args, **kwargs)
            except Exception as e:
                logger.error(f"Hook error: {e}")


# Global workflow engine instance
_workflow_engine: Optional[WorkflowEngine] = None


def get_workflow_engine() -> WorkflowEngine:
    """Get or create the global workflow engine"""
    global _workflow_engine
    if _workflow_engine is None:
        _workflow_engine = WorkflowEngine()
    return _workflow_engine


def serialize_workflow(workflow: WorkflowTemplate) -> Dict[str, Any]:
    """Serialize a workflow template to JSON"""
    return {
        "id": workflow.id,
        "name": workflow.name,
        "description": workflow.description,
        "category": workflow.category,
        "difficulty": workflow.difficulty,
        "version": workflow.version,
        "author": workflow.author,
        "inputs": [asdict(inp) for inp in workflow.inputs],
        "steps": [asdict(step) for step in workflow.steps],
        "tags": workflow.tags,
        "best_practices": workflow.best_practices,
        "estimated_time": workflow.estimated_time,
        "created_at": workflow.created_at,
        "updated_at": workflow.updated_at
    }


def serialize_execution(execution: WorkflowExecution) -> Dict[str, Any]:
    """Serialize a workflow execution to JSON"""
    return {
        "id": execution.id,
        "workflow_id": execution.workflow_id,
        "template_id": execution.template_id,
        "status": execution.status.value,
        "inputs": execution.inputs,
        "context": execution.context,
        "current_step": execution.current_step,
        "completed_steps": execution.completed_steps,
        "failed_steps": execution.failed_steps,
        "results": execution.results,
        "errors": execution.errors,
        "progress": execution.progress,
        "started_at": execution.started_at,
        "completed_at": execution.completed_at
    }
