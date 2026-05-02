"""
Phase 4: Workflows REST API and WebSocket endpoints
Handles workflow template management and execution
"""

from flask import Blueprint, request, jsonify
from flask_socketio import Namespace, emit
import asyncio
import logging
from typing import Optional

from workflows import (
    get_workflow_engine, serialize_workflow, serialize_execution,
    WorkflowTemplate, WorkflowStep, WorkflowInput, WorkflowStatus
)
from workflow_templates import register_default_templates
from workflow_tools import get_ai_workflow_tools

logger = logging.getLogger(__name__)

# Create blueprint
workflow_bp = Blueprint('workflows', __name__, url_prefix='/api/workflows')

# Initialize engine and templates
_engine_initialized = False


def initialize_workflows():
    """Initialize workflow engine and templates"""
    global _engine_initialized
    if not _engine_initialized:
        engine = get_workflow_engine()
        
        # Register default templates
        register_default_templates()
        
        # Register AI-powered tools
        ai_tools = get_ai_workflow_tools()
        for executor in engine.executors:
            if hasattr(executor, 'tool_registry'):
                executor.tool_registry.update(ai_tools)
        
        _engine_initialized = True
        logger.info("Workflow engine initialized with default templates and AI tools")


# REST API Endpoints

@workflow_bp.route('/health', methods=['GET'])
def health():
    """Check workflow engine health"""
    initialize_workflows()
    engine = get_workflow_engine()
    
    return jsonify({
        "status": "healthy",
        "templates_loaded": len(engine.templates),
        "active_executions": len(engine.executions)
    }), 200


@workflow_bp.route('/templates', methods=['GET'])
def list_templates():
    """Get all available workflow templates"""
    initialize_workflows()
    engine = get_workflow_engine()
    
    category = request.args.get('category')
    difficulty = request.args.get('difficulty')
    
    templates = engine.list_templates(category=category)
    
    # Filter by difficulty if provided
    if difficulty:
        templates = [t for t in templates if t.difficulty == difficulty]
    
    return jsonify({
        "count": len(templates),
        "templates": [serialize_workflow(t) for t in templates]
    }), 200


@workflow_bp.route('/templates/<template_id>', methods=['GET'])
def get_template(template_id: str):
    """Get a specific workflow template"""
    initialize_workflows()
    engine = get_workflow_engine()
    
    template = engine.get_template(template_id)
    if not template:
        return jsonify({"error": "Template not found"}), 404
    
    return jsonify(serialize_workflow(template)), 200


@workflow_bp.route('/templates', methods=['POST'])
def create_template():
    """Create a new workflow template"""
    initialize_workflows()
    engine = get_workflow_engine()
    
    try:
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['id', 'name', 'description', 'category', 'difficulty']
        for field in required_fields:
            if field not in data:
                return jsonify({"error": f"Missing required field: {field}"}), 400
        
        # Parse inputs
        inputs = []
        for inp_data in data.get('inputs', []):
            inputs.append(WorkflowInput(
                name=inp_data.get('name'),
                type=inp_data.get('type', 'string'),
                required=inp_data.get('required', True),
                default=inp_data.get('default'),
                description=inp_data.get('description', ''),
                options=inp_data.get('options', [])
            ))
        
        # Parse steps
        steps = []
        for step_data in data.get('steps', []):
            steps.append(WorkflowStep(
                id=step_data.get('id'),
                type=step_data.get('type'),
                name=step_data.get('name'),
                description=step_data.get('description', ''),
                action=step_data.get('action', ''),
                config=step_data.get('config', {}),
                inputs=step_data.get('inputs', {}),
                outputs=step_data.get('outputs', {}),
                condition=step_data.get('condition'),
                next_step=step_data.get('next_step'),
                error_handler=step_data.get('error_handler'),
                timeout=step_data.get('timeout', 300),
                retry_count=step_data.get('retry_count', 0),
                retry_delay=step_data.get('retry_delay', 5),
                tags=step_data.get('tags', [])
            ))
        
        # Create template
        from datetime import datetime
        template = WorkflowTemplate(
            id=data['id'],
            name=data['name'],
            description=data['description'],
            category=data['category'],
            difficulty=data['difficulty'],
            icon=data.get('icon', ''),
            version=data.get('version', '1.0.0'),
            author=data.get('author', ''),
            inputs=inputs,
            steps=steps,
            expected_output=data.get('expected_output', ''),
            estimated_time=data.get('estimated_time', 0),
            tags=data.get('tags', []),
            best_practices=data.get('best_practices', []),
            created_at=datetime.now().isoformat(),
            updated_at=datetime.now().isoformat()
        )
        
        engine.register_template(template)
        
        return jsonify({
            "message": "Template created successfully",
            "template": serialize_workflow(template)
        }), 201
        
    except Exception as e:
        logger.error(f"Error creating template: {e}")
        return jsonify({"error": str(e)}), 400


@workflow_bp.route('/templates/<template_id>', methods=['PUT'])
def update_template(template_id: str):
    """Update an existing workflow template"""
    initialize_workflows()
    engine = get_workflow_engine()
    
    template = engine.get_template(template_id)
    if not template:
        return jsonify({"error": "Template not found"}), 404
    
    try:
        data = request.get_json()
        
        # Update fields
        if 'name' in data:
            template.name = data['name']
        if 'description' in data:
            template.description = data['description']
        if 'steps' in data:
            # Parse new steps
            steps = []
            for step_data in data['steps']:
                steps.append(WorkflowStep(
                    id=step_data.get('id'),
                    type=step_data.get('type'),
                    name=step_data.get('name'),
                    description=step_data.get('description', ''),
                    action=step_data.get('action', ''),
                    inputs=step_data.get('inputs', {})
                ))
            template.steps = steps
        
        from datetime import datetime
        template.updated_at = datetime.now().isoformat()
        
        return jsonify({
            "message": "Template updated successfully",
            "template": serialize_workflow(template)
        }), 200
        
    except Exception as e:
        logger.error(f"Error updating template: {e}")
        return jsonify({"error": str(e)}), 400


@workflow_bp.route('/execute', methods=['POST'])
def execute_workflow():
    """Execute a workflow"""
    initialize_workflows()
    engine = get_workflow_engine()
    
    try:
        data = request.get_json()
        
        workflow_id = data.get('workflow_id', f"wf-{str(__import__('uuid').uuid4())[:8]}")
        template_id = data.get('template_id')
        inputs = data.get('inputs', {})
        
        if not template_id:
            return jsonify({"error": "template_id is required"}), 400
        
        # Validate template exists
        template = engine.get_template(template_id)
        if not template:
            return jsonify({"error": "Template not found"}), 404
        
        # Execute workflow
        execution_id = asyncio.run(engine.execute_workflow(
            workflow_id=workflow_id,
            template_id=template_id,
            inputs=inputs
        ))
        
        execution = engine.get_execution(execution_id)
        
        return jsonify({
            "message": "Workflow execution started",
            "execution_id": execution_id,
            "execution": serialize_execution(execution)
        }), 201
        
    except Exception as e:
        logger.error(f"Error executing workflow: {e}")
        return jsonify({"error": str(e)}), 400


@workflow_bp.route('/execution/<execution_id>', methods=['GET'])
def get_execution_status(execution_id: str):
    """Get workflow execution status"""
    initialize_workflows()
    engine = get_workflow_engine()
    
    execution = engine.get_execution(execution_id)
    if not execution:
        return jsonify({"error": "Execution not found"}), 404
    
    return jsonify(serialize_execution(execution)), 200


@workflow_bp.route('/execution/<execution_id>/pause', methods=['POST'])
def pause_execution(execution_id: str):
    """Pause a running workflow"""
    initialize_workflows()
    engine = get_workflow_engine()
    
    if engine.pause_execution(execution_id):
        execution = engine.get_execution(execution_id)
        return jsonify({
            "message": "Workflow paused",
            "execution": serialize_execution(execution)
        }), 200
    else:
        return jsonify({"error": "Cannot pause execution"}), 400


@workflow_bp.route('/execution/<execution_id>/resume', methods=['POST'])
def resume_execution(execution_id: str):
    """Resume a paused workflow"""
    initialize_workflows()
    engine = get_workflow_engine()
    
    if engine.resume_execution(execution_id):
        execution = engine.get_execution(execution_id)
        return jsonify({
            "message": "Workflow resumed",
            "execution": serialize_execution(execution)
        }), 200
    else:
        return jsonify({"error": "Cannot resume execution"}), 400


@workflow_bp.route('/execution/<execution_id>/cancel', methods=['POST'])
def cancel_execution(execution_id: str):
    """Cancel a workflow execution"""
    initialize_workflows()
    engine = get_workflow_engine()
    
    if engine.cancel_execution(execution_id):
        execution = engine.get_execution(execution_id)
        return jsonify({
            "message": "Workflow cancelled",
            "execution": serialize_execution(execution)
        }), 200
    else:
        return jsonify({"error": "Cannot cancel execution"}), 400


@workflow_bp.route('/execution/list', methods=['GET'])
def list_executions():
    """List all workflow executions"""
    initialize_workflows()
    engine = get_workflow_engine()
    
    status = request.args.get('status')
    
    executions = list(engine.executions.values())
    
    if status:
        executions = [e for e in executions if e.status.value == status]
    
    return jsonify({
        "count": len(executions),
        "executions": [serialize_execution(e) for e in executions]
    }), 200


class WorkflowNamespace(Namespace):
    def __init__(self, namespace='/workflows'):
        super().__init__(namespace)

    def on_list_templates(self):
        """WebSocket event: list templates"""
        initialize_workflows()
        engine = get_workflow_engine()
        
        templates = engine.list_templates()
        emit('templates_list', {
            "count": len(templates),
            "templates": [serialize_workflow(t) for t in templates]
        })

    def on_execute(self, data):
        """WebSocket event: execute workflow"""
        initialize_workflows()
        engine = get_workflow_engine()
        
        try:
            template_id = data.get('template_id')
            inputs = data.get('inputs', {})
            
            if not template_id:
                emit('error', {"error": "template_id is required"})
                return
            
            # Execute workflow
            execution_id = asyncio.run(engine.execute_workflow(
                template_id=template_id,
                inputs=inputs
            ))
            
            execution = engine.get_execution(execution_id)
            
            emit('execution_started', {
                "execution_id": execution_id,
                "execution": serialize_execution(execution)
            })
            
        except Exception as e:
            logger.error(f"Error executing workflow: {e}")
            emit('error', {"error": str(e)})

    def on_get_status(self, data):
        """WebSocket event: get execution status"""
        initialize_workflows()
        engine = get_workflow_engine()
        
        execution_id = data.get('execution_id')
        if not execution_id:
            emit('error', {"error": "execution_id is required"})
            return
        
        execution = engine.get_execution(execution_id)
        if not execution:
            emit('error', {"error": "Execution not found"})
            return
        
        emit('status', {
            "execution_id": execution_id,
            "execution": serialize_execution(execution)
        })

    def on_pause(self, data):
        """WebSocket event: pause workflow"""
        initialize_workflows()
        engine = get_workflow_engine()
        
        execution_id = data.get('execution_id')
        if engine.pause_execution(execution_id):
            execution = engine.get_execution(execution_id)
            emit('paused', {
                "execution_id": execution_id,
                "execution": serialize_execution(execution)
            })
        else:
            emit('error', {"error": "Cannot pause execution"})

    def on_resume(self, data):
        """WebSocket event: resume workflow"""
        initialize_workflows()
        engine = get_workflow_engine()
        
        execution_id = data.get('execution_id')
        if engine.resume_execution(execution_id):
            execution = engine.get_execution(execution_id)
            emit('resumed', {
                "execution_id": execution_id,
                "execution": serialize_execution(execution)
            })
        else:
            emit('error', {"error": "Cannot resume execution"})

    def on_cancel(self, data):
        """WebSocket event: cancel workflow"""
        initialize_workflows()
        engine = get_workflow_engine()
        
        execution_id = data.get('execution_id')
        if engine.cancel_execution(execution_id):
            execution = engine.get_execution(execution_id)
            emit('cancelled', {
                "execution_id": execution_id,
                "execution": serialize_execution(execution)
            })
        else:
            emit('error', {"error": "Cannot cancel execution"})
