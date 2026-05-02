import asyncio
import os
import sys

# Add backend to path
sys.path.append(os.path.abspath('backend'))

from workflow_api import initialize_workflows
from workflows import get_workflow_engine
from workflow_tools import get_ai_workflow_tools
from ai_manager import init_ai

async def test():
    # Initialize AI manager
    init_ai()
    
    # Initialize engine and templates
    initialize_workflows()
    engine = get_workflow_engine()
    
    # Let's see what templates we have
    templates = engine.list_templates()
    print(f"Loaded {len(templates)} templates")
    
    template_id = None
    for t in templates:
        print(f" - {t.id}: {t.name}")
        if "quick" in t.id.lower() or "quick" in t.name.lower():
            template_id = t.id
            
    if not template_id and templates:
        template_id = templates[0].id
        
    if not template_id:
        print("No templates found!")
        return
        
    print(f"\nExecuting template: {template_id}")
    
    # Execute workflow
    execution_id = await engine.execute_workflow(
        workflow_id="test-wf-1",
        template_id=template_id,
        inputs={"target": "test-domain.com"}
    )
    
    print(f"Execution started: {execution_id}")
    
    # Wait for completion
    for i in range(100):
        await asyncio.sleep(3)
        execution = engine.get_execution(execution_id)
        print(f"Status: {execution.status.value}, Progress: {execution.progress*100:.1f}%")
        if execution.status.value in ["completed", "failed", "cancelled"]:
            break
            
    execution = engine.get_execution(execution_id)
    print("\n--- Final Results ---")
    print(f"Status: {execution.status.value}")
    if execution.errors:
        print(f"Errors: {execution.errors}")
    
    for step_id, result in execution.results.items():
        print(f"\n[{step_id}]")
        if isinstance(result, dict) and 'output' in result:
            print(str(result['output'])[:200] + "...")
        else:
            print(str(result)[:200] + "...")

if __name__ == "__main__":
    asyncio.run(test())
