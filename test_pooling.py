
import sys
import os
import time

# Add backend to path
sys.path.append(os.path.join(os.getcwd(), 'backend'))

from docker_lab_manager import get_docker_manager

def test_pooling():
    manager = get_docker_manager()
    print(f"Docker Available: {manager.is_docker_available}")
    
    if not manager.is_docker_available:
        print("Skipping real test (simulation mode active)")
        return

    # 1. Replenish pool
    print("\n1. Replenishing pool...")
    manager.replenish_pool()
    
    # Give it a second to start
    time.sleep(5)
    
    # 2. Check available in pool
    from docker_lab_manager import DockerLabManager
    filters = {
        "label": [
            f"studyhub.pool=true",
        ],
        "status": "running"
    }
    pooled = manager.client.containers.list(filters=filters)
    print(f"Containers in pool: {len(pooled)}")
    
    if len(pooled) == 0:
        print("Error: Pool did not replenish.")
        return

    # 3. Spawn a lab that should be in pool (nginx:alpine)
    print("\n2. Spawning lab (should be from pool)...")
    start_time = time.time()
    result = manager.spawn_lab_container(user_id=999, image_name="nginx:alpine")
    end_time = time.time()
    
    print(f"Spawn time: {end_time - start_time:.2f}s")
    print(f"Result Pooled: {result.get('pooled', False)}")
    
    # 4. Cleanup
    print("\n3. Cleaning up test container...")
    manager.kill_user_containers(999)
    print("Test complete.")

if __name__ == "__main__":
    test_pooling()
