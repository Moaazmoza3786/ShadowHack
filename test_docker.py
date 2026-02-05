import sys
try:
    import docker
    print("Docker module found!")
    try:
        client = docker.from_env()
        print("Docker client connected!")
        print(client.version())
    except Exception as e:
        print(f"Docker module found but connection failed: {e}")
except ImportError:
    print("Docker module NOT found.")
