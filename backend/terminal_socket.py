"""
Terminal Socket Handler for ShadowHack
Phase 16: Interactive Web Terminal
Bridges WebSocket events to Docker exec streams.
"""

from flask import request
from flask_socketio import Namespace, emit, disconnect
from docker_lab_manager import DockerLabManager, logger
import threading
import time
import socket

try:
    from main import socketio
except ImportError:
    socketio = None

class TerminalNamespace(Namespace):
    """
    Handles terminal connections for Docker labs.
    Path: /ws/terminal
    """
    
    def __init__(self, check_origin=True):
        super().__init__('/ws/terminal')
        self.lab_manager = DockerLabManager()
        self.active_terminals = {} # socket_id -> {exec_id, socket, stream}

    def on_connect(self):
        """Handle client connection"""
        # In real implementation: Verify token from query params
        # token = request.args.get('token')
        lab_id = request.args.get('lab_id')
        user_id = request.args.get('user_id')
        
        if not lab_id or not user_id:
            logger.warning("Terminal connection rejected: Missing params")
            disconnect()
            return
            
        logger.info(f"Terminal connection request: User {user_id} for Lab {lab_id}")
        
        # Verify container belongs to user (Security check)
        status = self.lab_manager.get_lab_status(int(user_id), int(lab_id))
        
        if status['state'] != 'running':
            emit('terminal_error', {'message': 'Lab container is not running'})
            disconnect()
            return

        container_name = status.get('container_name')
        if not container_name:
            emit('terminal_error', {'message': 'Container ID not found'})
            disconnect()
            return
            
        # Store metadata
        self.active_terminals[request.sid] = {
            'container_name': container_name,
            'user_id': user_id,
            'buffer': []
        }
        
        emit('terminal_params', {'rows': 24, 'cols': 80})
        
        # Start the shell session
        self._start_shell(request.sid, container_name)

    def on_disconnect(self):
        """Cleanup resources on disconnect"""
        if request.sid in self.active_terminals:
            logger.info(f"Terminal disconnected: {request.sid}")
            # The docker stream closes automatically when we stop reading/writing
            del self.active_terminals[request.sid]

    def on_input(self, data):
        """Receive keystrokes from frontend xterm.js"""
        if request.sid not in self.active_terminals:
            return
            
        session = self.active_terminals[request.sid]
        sock = session.get('socket')
        
        if sock:
            try:
                # Send raw bytes to docker socket
                sock.send(data.encode())
            except Exception as e:
                logger.error(f"Error sending input to container: {e}")
                emit('terminal_error', {'message': 'Connection lost'})

    def on_resize(self, data):
        """Handle terminal resize"""
        if request.sid not in self.active_terminals:
            return
            
        rows = data.get('rows', 24)
        cols = data.get('cols', 80)
        container_name = self.active_terminals[request.sid].get('container_name')
        
        if container_name:
            try:
                # Resize via Docker API
                container = self.lab_manager.client.containers.get(container_name)
                container.resize(height=rows, width=cols)
            except Exception as e:
                logger.warning(f"Resize failed: {e}")

    def _start_shell(self, sid, container_name):
        """Attach to container shell via raw socket"""
        try:
            container = self.lab_manager.client.containers.get(container_name)
            
            # Exec a bash shell (or sh if bash is missing)
            # We use socket=True to get a raw socket for bidirectional stream
            exec_cmd = container.client.api.exec_create(
                container.id, 
                cmd=["/bin/bash"], 
                stdin=True, 
                tty=True
            )
            
            exec_id = exec_cmd['Id']
            
            # Start exec and get raw socket
            sock = container.client.api.exec_start(
                exec_id, 
                detach=False, 
                tty=True, 
                socket=True
            )
            
            # Store socket reference
            if sid in self.active_terminals:
                self.active_terminals[sid]['socket'] = sock
                
            # Start background thread to read output from container -> frontend
            threading.Thread(
                target=self._read_docker_stream, 
                args=(sid, sock),
                daemon=True
            ).start()
            
        except Exception as e:
            logger.error(f"Failed to start shell: {e}")
            if sid in self.active_terminals: # Check if still connected
                socketio.emit('terminal_error', {'message': str(e)}, to=sid, namespace='/ws/terminal')

    def _read_docker_stream(self, sid, sock):
        """Read data from Docker socket and emit to frontend"""
        try:
            # We must use a separate socket object for reading if blocking
            # Or just read from the raw socket
            while True:
                # data = sock.read(4096) # For SSLSocket or similar
                # For raw socket from docker-py on Windows/Linux:
                data = sock.recv(4096)
                
                if not data:
                    break
                    
                # Emit to specific client in namespace
                if socketio:
                   socketio.emit('output', data.decode(errors='replace'), to=sid, namespace='/ws/terminal')
                
        except Exception as e:
            logger.error(f"Read stream ended: {e}")
        finally:
            if sid in self.active_terminals:
                socketio.emit('terminal_error', {'message': 'Session ended'}, to=sid, namespace='/ws/terminal')
