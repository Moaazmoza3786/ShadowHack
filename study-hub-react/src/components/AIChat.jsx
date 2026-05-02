/**
 * AI Chat Component
 * Real-time chat interface with MiniMax M2.5 AI Assistant
 */

import React, { useState, useEffect, useRef } from 'react';
import { AlertCircle, Send, Loader, MessageCircle, Zap } from 'lucide-react';
import io from 'socket.io-client';

const AIChat = ({ conversationId, role = 'pentester' }) => {
  const [messages, setMessages] = useState([]);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [socket, setSocket] = useState(null);
  const [aiStatus, setAiStatus] = useState('disconnected');
  const messagesEndRef = useRef(null);

  // Scroll to bottom on new messages
  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  useEffect(() => {
    scrollToBottom();
  }, [messages]);

  // Initialize WebSocket connection
  useEffect(() => {
    const newSocket = io('/ai', {
      reconnection: true,
      reconnectionDelay: 1000,
      reconnectionDelayMax: 5000,
      reconnectionAttempts: 5,
    });

    newSocket.on('connect', () => {
      console.log('Connected to AI service');
      setAiStatus('connected');

      // Start chat session
      newSocket.emit('ai:start_chat', {
        conversation_id: conversationId,
        user_id: localStorage.getItem('user_id') || 'anonymous',
        role: role,
      });
    });

    newSocket.on('ai:chat_started', (data) => {
      console.log('Chat session started:', data);
    });

    newSocket.on('ai:message_chunk', (data) => {
      // Append chunk to last message
      setMessages((prev) => {
        const updated = [...prev];
        if (updated.length > 0) {
          const lastMsg = updated[updated.length - 1];
          if (lastMsg.role === 'assistant') {
            lastMsg.content += data.chunk;
          }
        }
        return updated;
      });
    });

    newSocket.on('ai:response_complete', (data) => {
      setLoading(false);
    });

    newSocket.on('ai:status_update', (data) => {
      console.log('AI Status:', data);
      setAiStatus('ready');
    });

    newSocket.on('error', (error) => {
      console.error('Socket error:', error);
      setMessages((prev) => [
        ...prev,
        {
          role: 'system',
          content: `Error: ${error.message}`,
        },
      ]);
      setLoading(false);
    });

    newSocket.on('disconnect', () => {
      setAiStatus('disconnected');
    });

    setSocket(newSocket);

    return () => {
      newSocket.disconnect();
    };
  }, [conversationId, role]);

  const handleSendMessage = (e) => {
    e.preventDefault();

    if (!input.trim() || !socket) return;

    // Add user message
    setMessages((prev) => [
      ...prev,
      {
        role: 'user',
        content: input,
      },
    ]);

    // Add loading placeholder for assistant
    setMessages((prev) => [
      ...prev,
      {
        role: 'assistant',
        content: '',
      },
    ]);

    setLoading(true);
    setInput('');

    // Send message to AI
    socket.emit('ai:send_message', {
      conversation_id: conversationId,
      message: input,
      role: role,
    });
  };

  const roleDescriptions = {
    pentester: '🎯 Pentester - Expert penetration testing strategies',
    analyst: '📊 Analyst - Security vulnerability analysis',
    payload_generator: '💣 Payload Generator - Exploit development',
    report_writer: '📝 Report Writer - Professional documentation',
  };

  return (
    <div className="flex flex-col h-full bg-slate-900 rounded-lg border border-slate-700">
      {/* Header */}
      <div className="bg-linear-to-r from-cyan-900 to-blue-900 border-b border-cyan-500 p-4 rounded-t-lg">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Zap className="w-5 h-5 text-cyan-400" />
            <h2 className="text-lg font-bold text-cyan-300">ShadowHack AI Assistant</h2>
          </div>
          <div className="flex items-center gap-2">
            <div
              className={`w-2 h-2 rounded-full ${
                aiStatus === 'connected' || aiStatus === 'ready'
                  ? 'bg-green-500'
                  : aiStatus === 'disconnected'
                    ? 'bg-red-500'
                    : 'bg-yellow-500'
              }`}
            ></div>
            <span className="text-sm text-cyan-200">{aiStatus}</span>
          </div>
        </div>
        <p className="text-sm text-cyan-400 mt-2">{roleDescriptions[role]}</p>
      </div>

      {/* Messages Area */}
      <div className="flex-1 overflow-y-auto p-4 space-y-4">
        {messages.length === 0 ? (
          <div className="flex items-center justify-center h-full text-slate-400">
            <div className="text-center">
              <MessageCircle className="w-12 h-12 mx-auto mb-2 opacity-50" />
              <p>Start a conversation with the AI Assistant</p>
            </div>
          </div>
        ) : (
          messages.map((msg, idx) => (
            <div
              key={idx}
              className={`flex ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`}
            >
              <div
                className={`max-w-xs lg:max-w-md xl:max-w-lg px-4 py-2 rounded-lg ${
                  msg.role === 'user'
                    ? 'bg-cyan-600 text-white rounded-br-none'
                    : msg.role === 'system'
                      ? 'bg-red-900 text-red-200 rounded-bl-none'
                      : 'bg-slate-800 text-slate-100 rounded-bl-none border border-slate-700'
                }`}
              >
                <p className="text-sm whitespace-pre-wrap break-words">{msg.content}</p>
              </div>
            </div>
          ))
        )}
        {loading && (
          <div className="flex justify-start">
            <div className="bg-slate-800 px-4 py-2 rounded-lg border border-slate-700">
              <Loader className="w-5 h-5 text-cyan-400 animate-spin" />
            </div>
          </div>
        )}
        <div ref={messagesEndRef} />
      </div>

      {/* Input Area */}
      <div className="border-t border-slate-700 p-4">
        <form onSubmit={handleSendMessage} className="flex gap-2">
          <input
            type="text"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder="Ask the AI anything about security testing..."
            disabled={loading || aiStatus === 'disconnected'}
            className="flex-1 bg-slate-800 border border-slate-600 rounded px-4 py-2 text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500 disabled:opacity-50"
          />
          <button
            type="submit"
            disabled={loading || !input.trim() || aiStatus === 'disconnected'}
            className="bg-cyan-600 hover:bg-cyan-700 disabled:bg-slate-600 text-white rounded px-4 py-2 flex items-center gap-2 transition"
          >
            <Send className="w-4 h-4" />
            Send
          </button>
        </form>

        {aiStatus === 'disconnected' && (
          <div className="mt-2 flex items-center gap-2 text-red-400 text-sm">
            <AlertCircle className="w-4 h-4" />
            AI Service disconnected
          </div>
        )}
      </div>
    </div>
  );
};

export default AIChat;
