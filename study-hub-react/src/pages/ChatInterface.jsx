
import React, { useState, useEffect, useRef } from 'react';
import {
    MessageSquare, Hash, User, Send, Paperclip,
    MoreVertical, Search, Settings, Phone, Video
} from 'lucide-react';
import './ChatInterface.css';

const ChatInterface = () => {
    const [activeChannel, setActiveChannel] = useState(null); // { id, type, name }
    const [messages, setMessages] = useState([]);
    const [newMessage, setNewMessage] = useState('');
    const [channels, setChannels] = useState([]);
    const [dms, setDms] = useState([]);
    const [loading, setLoading] = useState(true);
    const messagesEndRef = useRef(null);
    const userId = 1; // Simulated current user

    useEffect(() => {
        fetchContacts();
        // Poll for contacts/status updates
        const interval = setInterval(fetchContacts, 10000);
        return () => clearInterval(interval);
    }, []);

    useEffect(() => {
        if (activeChannel) {
            fetchHistory();
            // Poll for new messages
            const interval = setInterval(fetchHistory, 3000);
            return () => clearInterval(interval);
        }
    }, [activeChannel]);

    useEffect(() => {
        scrollToBottom();
    }, [messages]);

    const scrollToBottom = () => {
        messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
    };

    const fetchContacts = async () => {
        try {
            const res = await fetch(`http://localhost:5000/api/chat/contacts/${userId}`);
            const data = await res.json();
            if (data.success) {
                setChannels(data.channels);
                setDms(data.direct_messages);

                // Set default active channel (first team or dm)
                if (!activeChannel && !loading) {
                    if (data.channels.length > 0) {
                        setActiveChannel({ ...data.channels[0], type: 'team' });
                    } else if (data.direct_messages.length > 0) {
                        setActiveChannel({ ...data.direct_messages[0], type: 'dm' });
                    }
                }
            }
        } catch (err) {
            console.error(err);
        } finally {
            setLoading(false);
        }
    };

    const fetchHistory = async () => {
        if (!activeChannel) return;

        let url = '';
        if (activeChannel.type === 'team') {
            url = `http://localhost:5000/api/chat/history/team/${activeChannel.id}`;
        } else {
            url = `http://localhost:5000/api/chat/history/dm/${userId}/${activeChannel.id}`;
        }

        try {
            const res = await fetch(url);
            const data = await res.json();
            if (data.success) {
                // Simple diff check to avoid unnecessary re-renders/scrolls if deep equality implemented
                // For now just setMessages
                setMessages(data.messages.map(m => ({
                    ...m,
                    is_me: m.sender_id === userId
                })));
            }
        } catch (err) {
            console.error(err);
        }
    };

    const handleSend = async (e) => {
        e.preventDefault();
        if (!newMessage.trim() || !activeChannel) return;

        const payload = {
            sender_id: userId,
            content: newMessage,
            type: 'text'
        };

        if (activeChannel.type === 'team') {
            payload.team_id = activeChannel.id;
        } else {
            payload.recipient_id = activeChannel.id;
        }

        try {
            await fetch('http://localhost:5000/api/chat/send', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });
            setNewMessage('');
            fetchHistory(); // Immediate update
        } catch (err) {
            console.error(err);
        }
    };

    return (
        <div className="chat-interface">
            {/* Sidebar */}
            <div className="chat-sidebar">
                <div className="sidebar-header">
                    <div className="search-bar">
                        <Search size={16} />
                        <input type="text" placeholder="Find or start a conversation" />
                    </div>
                </div>

                <div className="channels-list">
                    <div className="list-section">
                        <h3 className="section-title">TEAMS</h3>
                        {channels.map(channel => (
                            <button
                                key={`team-${channel.id}`}
                                className={`channel-item ${activeChannel?.id === channel.id && activeChannel?.type === 'team' ? 'active' : ''}`}
                                onClick={() => setActiveChannel({ ...channel, type: 'team' })}
                            >
                                <Hash size={16} />
                                <span>{channel.name}</span>
                                {channel.unread > 0 && <span className="unread-badge">{channel.unread}</span>}
                            </button>
                        ))}
                    </div>

                    <div className="list-section">
                        <h3 className="section-title">DIRECT MESSAGES</h3>
                        {dms.map(dm => (
                            <button
                                key={`dm-${dm.id}`}
                                className={`channel-item user ${activeChannel?.id === dm.id && activeChannel?.type === 'dm' ? 'active' : ''}`}
                                onClick={() => setActiveChannel({ ...dm, type: 'dm' })}
                            >
                                <div className="dm-avatar">
                                    <img src={dm.avatar || `https://api.dicebear.com/7.x/cyber/svg?seed=${dm.name}`} alt="" />
                                    <span className={`status-dot ${dm.status}`}></span>
                                </div>
                                <span>{dm.name}</span>
                                {dm.unread > 0 && <span className="unread-badge">{dm.unread}</span>}
                            </button>
                        ))}
                    </div>
                </div>

                <div className="user-controls">
                    <div className="my-avatar">
                        <img src={`https://api.dicebear.com/7.x/cyber/svg?seed=CurrentUser`} alt="Me" />
                        <span className="status-dot online"></span>
                    </div>
                    <div className="my-info">
                        <span className="my-name">CyberOperator</span>
                        <span className="my-status">#Online</span>
                    </div>
                    <button className="settings-btn"><Settings size={16} /></button>
                </div>
            </div>

            {/* Main Chat Area */}
            <div className="chat-main">
                {activeChannel ? (
                    <>
                        <header className="chat-header">
                            <div className="header-info">
                                {activeChannel.type === 'team' ? <Hash size={24} /> : <User size={24} />}
                                <div>
                                    <h2>{activeChannel.name}</h2>
                                    <p>{activeChannel.type === 'team' ? 'Team Channel' : 'Direct Message'}</p>
                                </div>
                            </div>
                            <div className="header-actions">
                                <button title="Voice Call"><Phone size={20} /></button>
                                <button title="Video Call"><Video size={20} /></button>
                                <button title="More"><MoreVertical size={20} /></button>
                            </div>
                        </header>

                        <div className="messages-list">
                            {messages.map((msg, idx) => {
                                const isSequence = idx > 0 && messages[idx - 1].sender_id === msg.sender_id;
                                return (
                                    <div key={msg.id} className={`message-item ${msg.is_me ? 'me' : ''} ${isSequence ? 'sequence' : ''}`}>
                                        {!msg.is_me && !isSequence && (
                                            <div className="message-avatar">
                                                <img src={msg.sender_avatar || `https://api.dicebear.com/7.x/cyber/svg?seed=${msg.sender_name}`} alt="" />
                                            </div>
                                        )}
                                        <div className="message-content-wrapper">
                                            {!msg.is_me && !isSequence && (
                                                <span className="sender-name">
                                                    {msg.sender_name}
                                                    <span className="timestamp">{new Date(msg.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</span>
                                                </span>
                                            )}
                                            <div className="message-bubble">
                                                {msg.content}
                                            </div>
                                        </div>
                                    </div>
                                );
                            })}
                            <div ref={messagesEndRef} />
                        </div>

                        <form className="chat-input-area" onSubmit={handleSend}>
                            <button type="button" className="attach-btn"><Paperclip size={20} /></button>
                            <input
                                type="text"
                                value={newMessage}
                                onChange={(e) => setNewMessage(e.target.value)}
                                placeholder={`Message ${activeChannel.type === 'team' ? '#' : '@'}${activeChannel.name}`}
                            />
                            <button type="submit" className="send-btn" disabled={!newMessage.trim()}>
                                <Send size={20} />
                            </button>
                        </form>
                    </>
                ) : (
                    <div className="empty-chat">
                        <MessageSquare size={48} />
                        <p>Select a channel or conversation to start chatting</p>
                    </div>
                )}
            </div>
        </div>
    );
};

export default ChatInterface;
