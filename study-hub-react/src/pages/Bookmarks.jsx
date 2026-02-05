
import React, { useState, useEffect } from 'react';
import { Bookmark, ExternalLink, Trash2, Search, Code, BookOpen, PenTool } from 'lucide-react';
import { Link } from 'react-router-dom';
import './Bookmarks.css';

const Bookmarks = () => {
    const [bookmarks, setBookmarks] = useState([]);
    const [filter, setFilter] = useState('all');
    const [loading, setLoading] = useState(true);
    const userId = 1; // Simulated current user

    useEffect(() => {
        fetchBookmarks();
    }, []);

    const fetchBookmarks = async () => {
        try {
            const res = await fetch(`http://localhost:5000/api/search/bookmarks/${userId}`);
            const data = await res.json();
            if (data.success) setBookmarks(data.bookmarks);
        } catch (err) {
            console.error(err);
        } finally {
            setLoading(false);
        }
    };

    const removeBookmark = async (id, e) => {
        e.preventDefault();
        e.stopPropagation();
        if (!window.confirm('Remove this bookmark?')) return;

        try {
            await fetch(`http://localhost:5000/api/search/bookmarks/${id}`, { method: 'DELETE' });
            setBookmarks(prev => prev.filter(b => b.id !== id));
        } catch (err) {
            console.error(err);
        }
    };

    const getIcon = (type) => {
        switch (type) {
            case 'lab': return <Code size={20} />;
            case 'course': return <BookOpen size={20} />;
            case 'tool': return <PenTool size={20} />;
            default: return <Bookmark size={20} />;
        }
    };

    const filteredBookmarks = filter === 'all'
        ? bookmarks
        : bookmarks.filter(b => b.type === filter);

    return (
        <div className="bookmarks-container">
            <header className="bookmarks-header">
                <Bookmark size={28} className="header-icon" />
                <div>
                    <h1>SAVED <span className="highlight">ITEMS</span></h1>
                    <p>Your personal collection of labs, courses, and tools.</p>
                </div>
            </header>

            <div className="bookmarks-controls">
                <div className="filter-tabs">
                    {['all', 'lab', 'course', 'tool'].map(f => (
                        <button
                            key={f}
                            className={`filter-btn ${filter === f ? 'active' : ''}`}
                            onClick={() => setFilter(f)}
                        >
                            {f.charAt(0).toUpperCase() + f.slice(1)}s
                        </button>
                    ))}
                </div>
            </div>

            <div className="bookmarks-grid">
                {loading ? (
                    <div className="loading">Loading bookmarks...</div>
                ) : filteredBookmarks.length > 0 ? (
                    filteredBookmarks.map(item => (
                        <Link to={item.path} key={item.id} className="bookmark-card">
                            <div className="bookmark-icon">
                                {getIcon(item.type)}
                            </div>
                            <div className="bookmark-content">
                                <h3>{item.title}</h3>
                                <p>{item.description || 'No description provided'}</p>
                                <div className="bookmark-meta">
                                    <span className="bookmark-type">{item.type}</span>
                                    <span className="bookmark-date">Saved {new Date(item.created_at).toLocaleDateString()}</span>
                                </div>
                            </div>
                            <button
                                className="delete-bookmark"
                                onClick={(e) => removeBookmark(item.id, e)}
                                title="Remove"
                            >
                                <Trash2 size={16} />
                            </button>
                        </Link>
                    ))
                ) : (
                    <div className="empty-state">
                        <Bookmark size={48} />
                        <p>No bookmarks found.</p>
                        <p className="sub-text">Use the search bar or explore content to add some!</p>
                    </div>
                )}
            </div>
        </div>
    );
};

export default Bookmarks;
