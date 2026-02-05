
import React, { useState, useEffect, useRef } from 'react';
import { Search, User, Users, Code, PenTool, Hash, X, Star, Link2 } from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import './GlobalSearch.css';

const GlobalSearch = ({ userId = 1 }) => {
    const [isOpen, setIsOpen] = useState(false);
    const [query, setQuery] = useState('');
    const [results, setResults] = useState([]);
    const [loading, setLoading] = useState(false);
    const searchRef = useRef(null);
    const navigate = useNavigate();

    // Close on click outside
    useEffect(() => {
        const handleClickOutside = (e) => {
            if (searchRef.current && !searchRef.current.contains(e.target)) {
                setIsOpen(false);
            }
        };
        document.addEventListener('mousedown', handleClickOutside);
        return () => document.removeEventListener('mousedown', handleClickOutside);
    }, []);

    // Keyboard shortcut (Ctrl+K or Cmd+K)
    useEffect(() => {
        const handleKeyDown = (e) => {
            if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
                e.preventDefault();
                setIsOpen(true);
                // Focus input after opening
                setTimeout(() => document.querySelector('.search-input')?.focus(), 100);
            }
            if (e.key === 'Escape') setIsOpen(false);
        };
        document.addEventListener('keydown', handleKeyDown);
        return () => document.removeEventListener('keydown', handleKeyDown);
    }, []);

    // Debounced search
    useEffect(() => {
        const delaySearch = setTimeout(() => {
            if (query.length >= 2) {
                performSearch();
            } else {
                setResults([]);
            }
        }, 300);
        return () => clearTimeout(delaySearch);
    }, [query]);

    const performSearch = async () => {
        setLoading(true);
        try {
            const res = await fetch(`http://localhost:5000/api/search/global?q=${encodeURIComponent(query)}`);
            const data = await res.json();
            if (data.success) {
                setResults(data.results);
            }
        } catch (err) {
            console.error(err);
        } finally {
            setLoading(false);
        }
    };

    const handleNavigate = (link) => {
        navigate(link);
        setIsOpen(false);
        setQuery('');
    };

    const getIcon = (type) => {
        switch (type) {
            case 'user': return <User size={18} />;
            case 'team': return <Users size={18} />;
            case 'lab': return <Code size={18} />;
            case 'tool': return <PenTool size={18} />;
            case 'feature': return <Link2 size={18} />;
            default: return <Hash size={18} />;
        }
    };

    if (!isOpen) {
        return (
            <button className="search-trigger" onClick={() => setIsOpen(true)}>
                <Search size={18} />
                <span className="search-placeholder">Search... (Ctrl+K)</span>
            </button>
        );
    }

    return (
        <div className="search-overlay">
            <div className="search-container" ref={searchRef}>
                <div className="search-header">
                    <Search size={20} className="search-icon" />
                    <input
                        type="text"
                        className="search-input"
                        value={query}
                        onChange={(e) => setQuery(e.target.value)}
                        placeholder="Search users, teams, labs..."
                        autoFocus
                    />
                    <button className="close-btn" onClick={() => setIsOpen(false)}>
                        <X size={20} />
                    </button>
                </div>

                <div className="search-results">
                    {loading && <div className="search-loading">Searching...</div>}

                    {!loading && results.length > 0 && (
                        <div className="results-list">
                            {results.map((result, index) => (
                                <div
                                    key={index}
                                    className="result-item"
                                    onClick={() => handleNavigate(result.link)}
                                >
                                    <div className={`result-icon type-${result.type}`}>
                                        {getIcon(result.type)}
                                    </div>
                                    <div className="result-content">
                                        <div className="result-title">{result.title}</div>
                                        <div className="result-subtitle">{result.subtitle}</div>
                                    </div>
                                    <span className="result-type">{result.type}</span>
                                </div>
                            ))}
                        </div>
                    )}

                    {!loading && query.length >= 2 && results.length === 0 && (
                        <div className="no-results">
                            <p>No results found for "{query}"</p>
                        </div>
                    )}

                    {!loading && query.length < 2 && (
                        <div className="search-suggestions">
                            <h3>Quick Links</h3>
                            <div className="suggestion-tags">
                                <button onClick={() => handleNavigate('/cyber-ops')}>CyberOps</button>
                                <button onClick={() => handleNavigate('/teams')}>Teams</button>
                                <button onClick={() => handleNavigate('/analytics')}>Analytics</button>
                                <button onClick={() => handleNavigate('/assessments')}>Assessments</button>
                            </div>
                        </div>
                    )}
                </div>

                <div className="search-footer">
                    <span>Search for <kbd>Users</kbd>, <kbd>Teams</kbd>, <kbd>Labs</kbd>, <kbd>Tools</kbd></span>
                </div>
            </div>
        </div>
    );
};

export default GlobalSearch;
