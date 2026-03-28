import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { BookOpen, Search, ThumbsUp, MessageSquare, Edit2, Plus, Zap } from 'lucide-react';

/**
 * Community Wiki & Knowledge Base
 * User-created documentation, guides, and security knowledge repository
 */

const WikiHub = () => {
  const [tab, setTab] = useState('browse');
  const [articles, setArticles] = useState([]);
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedArticle, setSelectedArticle] = useState(null);
  const [loading, setLoading] = useState(true);
  const [createMode, setCreateMode] = useState(false);

  useEffect(() => {
    fetchArticles();
  }, []);

  const fetchArticles = async () => {
    setLoading(true);
    try {
      const mockArticles = [
        {
          id: 1,
          title: 'Complete Guide to SQL Injection Prevention',
          author: 'SecurityPro',
          category: 'Web Security',
          views: 2341,
          upvotes: 523,
          comments: 45,
          last_updated: '2024-03-20',
          difficulty: 'Beginner',
          excerpt: 'Learn how to prevent SQL injection attacks with parameterized queries, input validation, and prepared statements.',
          content: 'SQL injection is one of the most common web security vulnerabilities...',
          tags: ['SQL', 'Web Security', 'Prevention'],
        },
        {
          id: 2,
          title: 'API Security Best Practices',
          author: 'APIGuru',
          category: 'API Security',
          views: 1842,
          upvotes: 412,
          comments: 38,
          last_updated: '2024-03-18',
          difficulty: 'Intermediate',
          excerpt: 'Master authentication, rate limiting, and input validation for secure APIs.',
          content: 'APIs are critical infrastructure requiring robust security...',
          tags: ['API', 'Authentication', 'Security'],
        },
        {
          id: 3,
          title: 'Buffer Overflow Exploitation Techniques',
          author: 'BinaryHacker',
          category: 'Reverse Engineering',
          views: 1523,
          upvotes: 389,
          comments: 52,
          last_updated: '2024-03-15',
          difficulty: 'Advanced',
          excerpt: 'Deep dive into stack-based buffer overflows, ROP chains, and exploitation techniques.',
          content: 'Buffer overflows remain a critical vulnerability class...',
          tags: ['Reverse Eng', 'Exploitation', 'Memory Safety'],
        },
        {
          id: 4,
          title: 'Cryptography Algorithms Explained',
          author: 'CryptoExpert',
          category: 'Cryptography',
          views: 2156,
          upvotes: 478,
          comments: 64,
          last_updated: '2024-03-19',
          difficulty: 'Intermediate',
          excerpt: 'Comprehensive explanation of AES, RSA, ECC, and hash functions.',
          content: 'Understanding modern cryptography is essential for security professionals...',
          tags: ['Crypto', 'AES', 'RSA', 'Hash Functions'],
        },
        {
          id: 5,
          title: 'Cloud Security: AWS IAM Deep Dive',
          author: 'CloudSecure',
          category: 'Cloud Security',
          views: 1765,
          upvotes: 345,
          comments: 29,
          last_updated: '2024-03-17',
          difficulty: 'Intermediate',
          excerpt: 'Master AWS IAM policies, roles, and permission delegation.',
          content: 'AWS Identity and Access Management is complex but critical...',
          tags: ['AWS', 'IAM', 'Cloud Security'],
        },
        {
          id: 6,
          title: 'OWASP Top 10 2024 - What Changed',
          author: 'SecureCode',
          category: 'Web Security',
          views: 3421,
          upvotes: 612,
          comments: 87,
          last_updated: '2024-03-16',
          difficulty: 'Beginner',
          excerpt: 'Overview of the latest OWASP Top 10 vulnerabilities and mitigation strategies.',
          content: 'The OWASP Top 10 is the most well-known list of web application risks...',
          tags: ['OWASP', 'Web Security', 'Vulnerabilities'],
        },
      ];

      setArticles(mockArticles);
    } catch (error) {
      console.error('Error fetching articles:', error);
    } finally {
      setLoading(false);
    }
  };

  const filteredArticles = articles.filter(article =>
    article.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
    article.tags.some(tag => tag.toLowerCase().includes(searchQuery.toLowerCase()))
  );

  const containerVariants = {
    hidden: { opacity: 0 },
    visible: { opacity: 1, transition: { staggerChildren: 0.1 } }
  };

  const itemVariants = {
    hidden: { opacity: 0, y: 20 },
    visible: { opacity: 1, y: 0 }
  };

  return (
    <div className="space-y-8 pb-12">
      {/* Header */}
      <motion.div
        initial={{ opacity: 0, y: -20 }}
        animate={{ opacity: 1, y: 0 }}
        className="space-y-4"
      >
        <div className="inline-flex items-center gap-2 px-4 py-2 rounded-full bg-emerald-500/10 border border-emerald-500/20">
          <BookOpen className="w-4 h-4 text-emerald-500" />
          <span className="text-sm font-bold text-emerald-500 uppercase tracking-widest">
            Community Knowledge
          </span>
        </div>
        <h1 className="text-5xl font-black text-white italic tracking-tighter uppercase">
          Wiki & Knowledge Base
        </h1>
        <p className="text-gray-400 text-lg max-w-2xl">
          Community-driven documentation, guides, and security knowledge contributed by experts.
        </p>
      </motion.div>

      {/* Tabs */}
      <div className="flex gap-4 border-b border-gray-700">
        {[
          { id: 'browse', label: 'Browse Articles', icon: '📚' },
          { id: 'my-articles', label: 'My Articles', icon: '✍️' },
          { id: 'contribute', label: 'Contribute', icon: '➕' }
        ].map(t => (
          <button
            key={t.id}
            onClick={() => setTab(t.id)}
            className={`px-6 py-3 font-bold uppercase tracking-widest transition-all ${
              tab === t.id
                ? 'text-emerald-500 border-b-2 border-emerald-500'
                : 'text-gray-400 hover:text-gray-300'
            }`}
          >
            {t.icon} {t.label}
          </button>
        ))}
      </div>

      {/* Browse Tab */}
      {tab === 'browse' && (
        <motion.div
          variants={containerVariants}
          initial="hidden"
          animate="visible"
          className="space-y-6"
        >
          {/* Search Bar */}
          <div className="relative">
            <Search className="absolute left-4 top-3.5 w-5 h-5 text-gray-500" />
            <input
              type="text"
              placeholder="Search articles, topics, tags..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full pl-12 pr-4 py-3 rounded-lg bg-gray-900 border border-gray-700 text-white placeholder-gray-500 focus:border-emerald-500 outline-none"
            />
          </div>

          {/* Stats */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <motion.div variants={itemVariants} className="p-4 rounded-xl bg-gradient-to-br from-blue-500/20 to-cyan-500/20 border border-blue-500/30">
              <p className="text-sm text-gray-400 mb-1">Total Articles</p>
              <p className="text-2xl font-black text-blue-400">{articles.length}</p>
            </motion.div>
            <motion.div variants={itemVariants} className="p-4 rounded-xl bg-gradient-to-br from-purple-500/20 to-pink-500/20 border border-purple-500/30">
              <p className="text-sm text-gray-400 mb-1">Active Contributors</p>
              <p className="text-2xl font-black text-purple-400">1,234</p>
            </motion.div>
            <motion.div variants={itemVariants} className="p-4 rounded-xl bg-gradient-to-br from-green-500/20 to-emerald-500/20 border border-green-500/30">
              <p className="text-sm text-gray-400 mb-1">Total Views</p>
              <p className="text-2xl font-black text-green-400">45.2K</p>
            </motion.div>
          </div>

          {/* Articles Grid */}
          <div className="space-y-4">
            <AnimatePresence>
              {filteredArticles.map((article, idx) => (
                <ArticleCard
                  key={article.id}
                  article={article}
                  index={idx}
                  onSelect={() => setSelectedArticle(article)}
                  variants={itemVariants}
                />
              ))}
            </AnimatePresence>
          </div>
        </motion.div>
      )}

      {/* My Articles Tab */}
      {tab === 'my-articles' && (
        <motion.div
          variants={containerVariants}
          initial="hidden"
          animate="visible"
          className="space-y-6"
        >
          <div className="p-8 rounded-xl bg-gradient-to-br from-gray-800/50 to-gray-900/50 border border-gray-700/50 text-center">
            <p className="text-gray-400 mb-4">You haven't published any articles yet.</p>
            <button
              onClick={() => setTab('contribute')}
              className="px-6 py-2 bg-emerald-500 hover:bg-emerald-600 text-white font-bold rounded-lg transition-all"
            >
              Write Your First Article
            </button>
          </div>
        </motion.div>
      )}

      {/* Contribute Tab */}
      {tab === 'contribute' && (
        <motion.div
          variants={containerVariants}
          initial="hidden"
          animate="visible"
          className="space-y-6 max-w-2xl"
        >
          <motion.div variants={itemVariants} className="p-8 rounded-xl bg-gradient-to-br from-emerald-500/20 to-green-500/20 border border-emerald-500/30 space-y-6">
            <h2 className="text-2xl font-bold text-white">Create New Article</h2>

            <div>
              <label className="block text-sm font-bold text-gray-300 mb-2">Article Title</label>
              <input
                type="text"
                placeholder="e.g., Advanced SQL Injection Techniques"
                className="w-full px-4 py-2 rounded-lg bg-gray-900/50 border border-gray-700 text-white placeholder-gray-500 focus:border-emerald-500 outline-none"
              />
            </div>

            <div>
              <label className="block text-sm font-bold text-gray-300 mb-2">Category</label>
              <select className="w-full px-4 py-2 rounded-lg bg-gray-900/50 border border-gray-700 text-white focus:border-emerald-500 outline-none">
                <option>Web Security</option>
                <option>Network Security</option>
                <option>Cryptography</option>
                <option>Reverse Engineering</option>
                <option>Cloud Security</option>
                <option>API Security</option>
              </select>
            </div>

            <div>
              <label className="block text-sm font-bold text-gray-300 mb-2">Difficulty Level</label>
              <div className="flex gap-3">
                {['Beginner', 'Intermediate', 'Advanced'].map(level => (
                  <button
                    key={level}
                    className="px-4 py-2 rounded-lg bg-gray-900/50 border border-gray-700 text-gray-300 hover:border-emerald-500 hover:text-emerald-400 transition-all"
                  >
                    {level}
                  </button>
                ))}
              </div>
            </div>

            <div>
              <label className="block text-sm font-bold text-gray-300 mb-2">Content</label>
              <textarea
                placeholder="Write your article content here... (Markdown supported)"
                rows={10}
                className="w-full px-4 py-2 rounded-lg bg-gray-900/50 border border-gray-700 text-white placeholder-gray-500 focus:border-emerald-500 outline-none font-mono text-sm"
              />
            </div>

            <div>
              <label className="block text-sm font-bold text-gray-300 mb-2">Tags (comma-separated)</label>
              <input
                type="text"
                placeholder="e.g., SQL, Security, Database, OWASP"
                className="w-full px-4 py-2 rounded-lg bg-gray-900/50 border border-gray-700 text-white placeholder-gray-500 focus:border-emerald-500 outline-none"
              />
            </div>

            <div className="flex gap-3 pt-4">
              <button className="flex-1 px-6 py-3 bg-emerald-500 hover:bg-emerald-600 text-white font-bold rounded-lg transition-all">
                Publish Article
              </button>
              <button
                onClick={() => setTab('browse')}
                className="flex-1 px-6 py-3 bg-gray-700 hover:bg-gray-600 text-white font-bold rounded-lg transition-all"
              >
                Cancel
              </button>
            </div>
          </motion.div>

          {/* Guidelines */}
          <motion.div variants={itemVariants} className="p-6 rounded-xl bg-gray-900/50 border border-gray-700/50">
            <h3 className="text-lg font-bold text-white mb-4">📋 Writing Guidelines</h3>
            <ul className="space-y-2 text-gray-300 text-sm">
              <li>✓ Use clear, structured headings (H2, H3)</li>
              <li>✓ Include code examples with syntax highlighting</li>
              <li>✓ Provide links to external resources</li>
              <li>✓ Review for accuracy and completeness</li>
              <li>✓ Add practical examples whenever possible</li>
              <li>✓ Cite sources and attribute ideas</li>
            </ul>
          </motion.div>
        </motion.div>
      )}

      {/* Article Detail Modal */}
      <AnimatePresence>
        {selectedArticle && (
          <ArticleModal article={selectedArticle} onClose={() => setSelectedArticle(null)} />
        )}
      </AnimatePresence>
    </div>
  );
};

const ArticleCard = ({ article, index, onSelect, variants }) => (
  <motion.div
    variants={variants}
    exit={{ opacity: 0 }}
    onClick={onSelect}
    className="group p-6 rounded-xl bg-gradient-to-br from-gray-800/50 to-gray-900/50 border border-gray-700/50 hover:border-emerald-500/50 cursor-pointer transition-all hover:shadow-lg hover:shadow-emerald-500/20"
  >
    {/* Header */}
    <div className="mb-4">
      <div className="flex items-start justify-between mb-2">
        <h3 className="text-lg font-bold text-white flex-1">{article.title}</h3>
        <span className="px-3 py-1 rounded-full text-xs font-bold bg-emerald-500/20 text-emerald-400 ml-4">
          {article.difficulty}
        </span>
      </div>
      <p className="text-sm text-gray-400">by {article.author} • {article.category}</p>
    </div>

    {/* Excerpt */}
    <p className="text-gray-400 text-sm mb-4 line-clamp-2">{article.excerpt}</p>

    {/* Tags */}
    <div className="flex flex-wrap gap-2 mb-4">
      {article.tags.map((tag, idx) => (
        <span key={idx} className="px-2 py-1 rounded text-xs bg-gray-900/50 border border-gray-700/50 text-gray-400">
          {tag}
        </span>
      ))}
    </div>

    {/* Stats */}
    <div className="flex items-center justify-between text-xs text-gray-500 pt-4 border-t border-gray-700/50">
      <div className="flex items-center gap-4">
        <span>👁️ {article.views} views</span>
        <span>👍 {article.upvotes} upvotes</span>
        <span>💬 {article.comments} comments</span>
      </div>
      <span>Updated {article.last_updated}</span>
    </div>
  </motion.div>
);

const ArticleModal = ({ article, onClose }) => (
  <motion.div
    initial={{ opacity: 0 }}
    animate={{ opacity: 1 }}
    exit={{ opacity: 0 }}
    onClick={onClose}
    className="fixed inset-0 bg-black/50 backdrop-blur-sm flex items-center justify-center z-50"
  >
    <motion.div
      initial={{ scale: 0.9, opacity: 0 }}
      animate={{ scale: 1, opacity: 1 }}
      exit={{ scale: 0.9, opacity: 0 }}
      onClick={(e) => e.stopPropagation()}
      className="bg-gray-900 border border-gray-700 rounded-2xl p-8 max-w-2xl w-full max-h-[80vh] overflow-y-auto space-y-6"
    >
      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-3xl font-bold text-white mb-2">{article.title}</h1>
          <p className="text-gray-400">by {article.author} in {article.category}</p>
          <p className="text-sm text-gray-500 mt-2">Updated {article.last_updated}</p>
        </div>
        <button onClick={onClose} className="text-gray-400 hover:text-white text-2xl">×</button>
      </div>

      {/* Content */}
      <div className="prose prose-invert max-w-none">
        <p className="text-gray-300 leading-relaxed">{article.content}</p>
      </div>

      {/* Tags */}
      <div className="flex flex-wrap gap-2 py-4 border-t border-gray-700">
        {article.tags.map((tag, idx) => (
          <span key={idx} className="px-3 py-1 rounded-full text-sm bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">
            {tag}
          </span>
        ))}
      </div>

      {/* Actions */}
      <div className="grid grid-cols-3 gap-4 py-4 border-t border-gray-700">
        <button className="px-4 py-2 flex items-center justify-center gap-2 bg-gray-800 hover:bg-gray-700 text-white font-bold rounded-lg transition-all">
          <ThumbsUp className="w-4 h-4" />
          Upvote ({article.upvotes})
        </button>
        <button className="px-4 py-2 flex items-center justify-center gap-2 bg-gray-800 hover:bg-gray-700 text-white font-bold rounded-lg transition-all">
          <MessageSquare className="w-4 h-4" />
          Comments ({article.comments})
        </button>
        <button className="px-4 py-2 flex items-center justify-center gap-2 bg-emerald-500/20 hover:bg-emerald-500/30 text-emerald-400 font-bold rounded-lg transition-all">
          <Edit2 className="w-4 h-4" />
          Edit
        </button>
      </div>
    </motion.div>
  </motion.div>
);

export default WikiHub;
