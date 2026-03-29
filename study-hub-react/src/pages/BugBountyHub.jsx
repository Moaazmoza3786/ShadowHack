import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Bug, DollarSign, Target, Zap, Award, TrendingUp } from 'lucide-react';

/**
 * Bug Bounty Integration
 * Find, submit, and track bug bounties from HackerOne, Bugcrowd, Intigriti
 */

const BugBountyHub = () => {
  const [tab, setTab] = useState('opportunities');
  const [programs, setPrograms] = useState([]);
  const [submissions, setSubmissions] = useState([]);
  const [earnings, setEarnings] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchBugBountyData();
  }, []);

  const fetchBugBountyData = async () => {
    setLoading(true);
    try {
      // Mock bug bounty programs
      const mockPrograms = [
        {
          id: 1,
          platform: 'HackerOne',
          name: 'Acme Corporation',
          scope: 'Web Application',
          min_bounty: 100,
          max_bounty: 10000,
          severity_levels: ['Critical', 'High', 'Medium', 'Low'],
          active_researchers: 342,
          total_bounties: '2.1M',
          rating: 4.8,
          response_time: '2 hours',
          logo: '🏢',
        },
        {
          id: 2,
          platform: 'Bugcrowd',
          name: 'TechStart Inc',
          scope: 'Mobile App, API, Cloud',
          min_bounty: 50,
          max_bounty: 5000,
          severity_levels: ['Critical', 'High', 'Medium'],
          active_researchers: 215,
          total_bounties: '850K',
          rating: 4.6,
          response_time: '4 hours',
          logo: '📱',
        },
        {
          id: 3,
          platform: 'Intigriti',
          name: 'SecureBank',
          scope: 'API, Web, Infrastructure',
          min_bounty: 200,
          max_bounty: 15000,
          severity_levels: ['Critical', 'High', 'Medium', 'Low', 'Info'],
          active_researchers: 489,
          total_bounties: '3.5M',
          rating: 4.9,
          response_time: '1 hour',
          logo: '🏦',
        },
        {
          id: 4,
          platform: 'HackerOne',
          name: 'CloudSync Services',
          scope: 'Cloud Infrastructure',
          min_bounty: 150,
          max_bounty: 8000,
          severity_levels: ['Critical', 'High', 'Medium'],
          active_researchers: 278,
          total_bounties: '1.2M',
          rating: 4.7,
          response_time: '3 hours',
          logo: '☁️',
        },
      ];

      setPrograms(mockPrograms);

      // Mock submissions
      const mockSubmissions = [
        {
          id: 1,
          program: 'Acme Corporation',
          title: 'SQL Injection in User Search',
          severity: 'High',
          status: 'resolved',
          bounty: 2500,
          submitted_at: '2024-03-15',
          resolved_at: '2024-03-18',
          platform: 'HackerOne',
        },
        {
          id: 2,
          program: 'TechStart Inc',
          title: 'XSS in Profile Comments',
          severity: 'Medium',
          status: 'triaged',
          bounty: null,
          submitted_at: '2024-03-20',
          resolved_at: null,
          platform: 'Bugcrowd',
        },
        {
          id: 3,
          program: 'SecureBank',
          title: 'CORS Misconfiguration',
          severity: 'High',
          status: 'resolved',
          bounty: 5000,
          submitted_at: '2024-02-28',
          resolved_at: '2024-03-05',
          platform: 'Intigriti',
        },
      ];

      setSubmissions(mockSubmissions);

      // Mock earnings
      setEarnings({
        total: 12500,
        this_month: 5000,
        this_year: 12500,
        pending: 2000,
        verified_bugs: 3,
        platforms: [
          { name: 'HackerOne', total: 7500 },
          { name: 'Bugcrowd', total: 3000 },
          { name: 'Intigriti', total: 2000 },
        ],
      });
    } catch (error) {
      console.error('Error fetching bug bounty data:', error);
    } finally {
      setLoading(false);
    }
  };

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
        <div className="inline-flex items-center gap-2 px-4 py-2 rounded-full bg-red-500/10 border border-red-500/20">
          <Bug className="w-4 h-4 text-red-500" />
          <span className="text-sm font-bold text-red-500 uppercase tracking-widest">
            Vulnerability Rewards
          </span>
        </div>
        <h1 className="text-5xl font-black text-white italic tracking-tighter uppercase">
          Bug Bounty Hub
        </h1>
        <p className="text-gray-400 text-lg max-w-2xl">
          Find vulnerabilities, submit reports, and earn rewards from top companies and platforms.
        </p>
      </motion.div>

      {/* Earnings Overview */}
      {earnings && (
        <motion.div
          variants={containerVariants}
          initial="hidden"
          animate="visible"
          className="grid grid-cols-1 md:grid-cols-4 gap-4"
        >
          <motion.div variants={itemVariants} className="p-6 rounded-xl bg-gradient-to-br from-green-500/20 to-emerald-500/20 border border-green-500/30">
            <p className="text-sm text-gray-400 mb-2">Total Earnings</p>
            <p className="text-3xl font-black text-green-400">${earnings.total.toLocaleString()}</p>
          </motion.div>
          <motion.div variants={itemVariants} className="p-6 rounded-xl bg-gradient-to-br from-blue-500/20 to-cyan-500/20 border border-blue-500/30">
            <p className="text-sm text-gray-400 mb-2">This Month</p>
            <p className="text-3xl font-black text-blue-400">${earnings.this_month}</p>
          </motion.div>
          <motion.div variants={itemVariants} className="p-6 rounded-xl bg-gradient-to-br from-purple-500/20 to-pink-500/20 border border-purple-500/30">
            <p className="text-sm text-gray-400 mb-2">Pending Approval</p>
            <p className="text-3xl font-black text-purple-400">${earnings.pending}</p>
          </motion.div>
          <motion.div variants={itemVariants} className="p-6 rounded-xl bg-gradient-to-br from-yellow-500/20 to-orange-500/20 border border-yellow-500/30">
            <p className="text-sm text-gray-400 mb-2">Verified Reports</p>
            <p className="text-3xl font-black text-yellow-400">{earnings.verified_bugs}</p>
          </motion.div>
        </motion.div>
      )}

      {/* Tabs */}
      <div className="flex gap-4 border-b border-gray-700">
        {[
          { id: 'opportunities', label: 'Bug Bounty Programs', icon: '🎯' },
          { id: 'submissions', label: 'My Submissions', icon: '📝' },
          { id: 'earnings', label: 'Earnings', icon: '💰' }
        ].map(t => (
          <button
            key={t.id}
            onClick={() => setTab(t.id)}
            className={`px-6 py-3 font-bold uppercase tracking-widest transition-all ${
              tab === t.id
                ? 'text-red-500 border-b-2 border-red-500'
                : 'text-gray-400 hover:text-gray-300'
            }`}
          >
            {t.icon} {t.label}
          </button>
        ))}
      </div>

      {/* Opportunities Tab */}
      {tab === 'opportunities' && (
        <motion.div
          variants={containerVariants}
          initial="hidden"
          animate="visible"
          className="space-y-4"
        >
          <div className="p-4 rounded-lg bg-blue-500/10 border border-blue-500/30">
            <p className="text-sm text-blue-300">
              💡 Tip: Target programs with recent activity and quick response times for faster payouts.
            </p>
          </div>

          {programs.map((program, idx) => (
            <ProgramCard key={program.id} program={program} variants={itemVariants} index={idx} />
          ))}
        </motion.div>
      )}

      {/* Submissions Tab */}
      {tab === 'submissions' && (
        <motion.div
          variants={containerVariants}
          initial="hidden"
          animate="visible"
          className="space-y-4"
        >
          {submissions.map((submission, idx) => (
            <motion.div
              key={submission.id}
              variants={itemVariants}
              className="p-6 rounded-xl bg-gradient-to-br from-gray-800/50 to-gray-900/50 border border-gray-700/50"
            >
              <div className="flex items-start justify-between mb-4">
                <div className="flex-1">
                  <h3 className="text-lg font-bold text-white">{submission.title}</h3>
                  <p className="text-sm text-gray-400">{submission.program} • {submission.platform}</p>
                </div>
                <div className="flex items-center gap-2">
                  <span className={`px-3 py-1 rounded-full text-xs font-bold ${
                    submission.severity === 'Critical' ? 'bg-red-500/20 text-red-400' :
                    submission.severity === 'High' ? 'bg-orange-500/20 text-orange-400' :
                    'bg-yellow-500/20 text-yellow-400'
                  }`}>
                    {submission.severity}
                  </span>
                  <span className={`px-3 py-1 rounded-full text-xs font-bold ${
                    submission.status === 'resolved' ? 'bg-green-500/20 text-green-400' :
                    submission.status === 'triaged' ? 'bg-blue-500/20 text-blue-400' :
                    'bg-gray-500/20 text-gray-400'
                  }`}>
                    {submission.status}
                  </span>
                </div>
              </div>

              <div className="grid grid-cols-3 gap-4">
                <div>
                  <p className="text-xs text-gray-400 mb-1">Submitted</p>
                  <p className="text-sm font-bold text-white">{submission.submitted_at}</p>
                </div>
                <div>
                  <p className="text-xs text-gray-400 mb-1">Status</p>
                  <p className="text-sm font-bold text-white capitalize">{submission.status}</p>
                </div>
                <div>
                  <p className="text-xs text-gray-400 mb-1">Bounty</p>
                  <p className="text-sm font-bold text-green-400">
                    {submission.bounty ? `$${submission.bounty}` : 'Pending'}
                  </p>
                </div>
              </div>
            </motion.div>
          ))}
        </motion.div>
      )}

      {/* Earnings Tab */}
      {tab === 'earnings' && earnings && (
        <motion.div
          variants={containerVariants}
          initial="hidden"
          animate="visible"
          className="space-y-6"
        >
          {/* Platform Breakdown */}
          <motion.div variants={itemVariants} className="p-6 rounded-xl bg-gradient-to-br from-gray-800/50 to-gray-900/50 border border-gray-700/50">
            <h3 className="text-lg font-bold text-white mb-4">Earnings by Platform</h3>
            <div className="space-y-4">
              {earnings.platforms.map((platform, idx) => (
                <div key={idx}>
                  <div className="flex items-center justify-between mb-2">
                    <p className="font-bold text-white">{platform.name}</p>
                    <p className="text-green-400 font-bold">${platform.total.toLocaleString()}</p>
                  </div>
                  <div className="h-2 bg-gray-900/50 rounded-full overflow-hidden">
                    <motion.div
                      initial={{ width: 0 }}
                      animate={{ width: `${(platform.total / earnings.total) * 100}%` }}
                      transition={{ delay: 0.1, duration: 1 }}
                      className="h-full bg-gradient-to-r from-green-500 to-emerald-500"
                    />
                  </div>
                </div>
              ))}
            </div>
          </motion.div>

          {/* Tips for Maximizing Earnings */}
          <motion.div variants={itemVariants} className="p-6 rounded-xl bg-gradient-to-br from-purple-500/20 to-pink-500/20 border border-purple-500/30">
            <h3 className="text-lg font-bold text-white mb-4">💰 Tips to Maximize Earnings</h3>
            <ul className="space-y-2 text-gray-300">
              <li>• Focus on Critical and High severity vulnerabilities</li>
              <li>• Target programs with $5K+ maximum bounties</li>
              <li>• Prioritize programs with &lt; 2 hour response time</li>
              <li>• Build reputation: consistent quality reports = higher payouts</li>
              <li>• Specialize in areas with less competition (API, Cloud, IoT)</li>
              <li>• Document findings thoroughly for faster approvals</li>
            </ul>
          </motion.div>
        </motion.div>
      )}
    </div>
  );
};

const ProgramCard = ({ program, variants, index }) => {
  const [hovered, setHovered] = React.useState(false);

  return (
    <motion.div
      variants={variants}
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
      className="group p-6 rounded-xl bg-gradient-to-br from-gray-800/50 to-gray-900/50 border border-gray-700/50 hover:border-red-500/50 transition-all cursor-pointer"
    >
      {/* Header */}
      <div className="flex items-start justify-between mb-4">
        <div className="flex items-center gap-3">
          <span className="text-3xl">{program.logo}</span>
          <div>
            <p className="text-xs text-gray-400 font-bold">{program.platform}</p>
            <h3 className="text-lg font-bold text-white">{program.name}</h3>
          </div>
        </div>
        <div className="text-right">
          <div className="flex items-center gap-1 mb-1">
            <span className="text-yellow-500">⭐</span>
            <span className="font-bold text-yellow-400">{program.rating}</span>
          </div>
          <p className="text-xs text-gray-400">{program.active_researchers} researchers</p>
        </div>
      </div>

      {/* Scope & Severity */}
      <div className="mb-4 pb-4 border-t border-gray-700/50 pt-4">
        <p className="text-xs text-gray-400 mb-2">In Scope</p>
        <p className="text-sm text-gray-300 mb-3">{program.scope}</p>
        <div className="flex flex-wrap gap-2">
          {program.severity_levels.map((level, idx) => (
            <span key={idx} className="px-2 py-1 rounded text-xs bg-gray-900/50 border border-gray-700/50 text-gray-300">
              {level}
            </span>
          ))}
        </div>
      </div>

      {/* Bounty & Response Time */}
      <div className="grid grid-cols-3 gap-3 mb-4">
        <div className="p-3 rounded-lg bg-gray-900/50 border border-gray-700/50">
          <p className="text-xs text-gray-400">Bounty Range</p>
          <p className="text-sm font-bold text-green-400">${program.min_bounty}-${program.max_bounty.toLocaleString()}</p>
        </div>
        <div className="p-3 rounded-lg bg-gray-900/50 border border-gray-700/50">
          <p className="text-xs text-gray-400">Total Paid</p>
          <p className="text-sm font-bold text-blue-400">${program.total_bounties}</p>
        </div>
        <div className="p-3 rounded-lg bg-gray-900/50 border border-gray-700/50">
          <p className="text-xs text-gray-400">Response</p>
          <p className="text-sm font-bold text-purple-400">{program.response_time}</p>
        </div>
      </div>

      {/* Action */}
      <button className="w-full px-4 py-2 bg-gradient-to-r from-red-500 to-pink-500 hover:from-red-600 hover:to-pink-600 text-white font-bold rounded-lg transition-all">
        View Program →
      </button>
    </motion.div>
  );
};

export default BugBountyHub;
