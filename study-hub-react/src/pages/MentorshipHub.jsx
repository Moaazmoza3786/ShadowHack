import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { MessageCircle, Star, Users, TrendingUp, Calendar, MapPin, Award } from 'lucide-react';

/**
 * Mentorship Matching System
 * Connect learners with experienced mentors based on skills and goals
 */

const MentorshipHub = () => {
  const [tab, setTab] = useState('find-mentor'); // find-mentor, my-mentors, become-mentor
  const [mentors, setMentors] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selectedMentor, setSelectedMentor] = useState(null);
  const [filterSkill, setFilterSkill] = useState('all');

  useEffect(() => {
    if (tab === 'find-mentor') fetchMentors();
  }, [tab, filterSkill]);

  const fetchMentors = async () => {
    setLoading(true);
    try {
      // Mock mentors data
      const mockMentors = [
        {
          id: 1,
          name: 'Sarah Chen',
          expertise: ['Web Security', 'API Security', 'OWASP'],
          experience_years: 8,
          students_mentored: 23,
          rating: 4.9,
          hourly_rate: 50,
          available_slots: 3,
          bio: 'Passionate about web security. Led red team at Fortune 500.',
          languages: ['English', 'Mandarin'],
          avatar_url: 'https://api.dicebear.com/7.x/avataaars/svg?seed=sarah',
        },
        {
          id: 2,
          name: 'Marcus Johnson',
          expertise: ['Reverse Engineering', 'Malware Analysis', 'Binary Exploitation'],
          experience_years: 12,
          students_mentored: 45,
          rating: 4.95,
          hourly_rate: 75,
          available_slots: 1,
          bio: 'Expert in binary exploitation and reverse engineering. Author of 2 security books.',
          languages: ['English', 'Spanish'],
          avatar_url: 'https://api.dicebear.com/7.x/avataaars/svg?seed=marcus',
        },
        {
          id: 3,
          name: 'Priya Patel',
          expertise: ['Network Security', 'Cloud Security', 'DevSecOps'],
          experience_years: 6,
          students_mentored: 18,
          rating: 4.8,
          hourly_rate: 45,
          available_slots: 4,
          bio: 'Cloud security specialist. Certified AWS & Azure security architect.',
          languages: ['English', 'Hindi', 'Gujarati'],
          avatar_url: 'https://api.dicebear.com/7.x/avataaars/svg?seed=priya',
        },
        {
          id: 4,
          name: 'Alex Rodriguez',
          expertise: ['Cryptography', 'Blockchain Security', 'Smart Contracts'],
          experience_years: 5,
          students_mentored: 12,
          rating: 4.85,
          hourly_rate: 55,
          available_slots: 2,
          bio: 'Blockchain security researcher. Published 8 papers on crypto protocols.',
          languages: ['English', 'Portuguese'],
          avatar_url: 'https://api.dicebear.com/7.x/avataaars/svg?seed=alex',
        },
        {
          id: 5,
          name: 'Emma Thompson',
          expertise: ['Incident Response', 'Threat Intelligence', 'SOC Operations'],
          experience_years: 10,
          students_mentored: 34,
          rating: 4.92,
          hourly_rate: 60,
          available_slots: 2,
          bio: 'Led incident response for multiple Fortune 100 companies. GIAC GCIH certified.',
          languages: ['English', 'French'],
          avatar_url: 'https://api.dicebear.com/7.x/avataaars/svg?seed=emma',
        },
        {
          id: 6,
          name: 'David Kim',
          expertise: ['Penetration Testing', 'Red Teaming', 'Security Auditing'],
          experience_years: 9,
          students_mentored: 28,
          rating: 4.88,
          hourly_rate: 65,
          available_slots: 3,
          bio: 'OSCP, CEH, and Offensive Security certified. Lead pentester with 9 years experience.',
          languages: ['English', 'Korean'],
          avatar_url: 'https://api.dicebear.com/7.x/avataaars/svg?seed=david',
        },
      ];

      setMentors(mockMentors);
    } catch (error) {
      console.error('Error fetching mentors:', error);
    } finally {
      setLoading(false);
    }
  };

  const filteredMentors = filterSkill === 'all' 
    ? mentors 
    : mentors.filter(m => m.expertise.includes(filterSkill));

  const containerVariants = {
    hidden: { opacity: 0 },
    visible: {
      opacity: 1,
      transition: { staggerChildren: 0.1 }
    }
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
        <div className="inline-flex items-center gap-2 px-4 py-2 rounded-full bg-blue-500/10 border border-blue-500/20">
          <Users className="w-4 h-4 text-blue-500" />
          <span className="text-sm font-bold text-blue-500 uppercase tracking-widest">
            Expert Guidance
          </span>
        </div>
        <h1 className="text-5xl font-black text-white italic tracking-tighter uppercase">
          Mentorship Hub
        </h1>
        <p className="text-gray-400 text-lg max-w-2xl">
          Connect with industry experts. Get personalized guidance for your security journey.
        </p>
      </motion.div>

      {/* Tabs */}
      <div className="flex gap-4 border-b border-gray-700">
        {[
          { id: 'find-mentor', label: 'Find a Mentor', icon: '🔍' },
          { id: 'my-mentors', label: 'My Mentors', icon: '👥' },
          { id: 'become-mentor', label: 'Become a Mentor', icon: '🏆' }
        ].map(t => (
          <button
            key={t.id}
            onClick={() => setTab(t.id)}
            className={`px-6 py-3 font-bold uppercase tracking-widest transition-all ${
              tab === t.id
                ? 'text-blue-500 border-b-2 border-blue-500'
                : 'text-gray-400 hover:text-gray-300'
            }`}
          >
            {t.icon} {t.label}
          </button>
        ))}
      </div>

      {/* Find Mentor Tab */}
      {tab === 'find-mentor' && (
        <motion.div
          variants={containerVariants}
          initial="hidden"
          animate="visible"
          className="space-y-6"
        >
          {/* Filters */}
          <div className="flex gap-3 flex-wrap">
            {['all', 'Web Security', 'Network Security', 'Cryptography', 'Reverse Engineering', 'Cloud Security'].map(skill => (
              <button
                key={skill}
                onClick={() => setFilterSkill(skill)}
                className={`px-4 py-2 rounded-full font-bold transition-all ${
                  filterSkill === skill
                    ? 'bg-blue-500 text-white'
                    : 'bg-gray-800 text-gray-300 hover:bg-gray-700'
                }`}
              >
                {skill === 'all' ? 'All Mentors' : skill}
              </button>
            ))}
          </div>

          {/* Mentors Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            <AnimatePresence>
              {filteredMentors.map((mentor, idx) => (
                <MentorCard
                  key={mentor.id}
                  mentor={mentor}
                  index={idx}
                  onSelect={() => setSelectedMentor(mentor)}
                  variants={itemVariants}
                />
              ))}
            </AnimatePresence>
          </div>
        </motion.div>
      )}

      {/* My Mentors Tab */}
      {tab === 'my-mentors' && (
        <motion.div
          variants={containerVariants}
          initial="hidden"
          animate="visible"
          className="space-y-6"
        >
          <MyMentorsContent mentors={mentors.slice(0, 2)} />
        </motion.div>
      )}

      {/* Become Mentor Tab */}
      {tab === 'become-mentor' && (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          className="space-y-6"
        >
          <BecomeMentorContent />
        </motion.div>
      )}

      {/* Mentor Detail Modal */}
      <AnimatePresence>
        {selectedMentor && (
          <MentorDetailModal
            mentor={selectedMentor}
            onClose={() => setSelectedMentor(null)}
          />
        )}
      </AnimatePresence>
    </div>
  );
};

const MentorCard = ({ mentor, index, onSelect, variants }) => (
  <motion.div
    variants={variants}
    exit={{ opacity: 0 }}
    onClick={onSelect}
    className="group p-6 rounded-xl bg-gradient-to-br from-gray-800/50 to-gray-900/50 border border-gray-700/50 hover:border-blue-500/50 cursor-pointer transition-all hover:shadow-lg hover:shadow-blue-500/20"
  >
    {/* Avatar */}
    <div className="mb-4 flex items-center gap-4">
      <div className="w-16 h-16 rounded-full bg-gradient-to-br from-blue-500 to-purple-500 flex items-center justify-center text-2xl">
        {mentor.name.charAt(0)}
      </div>
      <div className="flex-1">
        <h3 className="text-lg font-bold text-white">{mentor.name}</h3>
        <div className="flex items-center gap-2 mt-1">
          <Star className="w-4 h-4 text-yellow-500 fill-yellow-500" />
          <span className="text-sm font-bold text-yellow-400">{mentor.rating}</span>
          <span className="text-xs text-gray-500">({mentor.students_mentored} students)</span>
        </div>
      </div>
    </div>

    {/* Expertise */}
    <div className="mb-4">
      <p className="text-xs text-gray-400 mb-2">Expertise</p>
      <div className="flex flex-wrap gap-2">
        {mentor.expertise.slice(0, 2).map((skill, idx) => (
          <span key={idx} className="px-2 py-1 rounded text-xs bg-blue-500/20 text-blue-300 border border-blue-500/30">
            {skill}
          </span>
        ))}
        {mentor.expertise.length > 2 && (
          <span className="px-2 py-1 rounded text-xs bg-gray-700/50 text-gray-400">
            +{mentor.expertise.length - 2}
          </span>
        )}
      </div>
    </div>

    {/* Stats */}
    <div className="grid grid-cols-2 gap-3 mb-4 pb-4 border-t border-gray-700/50 pt-4">
      <div>
        <p className="text-xs text-gray-400">Experience</p>
        <p className="text-sm font-bold text-white">{mentor.experience_years} years</p>
      </div>
      <div>
        <p className="text-xs text-gray-400">Rate</p>
        <p className="text-sm font-bold text-blue-400">${mentor.hourly_rate}/hr</p>
      </div>
    </div>

    {/* Availability */}
    <div className="flex items-center justify-between text-xs mb-4">
      <span className="text-gray-400">{mentor.available_slots} slots available</span>
      <span className={`px-2 py-1 rounded ${mentor.available_slots > 0 ? 'bg-green-500/20 text-green-400' : 'bg-red-500/20 text-red-400'}`}>
        {mentor.available_slots > 0 ? '✓ Available' : '✗ Booked'}
      </span>
    </div>

    {/* Action */}
    <button className="w-full px-4 py-2 bg-blue-500 hover:bg-blue-600 text-white font-bold rounded-lg transition-all">
      View Profile
    </button>
  </motion.div>
);

const MentorDetailModal = ({ mentor, onClose }) => (
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
        <div className="flex items-center gap-4">
          <div className="w-20 h-20 rounded-full bg-gradient-to-br from-blue-500 to-purple-500 flex items-center justify-center text-3xl">
            {mentor.name.charAt(0)}
          </div>
          <div>
            <h2 className="text-2xl font-bold text-white">{mentor.name}</h2>
            <div className="flex items-center gap-3 mt-2">
              <div className="flex items-center gap-1">
                <Star className="w-4 h-4 text-yellow-500 fill-yellow-500" />
                <span className="font-bold text-yellow-400">{mentor.rating}</span>
              </div>
              <span className="text-gray-400">•</span>
              <span className="text-gray-400">{mentor.students_mentored} students mentored</span>
            </div>
          </div>
        </div>
        <button onClick={onClose} className="text-gray-400 hover:text-white text-2xl">×</button>
      </div>

      {/* Bio */}
      <div>
        <h3 className="text-sm font-bold text-gray-400 mb-2">About</h3>
        <p className="text-gray-300">{mentor.bio}</p>
      </div>

      {/* Expertise */}
      <div>
        <h3 className="text-sm font-bold text-gray-400 mb-3">Expertise</h3>
        <div className="flex flex-wrap gap-2">
          {mentor.expertise.map((skill, idx) => (
            <span key={idx} className="px-3 py-1 rounded-full text-sm bg-blue-500/20 text-blue-300 border border-blue-500/30">
              {skill}
            </span>
          ))}
        </div>
      </div>

      {/* Details */}
      <div className="grid grid-cols-3 gap-4">
        <div className="p-4 rounded-lg bg-gray-800/50 border border-gray-700/50">
          <p className="text-xs text-gray-400 mb-1">Experience</p>
          <p className="text-lg font-bold text-white">{mentor.experience_years} years</p>
        </div>
        <div className="p-4 rounded-lg bg-gray-800/50 border border-gray-700/50">
          <p className="text-xs text-gray-400 mb-1">Hourly Rate</p>
          <p className="text-lg font-bold text-blue-400">${mentor.hourly_rate}</p>
        </div>
        <div className="p-4 rounded-lg bg-gray-800/50 border border-gray-700/50">
          <p className="text-xs text-gray-400 mb-1">Available Slots</p>
          <p className="text-lg font-bold text-green-400">{mentor.available_slots}</p>
        </div>
      </div>

      {/* Languages */}
      <div>
        <h3 className="text-sm font-bold text-gray-400 mb-2">Languages</h3>
        <p className="text-gray-300">{mentor.languages.join(', ')}</p>
      </div>

      {/* Action Buttons */}
      <div className="flex gap-3 pt-6 border-t border-gray-700">
        <button className="flex-1 px-4 py-3 bg-blue-500 hover:bg-blue-600 text-white font-bold rounded-lg transition-all flex items-center justify-center gap-2">
          <MessageCircle className="w-5 h-5" />
          Start Conversation
        </button>
        <button className="flex-1 px-4 py-3 bg-gray-700 hover:bg-gray-600 text-white font-bold rounded-lg transition-all">
          Schedule Session
        </button>
      </div>
    </motion.div>
  </motion.div>
);

const MyMentorsContent = ({ mentors }) => (
  <div className="space-y-4">
    {mentors.length === 0 ? (
      <div className="p-8 rounded-lg bg-gray-900/50 border border-gray-700/50 text-center">
        <p className="text-gray-400 mb-4">You haven't connected with a mentor yet.</p>
        <button className="px-6 py-2 bg-blue-500 text-white font-bold rounded-lg hover:bg-blue-600 transition-all">
          Find a Mentor
        </button>
      </div>
    ) : (
      mentors.map(mentor => (
        <div key={mentor.id} className="p-6 rounded-xl bg-gradient-to-r from-blue-500/10 to-purple-500/10 border border-blue-500/30 flex items-center justify-between">
          <div>
            <h3 className="text-lg font-bold text-white">{mentor.name}</h3>
            <p className="text-sm text-gray-400 mt-1">{mentor.expertise[0]}</p>
            <p className="text-xs text-gray-500 mt-2">Next session: Tomorrow at 2:00 PM</p>
          </div>
          <button className="px-4 py-2 bg-blue-500 hover:bg-blue-600 text-white font-bold rounded-lg transition-all">
            Message
          </button>
        </div>
      ))
    )}
  </div>
);

const BecomeMentorContent = () => (
  <motion.div
    initial={{ opacity: 0 }}
    animate={{ opacity: 1 }}
    className="space-y-6"
  >
    <div className="p-8 rounded-xl bg-gradient-to-r from-blue-500/20 to-purple-500/20 border border-blue-500/30">
      <h2 className="text-2xl font-bold text-white mb-4">Share Your Expertise</h2>
      <p className="text-gray-300 mb-6">
        Become a mentor and help the next generation of security professionals. Earn money while making an impact.
      </p>

      <div className="space-y-4 mb-6">
        <div className="flex items-center gap-3">
          <Award className="w-5 h-5 text-blue-500" />
          <div>
            <p className="font-bold text-white">Competitive Compensation</p>
            <p className="text-sm text-gray-400">Earn $30-100+ per hour depending on expertise</p>
          </div>
        </div>
        <div className="flex items-center gap-3">
          <Users className="w-5 h-5 text-blue-500" />
          <div>
            <p className="font-bold text-white">Impact Lives</p>
            <p className="text-sm text-gray-400">Guide learners on their security journey</p>
          </div>
        </div>
        <div className="flex items-center gap-3">
          <TrendingUp className="w-5 h-5 text-blue-500" />
          <div>
            <p className="font-bold text-white">Build Your Brand</p>
            <p className="text-sm text-gray-400">Showcase expertise and grow your reputation</p>
          </div>
        </div>
      </div>

      <button className="w-full px-6 py-3 bg-gradient-to-r from-blue-500 to-purple-500 hover:from-blue-600 hover:to-purple-600 text-white font-bold rounded-lg transition-all">
        Apply to Become a Mentor
      </button>
    </div>

    <div className="p-6 rounded-xl bg-gray-800/50 border border-gray-700/50">
      <h3 className="text-lg font-bold text-white mb-4">Requirements</h3>
      <ul className="space-y-2 text-gray-300">
        <li className="flex items-center gap-2">
          <span className="text-green-500">✓</span> 3+ years professional security experience
        </li>
        <li className="flex items-center gap-2">
          <span className="text-green-500">✓</span> At least one industry certification (CEH, OSCP, etc.)
        </li>
        <li className="flex items-center gap-2">
          <span className="text-green-500">✓</span> Ability to dedicate 2+ hours per week
        </li>
        <li className="flex items-center gap-2">
          <span className="text-green-500">✓</span> Excellent communication skills
        </li>
        <li className="flex items-center gap-2">
          <span className="text-green-500">✓</span> Background verification clearance
        </li>
      </ul>
    </div>
  </motion.div>
);

export default MentorshipHub;
