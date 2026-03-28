import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Globe, ShoppingCart, Verified, TrendingUp, Award, Share2, BarChart3 } from 'lucide-react';

/**
 * Certification Marketplace Component
 * Buy/sell certifications, verify credentials, marketplace analytics
 */

const CertMarketplace = () => {
    const [certs, setCerts] = useState([]);
    const [userCerts, setUserCerts] = useState([]);
    const [tab, setTab] = useState('market'); // market, selling, analytics
    const [loading, setLoading] = useState(false);
    const [searchQuery, setSearchQuery] = useState('');
    const [selectedCert, setSelectedCert] = useState(null);
    const [filterType, setFilterType] = useState('all'); // all, buying, selling, verified

    useEffect(() => {
        fetchCertificates();
        fetchUserCertificates();
    }, []);

    const fetchCertificates = async () => {
        setLoading(true);
        try {
            const response = await fetch('/api/marketplace/certificates');
            if (response.ok) {
                const data = await response.json();
                setCerts(data.certificates || generateMockCerts());
            }
        } catch (error) {
            console.error('Error fetching certificates:', error);
            setCerts(generateMockCerts());
        } finally {
            setLoading(false);
        }
    };

    const fetchUserCertificates = async () => {
        try {
            const response = await fetch('/api/marketplace/my-certificates');
            if (response.ok) {
                const data = await response.json();
                setUserCerts(data.certificates || []);
            }
        } catch (error) {
            console.error('Error fetching user certificates:', error);
        }
    };

    const generateMockCerts = () => {
        const types = [
            { name: 'CEH Certified', issuer: 'EC-Council', price: 150, demand: '⬆️ High' },
            { name: 'OSCP', issuer: 'Offensive Security', price: 200, demand: '⬆️⬆️ Very High' },
            { name: 'GPEN', issuer: 'GIAC', price: 120, demand: '⬆️ High' },
            { name: 'Security+', issuer: 'CompTIA', price: 100, demand: '➡️ Medium' },
            { name: 'CISSP', issuer: 'ISC²', price: 180, demand: '⬆️ High' },
            { name: 'CCNA Security', issuer: 'Cisco', price: 90, demand: '➡️ Medium' },
            { name: 'AWS Security', issuer: 'Amazon', price: 75, demand: '⬆️ High' },
            { name: 'Azure Security', issuer: 'Microsoft', price: 70, demand: '⬆️⬆️ Very High' },
        ];

        return types.map((cert, idx) => ({
            id: idx + 1,
            name: cert.name,
            issuer: cert.issuer,
            price: cert.price,
            demand: cert.demand,
            listings: Math.floor(Math.random() * 15) + 3,
            verified_count: Math.floor(Math.random() * 50) + 10,
            avg_rating: (4 + Math.random()).toFixed(1),
            trend: Math.floor(Math.random() * 20) + 5,
            marketCap: Math.floor(Math.random() * 50000) + 10000,
            last_sale: Math.floor(Math.random() * 7) + 1,
        }));
    };

    const handleBuyCert = async (cert) => {
        try {
            const response = await fetch(`/api/marketplace/buy/${cert.id}`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ price: cert.price })
            });
            if (response.ok) {
                alert(`Successfully purchased ${cert.name}!`);
                fetchUserCertificates();
            }
        } catch (error) {
            console.error('Error buying certificate:', error);
        }
    };

    const handleSellCert = async (cert, price) => {
        try {
            const response = await fetch(`/api/marketplace/list/${cert.id}`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ listing_price: price })
            });
            if (response.ok) {
                alert('Certificate listed for sale!');
                fetchUserCertificates();
            }
        } catch (error) {
            console.error('Error listing certificate:', error);
        }
    };

    const filteredCerts = certs.filter(cert => {
        const matchesSearch = cert.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
                            cert.issuer.toLowerCase().includes(searchQuery.toLowerCase());
        return matchesSearch;
    });

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
                <div className="inline-flex items-center gap-2 px-4 py-2 rounded-full bg-primary-500/10 border border-primary-500/20">
                    <ShoppingCart className="w-4 h-4 text-primary-500" />
                    <span className="text-sm font-bold text-primary-500 uppercase tracking-widest">
                        Digital Credentials
                    </span>
                </div>
                <h1 className="text-5xl font-black text-white italic tracking-tighter uppercase">
                    Certification Marketplace
                </h1>
                <p className="text-gray-400 text-lg max-w-2xl">
                    Buy, sell, and verify industry-recognized security certifications. Track demand and pricing trends.
                </p>
            </motion.div>

            {/* Tabs */}
            <div className="flex gap-4 border-b border-gray-700">
                {[
                    { id: 'market', label: 'Marketplace', icon: '🏪' },
                    { id: 'selling', label: 'My Listings', icon: '📤' },
                    { id: 'analytics', label: 'Market Analytics', icon: '📊' }
                ].map(t => (
                    <button
                        key={t.id}
                        onClick={() => setTab(t.id)}
                        className={`px-6 py-3 font-bold uppercase tracking-widest transition-all ${
                            tab === t.id
                                ? 'text-primary-500 border-b-2 border-primary-500'
                                : 'text-gray-400 hover:text-gray-300'
                        }`}
                    >
                        {t.icon} {t.label}
                    </button>
                ))}
            </div>

            {/* Marketplace Tab */}
            {tab === 'market' && (
                <motion.div
                    variants={containerVariants}
                    initial="hidden"
                    animate="visible"
                    className="space-y-6"
                >
                    {/* Search & Filter */}
                    <div className="flex gap-4 flex-col md:flex-row">
                        <input
                            type="text"
                            placeholder="Search certifications..."
                            value={searchQuery}
                            onChange={(e) => setSearchQuery(e.target.value)}
                            className="flex-1 px-4 py-3 rounded-lg bg-gray-900 border border-gray-700 text-white placeholder-gray-500 focus:border-primary-500 outline-none"
                        />
                    </div>

                    {/* Certificates Grid */}
                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                        <AnimatePresence>
                            {filteredCerts.map(cert => (
                                <motion.div
                                    key={cert.id}
                                    variants={itemVariants}
                                    exit={{ opacity: 0 }}
                                    onClick={() => setSelectedCert(cert)}
                                    className="group p-6 rounded-xl bg-gradient-to-br from-gray-800/50 to-gray-900/50 border border-gray-700/50 hover:border-primary-500/50 cursor-pointer transition-all hover:shadow-lg hover:shadow-primary-500/20"
                                >
                                    {/* Header */}
                                    <div className="flex items-start justify-between mb-4">
                                        <div>
                                            <h3 className="text-lg font-bold text-white">{cert.name}</h3>
                                            <p className="text-sm text-gray-400">{cert.issuer}</p>
                                        </div>
                                        <Verified className="w-5 h-5 text-primary-500" />
                                    </div>

                                    {/* Stats */}
                                    <div className="grid grid-cols-2 gap-3 mb-4">
                                        <div className="p-3 rounded-lg bg-gray-900/50">
                                            <p className="text-xs text-gray-400 mb-1">Current Price</p>
                                            <p className="text-lg font-bold text-green-400">${cert.price}</p>
                                        </div>
                                        <div className="p-3 rounded-lg bg-gray-900/50">
                                            <p className="text-xs text-gray-400 mb-1">Demand</p>
                                            <p className="text-sm font-bold text-white">{cert.demand}</p>
                                        </div>
                                        <div className="p-3 rounded-lg bg-gray-900/50">
                                            <p className="text-xs text-gray-400 mb-1">Active Listings</p>
                                            <p className="text-lg font-bold text-blue-400">{cert.listings}</p>
                                        </div>
                                        <div className="p-3 rounded-lg bg-gray-900/50">
                                            <p className="text-xs text-gray-400 mb-1">Rating</p>
                                            <p className="text-lg font-bold text-yellow-400">⭐ {cert.avg_rating}</p>
                                        </div>
                                    </div>

                                    {/* Market Info */}
                                    <div className="space-y-2 mb-4 pb-4 border-t border-gray-700/50">
                                        <div className="flex justify-between text-xs mt-4">
                                            <span className="text-gray-400">Market Cap</span>
                                            <span className="text-primary-500">${cert.marketCap.toLocaleString()}</span>
                                        </div>
                                        <div className="flex justify-between text-xs">
                                            <span className="text-gray-400">24h Change</span>
                                            <span className="text-green-400">+{cert.trend}%</span>
                                        </div>
                                    </div>

                                    {/* Action Button */}
                                    <button
                                        onClick={(e) => {
                                            e.stopPropagation();
                                            handleBuyCert(cert);
                                        }}
                                        className="w-full px-4 py-2 bg-primary-500 hover:bg-primary-600 text-white font-bold rounded-lg transition-all"
                                    >
                                        Buy for ${cert.price}
                                    </button>
                                </motion.div>
                            ))}
                        </AnimatePresence>
                    </div>
                </motion.div>
            )}

            {/* My Listings Tab */}
            {tab === 'selling' && (
                <motion.div
                    variants={containerVariants}
                    initial="hidden"
                    animate="visible"
                    className="space-y-6"
                >
                    {userCerts.length === 0 ? (
                        <div className="p-8 rounded-lg bg-gray-900/50 border border-gray-700/50 text-center">
                            <p className="text-gray-400 mb-4">You haven't earned any certifications yet.</p>
                            <button className="px-6 py-2 bg-primary-500 text-white font-bold rounded-lg hover:bg-primary-600 transition-all">
                                Start Learning Paths
                            </button>
                        </div>
                    ) : (
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                            {userCerts.map(cert => (
                                <motion.div
                                    key={cert.id}
                                    variants={itemVariants}
                                    className="p-6 rounded-xl bg-gradient-to-br from-gray-800/50 to-gray-900/50 border border-primary-500/30"
                                >
                                    <div className="flex items-center justify-between mb-4">
                                        <h3 className="text-lg font-bold text-white">{cert.name}</h3>
                                        {cert.listed && (
                                            <span className="px-3 py-1 rounded-full bg-green-500/20 text-green-400 text-xs font-bold">
                                                Listed
                                            </span>
                                        )}
                                    </div>
                                    <p className="text-sm text-gray-400 mb-4">Earned: {cert.earned_date}</p>
                                    {cert.listed ? (
                                        <div className="space-y-2">
                                            <p className="text-sm text-gray-300">Listed at: ${cert.listing_price}</p>
                                            <button className="w-full px-4 py-2 bg-red-500/20 text-red-400 rounded-lg hover:bg-red-500/30 transition-all">
                                                Remove Listing
                                            </button>
                                        </div>
                                    ) : (
                                        <input
                                            type="number"
                                            placeholder="Enter listing price"
                                            defaultValue={cert.suggested_price}
                                            className="w-full px-3 py-2 mb-3 rounded-lg bg-gray-900 border border-gray-700 text-white placeholder-gray-500 focus:border-primary-500 outline-none mb-3"
                                        />
                                    )}
                                    {!cert.listed && (
                                        <button
                                            onClick={() => handleSellCert(cert, Math.random() * 100 + 80)}
                                            className="w-full px-4 py-2 bg-primary-500 text-white font-bold rounded-lg hover:bg-primary-600 transition-all"
                                        >
                                            List for Sale
                                        </button>
                                    )}
                                </motion.div>
                            ))}
                        </div>
                    )}
                </motion.div>
            )}

            {/* Market Analytics Tab */}
            {tab === 'analytics' && (
                <motion.div
                    variants={containerVariants}
                    initial="hidden"
                    animate="visible"
                    className="space-y-6"
                >
                    {/* Top Stats */}
                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                        <motion.div variants={itemVariants} className="p-4 rounded-lg bg-gradient-to-br from-green-500/20 to-green-900/20 border border-green-500/30">
                            <p className="text-xs text-gray-400 mb-2">Market Volume</p>
                            <p className="text-2xl font-black text-green-400">$2.4M</p>
                            <p className="text-xs text-green-400 mt-2">↑ 12% this week</p>
                        </motion.div>
                        <motion.div variants={itemVariants} className="p-4 rounded-lg bg-gradient-to-br from-blue-500/20 to-blue-900/20 border border-blue-500/30">
                            <p className="text-xs text-gray-400 mb-2">Active Listings</p>
                            <p className="text-2xl font-black text-blue-400">284</p>
                            <p className="text-xs text-blue-400 mt-2">↑ 8 new today</p>
                        </motion.div>
                        <motion.div variants={itemVariants} className="p-4 rounded-lg bg-gradient-to-br from-purple-500/20 to-purple-900/20 border border-purple-500/30">
                            <p className="text-xs text-gray-400 mb-2">Avg. Trade Value</p>
                            <p className="text-2xl font-black text-purple-400">$142</p>
                            <p className="text-xs text-purple-400 mt-2">↓ 3% vs last week</p>
                        </motion.div>
                        <motion.div variants={itemVariants} className="p-4 rounded-lg bg-gradient-to-br from-yellow-500/20 to-yellow-900/20 border border-yellow-500/30">
                            <p className="text-xs text-gray-400 mb-2">Hot Certifications</p>
                            <p className="text-2xl font-black text-yellow-400">12</p>
                            <p className="text-xs text-yellow-400 mt-2">Based on demand</p>
                        </motion.div>
                    </div>

                    {/* Market Table */}
                    <div className="overflow-x-auto">
                        <table className="w-full text-sm">
                            <thead>
                                <tr className="border-b border-gray-700/50">
                                    <th className="px-4 py-3 text-left text-gray-400 font-bold">Certification</th>
                                    <th className="px-4 py-3 text-right text-gray-400 font-bold">24h Change</th>
                                    <th className="px-4 py-3 text-right text-gray-400 font-bold">Market Cap</th>
                                    <th className="px-4 py-3 text-right text-gray-400 font-bold">Demand</th>
                                </tr>
                            </thead>
                            <tbody>
                                {filteredCerts.sort((a, b) => b.trend - a.trend).map(cert => (
                                    <motion.tr
                                        key={cert.id}
                                        variants={itemVariants}
                                        className="border-b border-gray-700/30 hover:bg-gray-800/50 transition-colors"
                                    >
                                        <td className="px-4 py-3">
                                            <div>
                                                <p className="font-bold text-white">{cert.name}</p>
                                                <p className="text-xs text-gray-400">{cert.issuer}</p>
                                            </div>
                                        </td>
                                        <td className="px-4 py-3 text-right">
                                            <span className={`font-bold ${cert.trend > 0 ? 'text-green-400' : 'text-red-400'}`}>
                                                {cert.trend > 0 ? '+' : ''}{cert.trend}%
                                            </span>
                                        </td>
                                        <td className="px-4 py-3 text-right text-gray-300">
                                            ${cert.marketCap.toLocaleString()}
                                        </td>
                                        <td className="px-4 py-3 text-right">
                                            <span className="text-primary-400 font-bold">{cert.demand}</span>
                                        </td>
                                    </motion.tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                </motion.div>
            )}

            {/* Detail Modal */}
            <AnimatePresence>
                {selectedCert && (
                    <motion.div
                        initial={{ opacity: 0 }}
                        animate={{ opacity: 1 }}
                        exit={{ opacity: 0 }}
                        onClick={() => setSelectedCert(null)}
                        className="fixed inset-0 bg-black/50 backdrop-blur-sm flex items-center justify-center z-50"
                    >
                        <motion.div
                            initial={{ scale: 0.9, opacity: 0 }}
                            animate={{ scale: 1, opacity: 1 }}
                            exit={{ scale: 0.9, opacity: 0 }}
                            onClick={(e) => e.stopPropagation()}
                            className="bg-gray-900 border border-gray-700 rounded-2xl p-8 max-w-md w-full space-y-6"
                        >
                            <div>
                                <h2 className="text-2xl font-black text-white mb-2">{selectedCert.name}</h2>
                                <p className="text-gray-400">{selectedCert.issuer}</p>
                            </div>

                            <div className="grid grid-cols-2 gap-4">
                                <div className="p-4 bg-gray-800/50 rounded-lg">
                                    <p className="text-xs text-gray-400 mb-1">Current Price</p>
                                    <p className="text-2xl font-bold text-green-400">${selectedCert.price}</p>
                                </div>
                                <div className="p-4 bg-gray-800/50 rounded-lg">
                                    <p className="text-xs text-gray-400 mb-1">Verified Count</p>
                                    <p className="text-2xl font-bold text-blue-400">{selectedCert.verified_count}</p>
                                </div>
                            </div>

                            <div className="space-y-3">
                                <p className="text-sm text-gray-300">
                                    <strong>Market Cap:</strong> ${selectedCert.marketCap.toLocaleString()}
                                </p>
                                <p className="text-sm text-gray-300">
                                    <strong>24h Trend:</strong> <span className="text-green-400">+{selectedCert.trend}%</span>
                                </p>
                                <p className="text-sm text-gray-300">
                                    <strong>Last Sale:</strong> {selectedCert.last_sale} days ago
                                </p>
                            </div>

                            <div className="flex gap-3 pt-4 border-t border-gray-700">
                                <button
                                    onClick={() => {
                                        handleBuyCert(selectedCert);
                                        setSelectedCert(null);
                                    }}
                                    className="flex-1 px-4 py-3 bg-primary-500 hover:bg-primary-600 text-white font-bold rounded-lg transition-all"
                                >
                                    Buy Now
                                </button>
                                <button
                                    onClick={() => setSelectedCert(null)}
                                    className="flex-1 px-4 py-3 bg-gray-800 hover:bg-gray-700 text-white font-bold rounded-lg transition-all"
                                >
                                    Close
                                </button>
                            </div>
                        </motion.div>
                    </motion.div>
                )}
            </AnimatePresence>
        </div>
    );
};

export default CertMarketplace;
