import React, { useState } from 'react';
import { useAppContext } from '../context/AppContext';
import { courses } from '../data/courses';
import CourseCard from '../components/CourseCard';
import {
    Search,
    Filter,
    BookOpen,
    Target,
    Zap,
    Shield,
    ChevronDown,
    LayoutGrid,
    List
} from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';

const Courses = () => {
    const { t, language } = useAppContext();
    const [searchQuery, setSearchQuery] = useState('');
    const [selectedCategory, setSelectedCategory] = useState('all');
    const [viewMode, setViewMode] = useState('grid'); // 'grid' or 'list'

    const categories = [
        { id: 'all', label: t('الكل', 'All Systems'), icon: LayoutGrid },
        { id: 'beginner', label: t('مبتدئ', 'Entry Level'), icon: Shield },
        { id: 'intermediate', label: t('متوسط', 'Specialist'), icon: Target },
        { id: 'advanced', label: t('متقدم', 'Elite'), icon: Zap },
    ];

    const filteredCourses = courses.filter(course => {
        const matchesSearch = (language === 'ar' ? course.titleAr : course.title)
            .toLowerCase()
            .includes(searchQuery.toLowerCase());
        const matchesCategory = selectedCategory === 'all' || course.level === selectedCategory;
        return matchesSearch && matchesCategory;
    });

    return (
        <div className="space-y-12 pb-20">
            {/* Header Section */}
            <header className="flex flex-col md:flex-row md:items-center justify-between gap-8">
                <div className="space-y-4">
                    <div className="flex items-center gap-3">
                        <div className="w-2 h-10 bg-primary-500 rounded-full" />
                        <h1 className="text-5xl font-black text-white italic tracking-tighter uppercase">
                            SYSTEM <span className="text-primary-500">ARCHIVE</span>
                        </h1>
                    </div>
                    <p className="text-gray-500 font-bold uppercase tracking-[0.2em] text-xs">
                        {filteredCourses.length} ACTIVE MODULES DETECTED IN DATABASE
                    </p>
                </div>

                <div className="flex items-center gap-4">
                    <div className="flex bg-dark-800/80 border border-white/5 p-1 rounded-2xl">
                        <button
                            onClick={() => setViewMode('grid')}
                            className={`p-2.5 rounded-xl transition-all ${viewMode === 'grid' ? 'bg-primary-500 text-dark-900 shadow-lg' : 'text-gray-500 hover:text-white'}`}
                        >
                            <LayoutGrid size={18} />
                        </button>
                        <button
                            onClick={() => setViewMode('list')}
                            className={`p-2.5 rounded-xl transition-all ${viewMode === 'list' ? 'bg-primary-500 text-dark-900 shadow-lg' : 'text-gray-500 hover:text-white'}`}
                        >
                            <List size={18} />
                        </button>
                    </div>
                </div>
            </header>

            {/* Filter & Search Bar */}
            <div className="flex flex-col lg:flex-row gap-6">
                <div className="relative flex-1 group">
                    <Search className="absolute left-5 top-1/2 -translate-y-1/2 text-gray-500 group-focus-within:text-primary-500 transition-colors" size={20} />
                    <input
                        type="text"
                        placeholder="Search by mission title, technology, or instructor..."
                        value={searchQuery}
                        onChange={(e) => setSearchQuery(e.target.value)}
                        className="w-full bg-dark-800/40 border border-white/5 rounded-3xl py-4 pl-14 pr-6 focus:outline-none focus:border-primary-500/50 focus:bg-dark-800/60 transition-all text-gray-100 placeholder:text-gray-600 font-medium"
                    />
                </div>

                <div className="flex flex-wrap items-center gap-3">
                    {categories.map((cat) => (
                        <button
                            key={cat.id}
                            onClick={() => setSelectedCategory(cat.id)}
                            className={`
                                flex items-center gap-3 px-6 py-4 rounded-3xl border transition-all duration-300 font-bold uppercase tracking-widest text-[10px]
                                ${selectedCategory === cat.id
                                    ? 'bg-primary-500 border-primary-500 text-dark-900 shadow-[0_0_20px_rgba(0,242,234,0.2)]'
                                    : 'bg-dark-800/40 border-white/5 text-gray-400 hover:border-white/10 hover:text-white'}
                            `}
                        >
                            <cat.icon size={16} />
                            {cat.label}
                        </button>
                    ))}
                </div>
            </div>

            {/* Courses Grid */}
            <AnimatePresence mode="popLayout">
                {filteredCourses.length > 0 ? (
                    <motion.div
                        layout
                        className={viewMode === 'grid'
                            ? "grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-8"
                            : "space-y-6"
                        }
                    >
                        {filteredCourses.map((course) => (
                            <motion.div
                                key={course.id}
                                layout
                                initial={{ opacity: 0, scale: 0.9 }}
                                animate={{ opacity: 1, scale: 1 }}
                                exit={{ opacity: 0, scale: 0.9 }}
                                transition={{ duration: 0.2 }}
                            >
                                <CourseCard course={course} isList={viewMode === 'list'} />
                            </motion.div>
                        ))}
                    </motion.div>
                ) : (
                    <motion.div
                        initial={{ opacity: 0 }}
                        animate={{ opacity: 1 }}
                        className="flex flex-col items-center justify-center py-32 space-y-6 rounded-[3rem] border border-dashed border-white/10 bg-dark-800/20"
                    >
                        <div className="w-20 h-20 rounded-full bg-white/5 flex items-center justify-center text-gray-600">
                            <Search size={40} />
                        </div>
                        <div className="text-center">
                            <h3 className="text-2xl font-black text-white italic uppercase tracking-tighter">No Systems Found</h3>
                            <p className="text-gray-500 mt-1 font-bold uppercase tracking-widest text-[10px]">Try adjusting your search filters</p>
                        </div>
                        <button
                            onClick={() => { setSearchQuery(''); setSelectedCategory('all'); }}
                            className="px-8 py-3 bg-white/5 border border-white/10 rounded-2xl text-[10px] font-black text-white uppercase tracking-[0.2em] hover:bg-white/10 transition-all"
                        >
                            Reset Database Query
                        </button>
                    </motion.div>
                )}
            </AnimatePresence>
        </div>
    );
};

export default Courses;
