
import React, { useState, useEffect } from 'react';
import {
    Award, CheckCircle, XCircle, Clock, ArrowRight,
    RotateCcw, Trophy, Target, Zap
} from 'lucide-react';
import './SkillAssessment.css';

const SkillAssessment = () => {
    const [assessments, setAssessments] = useState([]);
    const [activeAssessment, setActiveAssessment] = useState(null);
    const [questions, setQuestions] = useState([]);
    const [currentQuestion, setCurrentQuestion] = useState(0);
    const [answers, setAnswers] = useState({});
    const [results, setResults] = useState(null);
    const [timeLeft, setTimeLeft] = useState(600); // 10 minutes

    useEffect(() => {
        fetchAssessments();
    }, []);

    useEffect(() => {
        if (activeAssessment && timeLeft > 0 && !results) {
            const timer = setInterval(() => setTimeLeft(t => t - 1), 1000);
            return () => clearInterval(timer);
        }
    }, [activeAssessment, timeLeft, results]);

    const fetchAssessments = async () => {
        try {
            const res = await fetch('http://localhost:5000/api/assessments/available');
            const data = await res.json();
            if (data.success) setAssessments(data.assessments);
        } catch (err) {
            console.error(err);
        }
    };

    const startAssessment = async (assessmentId) => {
        try {
            const res = await fetch(`http://localhost:5000/api/assessments/${assessmentId}/start`, {
                method: 'POST'
            });
            const data = await res.json();
            if (data.success) {
                setActiveAssessment(assessmentId);
                setQuestions(data.questions);
                setCurrentQuestion(0);
                setAnswers({});
                setResults(null);
                setTimeLeft(600);
            }
        } catch (err) {
            console.error(err);
        }
    };

    const selectAnswer = (questionId, optionIndex) => {
        setAnswers({ ...answers, [questionId]: optionIndex });
    };

    const submitAssessment = async () => {
        try {
            const res = await fetch(`http://localhost:5000/api/assessments/${activeAssessment}/submit`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ user_id: 1, answers })
            });
            const data = await res.json();
            if (data.success) {
                setResults(data);
            }
        } catch (err) {
            console.error(err);
        }
    };

    const formatTime = (seconds) => {
        const m = Math.floor(seconds / 60);
        const s = seconds % 60;
        return `${m}:${s.toString().padStart(2, '0')}`;
    };

    const resetAssessment = () => {
        setActiveAssessment(null);
        setQuestions([]);
        setAnswers({});
        setResults(null);
    };

    // Results screen
    if (results) {
        return (
            <div className="assessment-container">
                <div className="results-card">
                    <div className={`results-icon ${results.passed ? 'passed' : 'failed'}`}>
                        {results.passed ? <Trophy size={64} /> : <XCircle size={64} />}
                    </div>
                    <h1>{results.passed ? 'ASSESSMENT PASSED!' : 'Assessment Failed'}</h1>
                    <div className="score-circle">
                        <span className="score-value">{results.score_percent}%</span>
                    </div>
                    <p className="score-breakdown">
                        {results.score} / {results.total} correct (Need {results.passing_score} to pass)
                    </p>
                    {results.passed && (
                        <div className="xp-reward">
                            <Zap size={20} />
                            <span>+{results.xp_awarded} XP Awarded!</span>
                        </div>
                    )}
                    <button className="retry-btn" onClick={resetAssessment}>
                        <RotateCcw size={18} />
                        Back to Assessments
                    </button>
                </div>
            </div>
        );
    }

    // Quiz screen
    if (activeAssessment && questions.length > 0) {
        const q = questions[currentQuestion];
        return (
            <div className="assessment-container">
                <header className="quiz-header">
                    <div className="progress-info">
                        Question {currentQuestion + 1} of {questions.length}
                    </div>
                    <div className="timer" style={{ color: timeLeft < 60 ? '#ff4444' : 'var(--text-secondary)' }}>
                        <Clock size={16} />
                        {formatTime(timeLeft)}
                    </div>
                </header>

                <div className="question-card">
                    <h2>{q.question}</h2>
                    <div className="options">
                        {q.options.map((option, i) => (
                            <button
                                key={i}
                                className={`option ${answers[q.id] === i ? 'selected' : ''}`}
                                onClick={() => selectAnswer(q.id, i)}
                            >
                                <span className="option-letter">{String.fromCharCode(65 + i)}</span>
                                {option}
                            </button>
                        ))}
                    </div>
                </div>

                <div className="quiz-actions">
                    {currentQuestion < questions.length - 1 ? (
                        <button
                            className="next-btn"
                            onClick={() => setCurrentQuestion(c => c + 1)}
                            disabled={answers[q.id] === undefined}
                        >
                            Next Question
                            <ArrowRight size={18} />
                        </button>
                    ) : (
                        <button
                            className="submit-btn"
                            onClick={submitAssessment}
                            disabled={Object.keys(answers).length < questions.length}
                        >
                            Submit Assessment
                            <CheckCircle size={18} />
                        </button>
                    )}
                </div>

                <div className="progress-bar">
                    <div
                        className="progress-fill"
                        style={{ width: `${((currentQuestion + 1) / questions.length) * 100}%` }}
                    />
                </div>
            </div>
        );
    }

    // Assessment selection screen
    return (
        <div className="assessment-container">
            <header className="assessment-header">
                <Award size={28} className="header-icon" />
                <div>
                    <h1>SKILL <span className="highlight">ASSESSMENTS</span></h1>
                    <p>Test your knowledge. Prove your expertise. Earn certifications.</p>
                </div>
            </header>

            <div className="assessments-grid">
                {assessments.map(assessment => (
                    <div key={assessment.id} className="assessment-card">
                        <div className="assessment-icon">
                            <Target size={32} />
                        </div>
                        <h3>{assessment.name}</h3>
                        <div className="assessment-meta">
                            <span>{assessment.question_count} Questions</span>
                            <span>Pass: {assessment.passing_score}/{assessment.question_count}</span>
                        </div>
                        <div className="assessment-reward">
                            <Zap size={16} />
                            <span>+{assessment.xp_reward} XP</span>
                        </div>
                        <button className="start-btn" onClick={() => startAssessment(assessment.id)}>
                            Start Assessment
                        </button>
                    </div>
                ))}
            </div>
        </div>
    );
};

export default SkillAssessment;
