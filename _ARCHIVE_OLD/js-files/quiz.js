// ==================== QUIZ SYSTEM ====================
// نظام الاختبارات التفاعلي

// Current quiz state
let currentQuiz = null;
let currentQuestionIndex = 0;
let userAnswers = [];
let quizStartTime = null;

// Start quiz
function startQuiz(courseId, moduleId) {
    const course = courses.find(c => c.id === courseId);
    if (!course) return;

    const module = course.modules.find(m => m.id === moduleId);
    if (!module || !module.quiz) return;

    currentQuiz = {
        courseId: courseId,
        moduleId: moduleId,
        quiz: module.quiz
    };

    currentQuestionIndex = 0;
    userAnswers = [];
    quizStartTime = Date.now();

    showQuizQuestion();
}

// Show current question
function showQuizQuestion() {
    if (!currentQuiz) return;

    const quiz = currentQuiz.quiz;
    const question = quiz.questions[currentQuestionIndex];

    const quizHtml = `
        <div class="quiz-container">
            <div class="quiz-header">
                <h3>${quiz.title}</h3>
                <div class="quiz-progress">
                    <span>${txt('السؤال', 'Question')} ${currentQuestionIndex + 1} ${txt('من', 'of')} ${quiz.questions.length}</span>
                    <div class="progress">
                        <div class="progress-bar" style="width: ${((currentQuestionIndex + 1) / quiz.questions.length) * 100}%"></div>
                    </div>
                </div>
            </div>
            
            <div class="quiz-question">
                <h4>${question.question}</h4>
                <div class="quiz-options">
                    ${question.options.map((option, index) => `
                        <div class="quiz-option" onclick="selectAnswer(${index})">
                            <input type="radio" name="answer" id="option-${index}" value="${index}">
                            <label for="option-${index}">${option}</label>
                        </div>
                    `).join('')}
                </div>
            </div>
            
            <div class="quiz-actions">
                ${currentQuestionIndex > 0 ? `
                    <button class="btn btn-secondary" onclick="previousQuestion()">
                        <i class="fas fa-arrow-left"></i> ${txt('السابق', 'Previous')}
                    </button>
                ` : ''}
                
                <button class="btn btn-primary" onclick="nextQuestion()" id="next-btn" disabled>
                    ${currentQuestionIndex < quiz.questions.length - 1 ?
            txt('التالي', 'Next') :
            txt('إنهاء', 'Finish')
        }
                    <i class="fas fa-arrow-right"></i>
                </button>
            </div>
        </div>
    `;

    document.getElementById('content').innerHTML = quizHtml;
}

// Select answer
function selectAnswer(answerIndex) {
    userAnswers[currentQuestionIndex] = answerIndex;

    // Enable next button
    document.getElementById('next-btn').disabled = false;

    // Highlight selected option
    document.querySelectorAll('.quiz-option').forEach((opt, idx) => {
        opt.classList.toggle('selected', idx === answerIndex);
    });
}

// Next question
function nextQuestion() {
    if (userAnswers[currentQuestionIndex] === undefined) {
        alert(txt('الرجاء اختيار إجابة', 'Please select an answer'));
        return;
    }

    if (currentQuestionIndex < currentQuiz.quiz.questions.length - 1) {
        currentQuestionIndex++;
        showQuizQuestion();
    } else {
        finishQuiz();
    }
}

// Previous question
function previousQuestion() {
    if (currentQuestionIndex > 0) {
        currentQuestionIndex--;
        showQuizQuestion();
    }
}

// Finish quiz and show results
function finishQuiz() {
    const quiz = currentQuiz.quiz;
    let correctAnswers = 0;

    const results = quiz.questions.map((question, index) => {
        const userAnswer = userAnswers[index];
        const isCorrect = userAnswer === question.correctAnswer;
        if (isCorrect) correctAnswers++;

        return {
            question: question,
            userAnswer: userAnswer,
            correctAnswer: question.correctAnswer,
            isCorrect: isCorrect
        };
    });

    const score = correctAnswers;
    const total = quiz.questions.length;
    const percentage = Math.round((score / total) * 100);
    const passed = percentage >= quiz.passingScore;

    // Save quiz score
    saveQuizScore(currentQuiz.courseId, currentQuiz.moduleId, score, total);

    // Show results
    showQuizResults(results, score, total, percentage, passed);
}

// Show quiz results
function showQuizResults(results, score, total, percentage, passed) {
    const resultsHtml = `
        <div class="quiz-results">
            <div class="results-header ${passed ? 'passed' : 'failed'}">
                <i class="fas fa-${passed ? 'check-circle' : 'times-circle'} fa-3x mb-3"></i>
                <h2>${passed ? txt('نجحت!', 'Passed!') : txt('لم تنجح', 'Failed')}</h2>
                <h1 class="score">${score} / ${total}</h1>
                <p class="percentage">${percentage}%</p>
                <p>${txt('النسبة المطلوبة للنجاح', 'Passing score')}: ${currentQuiz.quiz.passingScore}%</p>
            </div>
            
            <div class="results-details">
                <h3>${txt('مراجعة الإجابات', 'Review Answers')}</h3>
                ${results.map((result, index) => `
                    <div class="result-item ${result.isCorrect ? 'correct' : 'incorrect'}">
                        <div class="result-question">
                            <strong>${txt('السؤال', 'Question')} ${index + 1}:</strong> ${result.question.question}
                        </div>
                        <div class="result-answer">
                            <div class="user-answer">
                                <i class="fas fa-${result.isCorrect ? 'check' : 'times'}"></i>
                                ${txt('إجابتك', 'Your answer')}: ${result.question.options[result.userAnswer]}
                            </div>
                            ${!result.isCorrect ? `
                                <div class="correct-answer">
                                    <i class="fas fa-check text-success"></i>
                                    ${txt('الإجابة الصحيحة', 'Correct answer')}: ${result.question.options[result.correctAnswer]}
                                </div>
                            ` : ''}
                            <div class="explanation">
                                <i class="fas fa-info-circle"></i>
                                ${result.question.explanation}
                            </div>
                        </div>
                    </div>
                `).join('')}
            </div>
            
            <div class="results-actions">
                <button class="btn btn-primary" onclick="retakeQuiz()">
                    <i class="fas fa-redo"></i> ${txt('إعادة المحاولة', 'Retake Quiz')}
                </button>
                <button class="btn btn-secondary" onclick="backToModule()">
                    <i class="fas fa-arrow-left"></i> ${txt('العودة للوحدة', 'Back to Module')}
                </button>
            </div>
        </div>
        
        <style>
            .quiz-results {
                max-width: 800px;
                margin: 0 auto;
            }
            .results-header {
                text-align: center;
                padding: 40px;
                border-radius: 15px;
                margin-bottom: 30px;
            }
            .results-header.passed {
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white;
            }
            .results-header.failed {
                background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
                color: white;
            }
            .score {
                font-size: 3rem;
                font-weight: bold;
                margin: 20px 0;
            }
            .percentage {
                font-size: 2rem;
                opacity: 0.9;
            }
            .result-item {
                background: white;
                padding: 20px;
                border-radius: 10px;
                margin-bottom: 15px;
                border-left: 4px solid #ddd;
            }
            .result-item.correct {
                border-left-color: #28a745;
            }
            .result-item.incorrect {
                border-left-color: #dc3545;
            }
            .result-question {
                margin-bottom: 15px;
                font-size: 1.1rem;
            }
            .user-answer, .correct-answer, .explanation {
                padding: 10px;
                margin: 5px 0;
                border-radius: 5px;
            }
            .user-answer {
                background: #f8f9fa;
            }
            .correct-answer {
                background: #d4edda;
            }
            .explanation {
                background: #e7f3ff;
                font-style: italic;
            }
            .results-actions {
                display: flex;
                gap: 15px;
                justify-content: center;
                margin-top: 30px;
            }
        </style>
    `;

    document.getElementById('content').innerHTML = resultsHtml;
}

// Retake quiz
function retakeQuiz() {
    startQuiz(currentQuiz.courseId, currentQuiz.moduleId);
}

// Back to module
function backToModule() {
    loadPage('module-viewer', currentQuiz.courseId, currentQuiz.moduleId);
}
