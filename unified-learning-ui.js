// ==================== LEARN PAGE (5-Tab Structure) ====================
function pageLearn() {
    const data = window.UnifiedLearningData || {};
    const paths = data.paths || [];
    const roadmaps = data.roadmaps || [];
    const modules = data.modules || [];
    const walkthroughs = data.walkthroughs || [];
    const networks = data.networks || [];

    return `
        <div class="learn-page-thm">
            <style>
                /* ============ TRYHACKME STYLE LEARN PAGE ============ */
                .learn-page-thm {
                    min-height: 100vh;
                    background: #141d2b;
                }

            /* Hero Section - Dark Navy */
            .learn-hero-thm {
                background: linear-gradient(135deg, #1a2332 0%, #212c3d 100%);
            padding: 50px 40px 60px;
            position: relative;
            overflow: hidden;
                }
            .learn-hero-thm::before {
                content: '';
            position: absolute;
            top: 0;
            right: 0;
            width: 50%;
            height: 100%;
            background: radial-gradient(circle at 70% 50%, rgba(34, 197, 94, 0.05) 0%, transparent 50%);
                }
            .learn-hero-container {
                max - width: 1400px;
            margin: 0 auto;
            display: grid;
            grid-template-columns: 1fr 400px;
            gap: 60px;
            align-items: center;
                }
            @media (max-width: 1000px) {
                .learn-hero-container { grid-template-columns: 1fr; }
                .learn-hero-image { display: none; }
            }

            .learn-hero-content h1 {
                font - size: 3rem;
            font-weight: 800;
            color: #fff;
            margin-bottom: 20px;
            font-family: 'Inter', 'Segoe UI', sans-serif;
                }
            .learn-hero-content p {
                font - size: 16px;
            color: rgba(255,255,255,0.7);
            line-height: 1.7;
            margin-bottom: 35px;
            max-width: 650px;
                }

            /* Stats Row */
            .learn-stats-row {
                display: flex;
            gap: 50px;
                }
            .learn-stat-item {
                display: flex;
            align-items: baseline;
            gap: 10px;
                }
            .learn-stat-number {
                font - size: 2.2rem;
            font-weight: 800;
            color: #fff;
            font-family: 'Inter', sans-serif;
                }
            .learn-stat-label {
                font - size: 14px;
            color: rgba(255,255,255,0.6);
            font-weight: 500;
                }

            /* Hero Image/Illustration */
            .learn-hero-image {
                display: flex;
            align-items: center;
            justify-content: center;
            position: relative;
                }
            .learn-hero-illustration {
                width: 350px;
            height: 250px;
            background: linear-gradient(135deg, #2a3a4d 0%, #1a2836 100%);
            border-radius: 20px;
            display: flex;
            align-items: center;
            justify-content: center;
            position: relative;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
                }
            .learn-hero-illustration::before {
                content: '💻';
            font-size: 80px;
            filter: drop-shadow(0 5px 20px rgba(0,0,0,0.3));
                }
            .illustration-shield {
                position: absolute;
            top: -20px;
            right: -20px;
            width: 80px;
            height: 80px;
            background: linear-gradient(135deg, #22c55e 0%, #16a34a 100%);
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 36px;
            box-shadow: 0 10px 30px rgba(34, 197, 94, 0.4);
                }
            .illustration-arrow {
                position: absolute;
            top: 10px;
            right: 40px;
            font-size: 40px;
            color: #ef4444;
            transform: rotate(-45deg);
            animation: arrowBounce 2s infinite ease-in-out;
                }
            @keyframes arrowBounce {
                0 %, 100 % { transform: rotate(-45deg) translate(0, 0); }
            50% {transform: rotate(-45deg) translate(5px, -5px); }
                }

            /* Tab Navigation - Clean Style */
            .learn-tabs-thm-container {
                background: #141d2b;
            border-bottom: 1px solid rgba(255,255,255,0.1);
            position: sticky;
            top: 0;
            z-index: 100;
                }
            .learn-tabs-thm {
                max - width: 1400px;
            margin: 0 auto;
            display: flex;
            gap: 0;
            padding: 0 40px;
                }
            .learn-tab-thm {
                padding: 18px 24px;
            background: transparent;
            border: none;
            border-bottom: 3px solid transparent;
            color: #94a3b8;
            font-weight: 600;
            font-size: 14px;
            cursor: pointer;
            transition: all 0.3s ease;
            display: flex;
            align-items: center;
            gap: 10px;
                }
            .learn-tab-thm:hover {
                color: #ffffff;
            background: rgba(255,255,255,0.05);
                }
            .learn-tab-thm.active {
                color: #22c55e;
            border-bottom-color: #22c55e;
                }
            .learn-tab-thm i {
                font - size: 16px;
            opacity: 0.7;
                }
            .learn-tab-thm.active i {
                opacity: 1;
                }

            /* Main Content Area */
            .learn-main-content {
                max-width: 1400px;
                margin: 0 auto;
                padding: 40px;
            }

            /* Tab Content Visibility Logic */
            .learn-tab-content {
                display: none;
                animation: fadeIn 0.5s ease;
            }
            .learn-tab-content.active {
                display: block;
            }
            @keyframes fadeIn {
                from { opacity: 0; transform: translateY(10px); }
                to { opacity: 1; transform: translateY(0); }
            }

            /* Section Header with Filters */
            .section-header-thm {
                margin - bottom: 30px;
                }
            .section-header-thm h2 {
                font - size: 1.5rem;
            font-weight: 700;
            color: #1f2937;
            margin-bottom: 8px;
                }
            .section-header-thm p {
                color: #6b7280;
            font-size: 14px;
            margin-bottom: 25px;
                }
            .section-filters-row {
                display: flex;
            justify-content: space-between;
            align-items: center;
            gap: 20px;
            flex-wrap: wrap;
                }
            .section-search-box {
                position: relative;
            flex: 0 0 300px;
                }
            .section-search-box i {
                position: absolute;
            left: 14px;
            top: 50%;
            transform: translateY(-50%);
            color: #9ca3af;
            font-size: 14px;
                }
            .section-search-box input {
                width: 100%;
            padding: 12px 16px 12px 42px;
            border: 1px solid #d1d5db;
            border-radius: 8px;
            font-size: 14px;
            color: #1f2937;
            background: #fff;
            transition: all 0.3s ease;
                }
            .section-search-box input::placeholder {
                color: #9ca3af;
                }
            .section-search-box input:focus {
                outline: none;
            border-color: #22c55e;
            box-shadow: 0 0 0 3px rgba(34, 197, 94, 0.1);
                }
            .section-filter-dropdowns {
                display: flex;
            gap: 12px;
                }
            .section-filter-dropdowns select {
                padding: 12px 36px 12px 16px;
            border: 1px solid #d1d5db;
            border-radius: 8px;
            font-size: 14px;
            color: #1f2937;
            background: #fff url("data:image/svg+xml,%3csvg xmlns='http://www.w3.org/2000/svg' fill='none' viewBox='0 0 20 20'%3e%3cpath stroke='%236b7280' stroke-linecap='round' stroke-linejoin='round' stroke-width='1.5' d='M6 8l4 4 4-4'/%3e%3c/svg%3e") right 12px center/16px 16px no-repeat;
            appearance: none;
            min-width: 130px;
            cursor: pointer;
            transition: all 0.3s ease;
                }
            .section-filter-dropdowns select:hover {
                border - color: #9ca3af;
                }
            .section-filter-dropdowns select:focus {
                outline: none;
            border-color: #22c55e;
            box-shadow: 0 0 0 3px rgba(34, 197, 94, 0.1);
                }

            /* Paths Grid - Light Theme Cards */
            .paths-grid-thm {
                display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 24px;
                }
            @media (max-width: 1400px) { .paths-grid-thm { grid-template-columns: repeat(3, 1fr); } }
            @media (max-width: 1000px) { .paths-grid-thm { grid-template-columns: repeat(2, 1fr); } }
            @media (max-width: 600px) { .paths-grid-thm { grid-template-columns: 1fr; } }

            .path-card-thm {
                background: rgba(30, 41, 59, 0.4);
                backdrop-filter: blur(20px);
                -webkit-backdrop-filter: blur(20px);
                border-radius: 16px;
                overflow: hidden;
                cursor: pointer;
                transition: all 0.4s cubic-bezier(0.175, 0.885, 0.32, 1.275);
                box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.3);
                border: 1px solid rgba(255, 255, 255, 0.1);
                position: relative;
            }
            .path-card-thm:hover {
                transform: translateY(-8px);
                background: rgba(30, 41, 59, 0.6);
                border-color: rgba(34, 197, 94, 0.5);
                box-shadow: 0 20px 50px rgba(0,0,0,0.4), 0 0 15px rgba(34, 197, 94, 0.2);
            }

            /* Latest Enrolled Badge */
            .latest-enrolled-badge {
                position: absolute;
            top: 0;
            left: 50%;
            transform: translate(-50%, -50%);
            background: linear-gradient(135deg, #1a2332 0%, #2d3a4d 100%);
            color: #fff;
            padding: 6px 14px;
            border-radius: 20px;
            font-size: 11px;
            font-weight: 600;
            z-index: 10;
            white-space: nowrap;
            box-shadow: 0 4px 15px rgba(0,0,0,0.2);
                }

            /* Card Image Area */
            .path-image-thm {
                height: 140px;
            background: var(--path-color, #3b82f6);
            display: flex;
            align-items: center;
            justify-content: center;
            position: relative;
            overflow: hidden;
                }
            .path-image-thm::before {
                content: '';
            position: absolute;
            inset: 0;
            background: linear-gradient(135deg, rgba(255,255,255,0.15) 0%, transparent 60%);
                }
            .path-image-thm i {
                font - size: 50px;
            color: rgba(255,255,255,0.9);
            z-index: 1;
                }

            /* Progress Circle on Card */
            .path-progress-thm {
                position: absolute;
            bottom: -20px;
            right: 16px;
            width: 44px;
            height: 44px;
            background: #fff;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 12px;
            font-weight: 700;
            color: #22c55e;
            box-shadow: 0 2px 10px rgba(0,0,0,0.15);
            z-index: 5;
            border: 2px solid #e5e7eb;
                }

            /* Card Content */
            .path-content-thm {
                padding: 24px 18px 18px;
            }
            .path-name-thm {
                font-size: 1.1rem;
                font-weight: 700;
                color: #f8fafc;
                margin-bottom: 10px;
                line-height: 1.4;
            }
            .path-card-thm:hover .path-name-thm {
                color: #22c55e;
            }
            .path-desc-thm {
                color: #94a3b8;
                font-size: 13px;
                line-height: 1.6;
                margin-bottom: 14px;
                display: -webkit-box;
                -webkit-line-clamp: 2;
                -webkit-box-orient: vertical;
                overflow: hidden;
            }
            .path-meta-thm {
                display: flex;
            align-items: center;
            gap: 15px;
                }
            .path-difficulty-thm {
                display: flex;
            align-items: center;
            gap: 5px;
            font-size: 12px;
            font-weight: 600;
                }
            .path-difficulty-thm i {font - size: 10px; }
            .path-difficulty-thm.easy {color: #22c55e; }
            .path-difficulty-thm.basic {color: #22c55e; }
            .path-difficulty-thm.intermediate {color: #f59e0b; }
            .path-difficulty-thm.medium {color: #f59e0b; }
            .path-difficulty-thm.hard {color: #ef4444; }

            /* Difficulty Badge Pill */
            .path-difficulty-badge {
                padding: 5px 12px;
                border-radius: 20px;
                font-size: 11px;
                font-weight: 700;
                text-transform: uppercase;
                display: flex;
                align-items: center;
                gap: 6px;
                background: rgba(255,255,255,0.05);
                border: 1px solid rgba(255,255,255,0.1);
            }
            .path-difficulty-badge.easy { background: rgba(34, 197, 94, 0.15); color: #22c55e; border-color: rgba(34, 197, 94, 0.3); }
            .path-difficulty-badge.basic { background: rgba(34, 197, 94, 0.15); color: #22c55e; border-color: rgba(34, 197, 94, 0.3); }
            .path-difficulty-badge.medium { background: rgba(245, 158, 11, 0.15); color: #f59e0b; border-color: rgba(245, 158, 11, 0.3); }
            .path-difficulty-badge.intermediate { background: rgba(245, 158, 11, 0.15); color: #f59e0b; border-color: rgba(245, 158, 11, 0.3); }
            .path-difficulty-badge.hard { background: rgba(239, 68, 68, 0.15); color: #ef4444; border-color: rgba(239, 68, 68, 0.3); }
            .path-difficulty-badge.advanced { background: rgba(239, 68, 68, 0.15); color: #ef4444; border-color: rgba(239, 68, 68, 0.3); }

            /* Tab Content */
            .learn-tab-content-thm {display: none; }
            .learn-tab-content-thm.active {display: block; }
            padding: 3px 10px;
            border-radius: 12px;
            font-size: 11px;
            font-weight: 700;
                }

            /* Tab Content */
            .learn-tab-content {display: none; }
            .learn-tab-content.active {display: block; }

            /* Roadmaps Section */
            .roadmaps-grid {display: grid; grid-template-columns: 1fr; gap: 30px; }
            .roadmap-card {
                background: rgba(255,255,255,0.03);
            border: 2px solid rgba(255,255,255,0.1);
            border-radius: 24px;
            padding: 40px;
            position: relative;
            overflow: hidden;
                }
            .roadmap-card::before {
                content: '';
            position: absolute;
            inset: 0;
            background: linear-gradient(135deg, var(--rm-color, #10b981)10, transparent);
            pointer-events: none;
                }
            .roadmap-header {display: block; text-align: center; margin-bottom: 25px; }
            .roadmap-icon {
                width: 70px; height: 70px;
            background: var(--rm-color, #10b981);
            border-radius: 18px;
            display: flex; align-items: center; justify-content: center;
            font-size: 30px; color: #fff;
                }
            .roadmap-info {flex: 1; }
            .roadmap-title {font - size: 1.8rem; font-weight: 700; color: #fff; margin-bottom: 8px; }
            .roadmap-desc {color: rgba(255,255,255,0.6); font-size: 15px; }
            .roadmap-visual {
                display: flex;
            align-items: center;
            gap: 15px;
            padding: 25px;
            background: rgba(0,0,0,0.2);
            border-radius: 16px;
            overflow-x: auto;
                }
            .roadmap-node {
                text - align: center;
            min-width: 140px;
                }
            .roadmap-node-circle {
                width: 80px; height: 80px;
            background: linear-gradient(135deg, var(--rm-color, #10b981), var(--rm-color, #10b981)cc);
            border-radius: 50%;
            display: flex; align-items: center; justify-content: center;
            margin: 0 auto 12px;
            font-size: 28px; color: #fff;
            box-shadow: 0 10px 30px var(--rm-color, #10b981)40;
                }
            .roadmap-node-title {color: #fff; font-weight: 600; font-size: 14px; }
            .roadmap-arrow {color: var(--rm-color, #10b981); font-size: 24px; }
            .roadmap-meta {display: flex; gap: 20px; margin-top: 12px; }
            .roadmap-meta span {color: rgba(255,255,255,0.5); font-size: 13px; display: flex; align-items: center; gap: 6px; }
            .roadmap-meta i {color: var(--rm-color, #10b981); }

            /* Flow Steps Visualization */
            .roadmap-flow {
                display: flex;
            align-items: center;
            padding: 25px;
            background: rgba(0,0,0,0.25);
            border-radius: 16px;
            overflow-x: auto;
            gap: 0;
            margin-bottom: 20px;
                }
            .flow-connector {
                display: flex;
            align-items: center;
            padding: 0 5px;
                }
            .flow-line {
                width: 40px;
            height: 3px;
            background: linear-gradient(90deg, var(--rm-color, #10b981), var(--rm-color, #10b981)80);
            border-radius: 2px;
                }
            .flow-step {
                display: flex;
            align-items: center;
            gap: 12px;
            padding: 15px 20px;
            background: rgba(255,255,255,0.03);
            border: 2px solid rgba(255,255,255,0.1);
            border-radius: 14px;
            cursor: pointer;
            transition: all 0.3s ease;
            min-width: 180px;
                }
            .flow-step:hover {
                transform: translateY(-3px);
            border-color: var(--rm-color, #10b981);
            background: rgba(255,255,255,0.06);
                }
            .flow-step.available {border - color: var(--rm-color, #10b981)60; }
            .flow-step.available .step-circle {
                background: var(--rm-color, #10b981);
            color: #fff;
                }
            .flow-step.completed {border - color: #22c55e60; }
            .flow-step.completed .step-circle {
                background: #22c55e;
            color: #fff;
                }
            .flow-step.locked {
                opacity: 0.5;
            cursor: not-allowed; 
                }
            .flow-step.locked .step-circle {
                background: rgba(255,255,255,0.1);
            color: rgba(255,255,255,0.4);
                }
            .step-circle {
                width: 45px; height: 45px;
            border-radius: 50%;
            display: flex; align-items: center; justify-content: center;
            font-size: 20px;
            flex-shrink: 0;
                }
            .step-content {flex: 1; min-width: 0; }
            .step-label {
                font - size: 11px;
            color: var(--rm-color, #10b981);
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-bottom: 4px;
                }
            .step-path-name {
                font - size: 14px;
            font-weight: 600;
            color: #fff;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
                }
            .roadmap-start-btn {
                width: 100%;
            padding: 14px 20px;
            background: linear-gradient(135deg, var(--rm-color, #10b981), var(--rm-color, #10b981)cc);
            border: none;
            border-radius: 12px;
            color: #fff;
            font-weight: 700;
            font-size: 15px;
            cursor: pointer;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 10px;
            transition: all 0.3s ease;
                }
            .roadmap-start-btn:hover {
                transform: scale(1.02);
            box-shadow: 0 10px 30px var(--rm-color, #10b981)40;
                }
            .roadmap-btn-group {
                display: flex;
            gap: 12px;
            margin-top: 5px;
                }
            .roadmap-start-btn {
                flex: 1.2;
            padding: 14px 20px;
            background: linear-gradient(135deg, var(--rm-color, #10b981), var(--rm-color, #10b981)cc);
            border: none;
            border-radius: 12px;
            color: #fff;
            font-weight: 700;
            font-size: 14px;
            cursor: pointer;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 8px;
            transition: all 0.3s ease;
                }
            .roadmap-start-btn:hover {
                transform: translateY(-2px);
            box-shadow: 0 8px 25px var(--rm-color, #10b981)50;
                }
            .roadmap-view-btn {
                flex: 1;
            padding: 14px 16px;
            background: transparent;
            border: 2px solid var(--rm-color, #10b981)60;
            border-radius: 12px;
            color: var(--rm-color, #10b981);
            font-weight: 600;
            font-size: 14px;
            cursor: pointer;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 8px;
            transition: all 0.3s ease;
                }
            .roadmap-view-btn:hover {
                background: var(--rm-color, #10b981)15;
            border-color: var(--rm-color, #10b981);
            transform: translateY(-2px);
                }

            /* ============ NEW ROADMAP STYLES - Enhanced TryHackMe Style ============ */
            .roadmap-container {
                max - width: 1200px;
            margin: 0 auto;
            padding: 40px 20px;
                }

            /* Header - Premium Enhanced */
            .roadmap-header {
                text - align: center;
            margin-bottom: 70px;
            padding: 50px 40px;
            background: linear-gradient(135deg, rgba(34, 197, 94, 0.15) 0%, rgba(139, 92, 246, 0.1) 50%, rgba(59, 130, 246, 0.15) 100%);
            border-radius: 28px;
            border: 1px solid rgba(255,255,255,0.12);
            position: relative;
            overflow: hidden;
                }
            .roadmap-header::before {
                content: '';
            position: absolute;
            top: -50%;
            left: -50%;
            width: 200%;
            height: 200%;
            background: radial-gradient(circle, rgba(34, 197, 94, 0.1) 0%, transparent 60%);
            animation: headerGlow 8s infinite ease-in-out;
                }
            @keyframes headerGlow {
                0 %, 100 % { transform: translate(0, 0); }
                    50% {transform: translate(30%, 30%); }
                }
            .roadmap-header h1 {
                font - size: 3rem;
            font-weight: 800;
            background: linear-gradient(135deg, #22c55e 0%, #60a5fa 50%, #a78bfa 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            margin-bottom: 18px;
            position: relative;
            z-index: 1;
            text-shadow: 0 0 30px rgba(34, 197, 94, 0.3);
                }
            .roadmap-underline {
                width: 120px;
            height: 5px;
            background: linear-gradient(90deg, #22c55e, #8b5cf6, #3b82f6);
            margin: 0 auto 28px;
            border-radius: 3px;
            animation: underlineGlow 3s infinite ease-in-out;
            position: relative;
            z-index: 1;
                }
            @keyframes underlineGlow {
                0 %, 100 % { box- shadow: 0 0 15px rgba(34, 197, 94, 0.6), 0 0 30px rgba(34, 197, 94, 0.3); }
            50% {box - shadow: 0 0 20px rgba(139, 92, 246, 0.6), 0 0 40px rgba(59, 130, 246, 0.3); }
                }
            .roadmap-header p {
                color: rgba(255,255,255,0.75);
            font-size: 17px;
            max-width: 700px;
            margin: 0 auto;
            line-height: 1.8;
            position: relative;
            z-index: 1;
                }

            /* Section Boxes - Premium Glassmorphism */
            .roadmap-section-box {
                background: linear-gradient(135deg, rgba(30, 41, 59, 0.6) 0%, rgba(15, 23, 42, 0.8) 100%);
            backdrop-filter: blur(15px);
            border: 1px solid rgba(255,255,255,0.12);
            border-radius: 24px;
            padding: 40px 50px;
            text-align: center;
            max-width: 750px;
            margin: 0 auto;
            transition: all 0.4s cubic-bezier(0.175, 0.885, 0.32, 1.275);
            position: relative;
            overflow: hidden;
                }
            .roadmap-section-box::before {
                content: '◆';
            position: absolute;
            top: -8px;
            left: 50%;
            transform: translateX(-50%);
            font-size: 16px;
            color: #22c55e;
            text-shadow: 0 0 10px rgba(34, 197, 94, 0.5);
                }
            .roadmap-section-box:hover {
                border - color: rgba(34, 197, 94, 0.4);
            transform: translateY(-8px) scale(1.01);
            box-shadow: 0 20px 50px rgba(0,0,0,0.3), 0 0 30px rgba(34, 197, 94, 0.1);
                }
            .roadmap-section-box h2 {
                font - size: 1.6rem;
            font-weight: 800;
            color: #fff;
            margin-bottom: 14px;
            background: linear-gradient(90deg, #fff, #94a3b8);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
                }
            .roadmap-section-box p {
                color: rgba(255,255,255,0.65);
            font-size: 15px;
            line-height: 1.8;
                }
            .roadmap-section-box a {
                color: #22c55e;
            text-decoration: none;
            font-weight: 600;
            transition: all 0.3s ease;
                }
            .roadmap-section-box a:hover {
                color: #4ade80;
            text-shadow: 0 0 10px rgba(34, 197, 94, 0.4);
                }

            /* Connectors - Premium Animated */
            .roadmap-connector {
                display: flex;
            flex-direction: column;
            align-items: center;
            height: 70px;
            margin: 18px 0;
                }
            .roadmap-connector .connector-line {
                width: 4px;
            flex: 1;
            background: linear-gradient(180deg, #22c55e 0%, #8b5cf6 50%, #3b82f6 100%);
            border-radius: 2px;
            box-shadow: 0 0 15px rgba(34, 197, 94, 0.3);
                }
            .roadmap-connector i {
                color: #22c55e;
            font-size: 16px;
            animation: arrowPulse 1.5s infinite;
            filter: drop-shadow(0 0 8px rgba(34, 197, 94, 0.5));
                }
            @keyframes arrowPulse {
                0 %, 100 % { opacity: 0.6; transform: translateY(0) scale(1); }
                    50% {opacity: 1; transform: translateY(6px) scale(1.3); }
                }

            /* Path Cards in Roadmap - Enhanced Glassmorphism */
            .roadmap-path-card {
                display: flex;
            align-items: center;
            gap: 18px;
            background: linear-gradient(135deg, rgba(30,41,59,0.95) 0%, rgba(15,23,42,0.95) 100%);
            backdrop-filter: blur(10px);
            border: 2px solid rgba(255,255,255,0.08);
            border-left: 5px solid var(--card-color, #22c55e);
            border-radius: 16px;
            padding: 16px 24px;
            max-width: 550px;
            margin: 0 auto;
            cursor: pointer;
            transition: all 0.4s cubic-bezier(0.175, 0.885, 0.32, 1.275);
            position: relative;
            overflow: visible;
                }
            .roadmap-path-card::before {
                content: '';
            position: absolute;
            inset: 0;
            background: linear-gradient(135deg, var(--card-color, #22c55e)15, transparent 50%);
            opacity: 0;
            transition: opacity 0.3s ease;
                }
            .roadmap-path-card:hover {
                border - color: var(--card-color, #22c55e);
            transform: translateY(-6px) scale(1.02);
            box-shadow: 0 15px 40px rgba(0,0,0,0.3), 0 0 30px rgba(34, 197, 94, 0.15);
                }
            .roadmap-path-card:hover::before {
                opacity: 1;
                }
            .roadmap-path-card.enrolled {
                border - color: #22c55e;
            box-shadow: 0 0 25px rgba(34,197,94,0.25);
                }
            .roadmap-path-card .latest-badge {
                position: absolute;
            top: -10px;
            left: 50%;
            transform: translateX(-50%);
            background: linear-gradient(135deg, #22c55e 0%, #10b981 100%);
            color: #fff;
            padding: 4px 10px;
            border-radius: 12px;
            font-size: 9px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.3px;
            box-shadow: 0 3px 10px rgba(34, 197, 94, 0.5);
            display: flex;
            align-items: center;
            gap: 4px;
            z-index: 10;
                }
            .roadmap-path-card .latest-badge::before {
                content: '✓';
            font-weight: 900;
            font-size: 9px;
                }
            .roadmap-path-card .card-image {
                width: 65px;
            height: 65px;
            border-radius: 14px;
            display: flex;
            align-items: center;
            justify-content: center;
            flex-shrink: 0;
            box-shadow: 0 4px 15px rgba(0,0,0,0.2);
                }
            .roadmap-path-card .card-image i {
                font - size: 28px;
            color: #fff;
                }
            .roadmap-path-card .card-info {
                flex: 1;
            position: relative;
            z-index: 1;
                }
            .roadmap-path-card .card-info h3 {
                font - size: 1.1rem;
            font-weight: 700;
            color: #fff;
            margin-bottom: 6px;
                }
            .roadmap-path-card .card-meta {
                display: flex;
            align-items: center;
            gap: 10px;
                }
            .roadmap-path-card .difficulty {
                font - size: 11px;
            font-weight: 600;
            display: flex;
            align-items: center;
            gap: 4px;
                }
            .roadmap-path-card .difficulty.easy {color: #22c55e; }
            .roadmap-path-card .difficulty.intermediate {color: #f59e0b; }
            .roadmap-path-card .difficulty.hard {color: #ef4444; }
            .roadmap-path-card .type-badge {
                background: rgba(255,255,255,0.1);
            color: rgba(255,255,255,0.7);
            padding: 3px 10px;
            border-radius: 12px;
            font-size: 10px;
            font-weight: 600;
                }
            .roadmap-path-card .card-progress {
                width: 44px;
            height: 44px;
            background: #1a1a2e;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 11px;
            font-weight: 700;
            color: #22c55e;
            flex-shrink: 0;
                }

            /* Career Branch Connector */
            .career-branch-connector {
                display: flex;
            flex-direction: column;
            align-items: center;
            margin: 30px 0;
            position: relative;
            height: 80px;
                }
            .career-branch-connector .branch-line-vertical {
                width: 2px;
            height: 30px;
            background: rgba(255,255,255,0.2);
                }
            .career-branch-connector .branch-line-horizontal {
                width: 70%;
            max-width: 800px;
            height: 2px;
            background: rgba(255,255,255,0.2);
                }
            .career-branch-connector .branch-ends {
                display: flex;
            justify-content: space-between;
            width: 70%;
            max-width: 800px;
                }
            .career-branch-connector .branch-drop {
                width: 2px;
            height: 30px;
            background: rgba(255,255,255,0.2);
                }

            /* Career Columns */
            .career-columns {
                display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 30px;
            margin-top: 20px;
                }
            @media (max-width: 1000px) {
                    .career - columns {grid - template - columns: 1fr; gap: 40px; }
                }
            .career-column {
                display: flex;
            flex-direction: column;
            gap: 15px;
                }
            .column-header {
                text - align: center;
            margin-bottom: 15px;
                }
            .column-header h3 {
                font - size: 1.2rem;
            font-weight: 700;
            color: #fff;
            margin-bottom: 8px;
                }
            .column-header p {
                color: rgba(255,255,255,0.5);
            font-size: 13px;
            line-height: 1.5;
                }
            .column-header a {
                color: #3b82f6;
            text-decoration: none;
                }

            /* Career Path Cards */
            .career-path-card {
                display: flex;
            align-items: center;
            gap: 12px;
            background: rgba(30,41,59,0.7);
            border: 1px solid rgba(255,255,255,0.08);
            border-radius: 12px;
            padding: 10px 15px;
            cursor: pointer;
            transition: all 0.3s ease;
            position: relative;
                }
            .career-path-card:hover {
                border - color: var(--card-color, #3b82f6);
            transform: translateX(5px);
            background: rgba(30,41,59,0.9);
                }
            .career-card-image {
                width: 50px;
            height: 50px;
            border-radius: 10px;
            display: flex;
            align-items: center;
            justify-content: center;
            flex-shrink: 0;
                }
            .career-card-image i {
                font - size: 22px;
            color: #fff;
                }
            .career-card-info {
                flex: 1;
                }
            .career-card-info h4 {
                font - size: 0.95rem;
            font-weight: 600;
            color: #fff;
            margin-bottom: 4px;
                }
            .career-card-meta {
                display: flex;
            align-items: center;
            gap: 8px;
                }
            .career-card-meta .difficulty {
                font - size: 10px;
            font-weight: 600;
            display: flex;
            align-items: center;
            gap: 3px;
            text-transform: capitalize;
                }
            .career-card-meta .difficulty.easy {color: #22c55e; }
            .career-card-meta .difficulty.intermediate {color: #f59e0b; }
            .career-card-meta .difficulty.hard {color: #ef4444; }
            .career-card-meta .type-badge {
                background: rgba(255,255,255,0.1);
            color: rgba(255,255,255,0.6);
            padding: 2px 8px;
            border-radius: 10px;
            font-size: 9px;
            font-weight: 600;
                }
            .career-card-progress {
                width: 36px;
            height: 36px;
            background: #1a1a2e;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 10px;
            font-weight: 700;
            color: #22c55e;
            flex-shrink: 0;
                }

            /* What's Next Section */
            .whats-next-section {
                text - align: center;
            margin-top: 30px;
            padding: 40px;
                }
            .whats-next-section h2 {
                font - size: 1.5rem;
            font-weight: 700;
            color: #fff;
            margin-bottom: 12px;
                }
            .whats-next-section p {
                color: rgba(255,255,255,0.5);
            font-size: 14px;
            margin-bottom: 25px;
                }
            .explore-btn {
                background: transparent;
            border: 2px solid #22c55e;
            color: #22c55e;
            padding: 12px 30px;
            border-radius: 8px;
            font-size: 14px;
            font-weight: 700;
            cursor: pointer;
            transition: all 0.3s ease;
                }
            .explore-btn:hover {
                background: #22c55e;
            color: #000;
                }

            /* Paths Grid - TryHackMe Style */
            .paths-grid {
                display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 24px;
                }
            @media (max-width: 1400px) {
                    .paths - grid {grid - template - columns: repeat(3, 1fr); }
                }
            @media (max-width: 1000px) {
                    .paths - grid {grid - template - columns: repeat(2, 1fr); }
                }
            @media (max-width: 600px) {
                    .paths - grid {grid - template - columns: 1fr; }
                }

            .path-card {
                background: linear-gradient(145deg, rgba(30, 41, 59, 0.95) 0%, rgba(15, 23, 42, 0.98) 100%);
            border-radius: 18px;
            overflow: hidden;
            cursor: pointer;
            position: relative;
            transition: all 0.4s cubic-bezier(0.175, 0.885, 0.32, 1.275);
            box-shadow: 0 6px 25px rgba(0,0,0,0.25);
            border: 1px solid rgba(255,255,255,0.08);
                }
            .path-card::before {
                content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 4px;
            background: linear-gradient(90deg, var(--path-color), #8b5cf6, #ec4899);
            opacity: 0;
            transition: opacity 0.3s ease;
            z-index: 10;
                }
            .path-card:hover {
                transform: translateY(-12px) scale(1.02);
            box-shadow: 0 25px 50px rgba(0,0,0,0.35), 0 0 40px var(--path-color)30;
            border-color: var(--path-color)60;
                }
            .path-card:hover::before {
                opacity: 1;
                }
            .path-card.in-progress {
                border: 2px solid var(--path-color);
            box-shadow: 0 6px 25px rgba(0,0,0,0.25), 0 0 20px var(--path-color)20;
                }

            /* Image/Illustration Area */
            .path-image-area {
                height: 160px;
            background: var(--path-color);
            display: flex;
            align-items: center;
            justify-content: center;
            position: relative;
            overflow: hidden;
                }
            .path-image-area::before {
                content: '';
            position: absolute;
            inset: 0;
            background: linear-gradient(135deg, rgba(255,255,255,0.2) 0%, transparent 50%);
                }
            .path-image-area i {
                font - size: 64px;
            color: rgba(255,255,255,0.9);
            z-index: 1;
                }

            /* Progress Circle */
            .path-progress-circle {
                position: absolute;
            top: 12px;
            right: 12px;
            width: 44px;
            height: 44px;
            background: #1a1a2e;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 11px;
            font-weight: 700;
            color: #22c55e;
            z-index: 5;
            box-shadow: 0 2px 8px rgba(0,0,0,0.3);
                }

            /* Card Content */
            .path-content {
                padding: 22px;
            background: transparent;
            border-left: 4px solid var(--path-color);
                }
            .path-name {
                font - size: 1.15rem;
            font-weight: 700;
            color: #fff;
            margin-bottom: 10px;
            line-height: 1.3;
            transition: color 0.3s ease;
                }
            .path-card:hover .path-name {
                color: var(--path-color);
                }
            .path-description {
                color: rgba(255,255,255,0.55);
            font-size: 13px;
            line-height: 1.6;
            margin-bottom: 16px;
            display: -webkit-box;
            -webkit-line-clamp: 2;
            -webkit-box-orient: vertical;
            overflow: hidden;
            min-height: 42px;
                }

            /* Difficulty Badge */
            .path-difficulty {
                display: inline-flex;
            align-items: center;
            gap: 6px;
            font-size: 12px;
            font-weight: 600;
                }
            .path-difficulty i {
                font - size: 10px;
                }
            .path-difficulty.easy {color: #22c55e; }
            .path-difficulty.basic {color: #22c55e; }
            .path-difficulty.intermediate {color: #f59e0b; }
            .path-difficulty.medium {color: #f59e0b; }
            .path-difficulty.hard {color: #ef4444; }
            .path-difficulty.advanced {color: #ef4444; }

            /* Hide old path-icon, path-stats */
            .path-icon {display: none; }
            .path-stats {display: none; }
            .path-btn {
                flex: 1.2;
            padding: 14px 20px;
            background: linear-gradient(135deg, var(--path-color), var(--path-color)cc);
            border: none;
            border-radius: 12px;
            color: #fff;
            font-weight: 700;
            font-size: 14px;
            cursor: pointer;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 8px;
            transition: all 0.3s ease;
                }
            .path-btn:hover {
                transform: translateY(-2px);
            box-shadow: 0 8px 25px var(--path-color)50;
                }
            .path-view-btn {
                flex: 1;
            padding: 14px 16px;
            background: transparent;
            border: 2px solid var(--path-color)60;
            border-radius: 12px;
            color: var(--path-color);
            font-weight: 600;
            font-size: 14px;
            cursor: pointer;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 8px;
            transition: all 0.3s ease;
                }
            .path-view-btn:hover {
                background: var(--path-color)15;
            border-color: var(--path-color);
            transform: translateY(-2px);
                }
            .path-btn-group {
                display: flex;
            gap: 12px;
            margin-top: 5px;
                }

            /* Networks Grid - TryHackMe Design */
            .networks-filter-bar {
                display: flex;
            gap: 15px;
            margin-bottom: 30px;
            flex-wrap: wrap;
                }
            .net-filter {
                padding: 8px 15px;
            border: 1px solid rgba(255,255,255,0.1);
            background: rgba(255,255,255,0.05);
            border-radius: 6px;
            color: #fff;
            font-size: 14px;
            outline: none;
                }
            .networks-grid {
                display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 25px;
                }
            @media (max-width: 1400px) { .networks - grid {grid - template - columns: repeat(3, 1fr); } }
            @media (max-width: 1000px) { .networks - grid {grid - template - columns: repeat(2, 1fr); } }
            @media (max-width: 650px) { .networks - grid {grid - template - columns: 1fr; } }

            .network-card-new {
                background: #fff;
            border: 1px solid #e5e7eb;
            border-radius: 8px;
            padding: 20px;
            display: flex;
            flex-direction: column;
            justify-content: space-between;
            min-height: 280px;
            cursor: pointer;
            transition: all 0.3s ease;
            position: relative;
                }
            .network-card-new:hover {
                box - shadow: 0 10px 25px rgba(0,0,0,0.08);
            transform: translateY(-3px);
            border-color: #d1d5db;
                }
            .net-card-top {
                margin - bottom: 20px;
                }
            .net-icon-box {
                font - size: 32px;
            color: #1f2937;
            margin-bottom: 15px;
                }
            .net-title {
                font - size: 1.1rem;
            font-weight: 700;
            color: #111827;
            margin-bottom: 10px;
                }
            .net-desc {
                color: #6b7280;
            font-size: 13px;
            line-height: 1.6;
            display: -webkit-box;
            -webkit-line-clamp: 4;
            -webkit-box-orient: vertical;
            overflow: hidden;
                }
            .net-card-bottom {
                border - top: 1px solid #f3f4f6;
            padding-top: 15px;
            display: flex;
            flex-direction: column;
            gap: 12px;
                }
            .net-difficulty {
                display: flex;
            align-items: center;
            gap: 6px;
            font-size: 13px;
            font-weight: 600;
                }
            .net-difficulty.easy {color: #10b981; }
            .net-difficulty.medium {color: #f59e0b; }
            .net-difficulty.hard {color: #ef4444; }
            .net-difficulty.insane {color: #7c3aed; }
            .net-badges {
                display: flex;
            gap: 8px;
            flex-wrap: wrap;
                }
            .net-badge {
                font - size: 11px;
            padding: 4px 10px;
            border-radius: 20px;
            font-weight: 700;
            text-transform: uppercase;
                }
            .net-badge.premium {
                background: #1f2937;
            color: #fff;
                }
            .net-badge.free {
                background: #e5e7eb;
            color: #374151;
                }
            .net-badge.streak {
                background: #059669;
            color: #fff;
            display: flex;
            align-items: center;
            gap: 4px;
                }

            /* Modules Grid */
            .modules-grid {
                display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 25px;
                }
            .module-card {
                background: rgba(255,255,255,0.03);
            border: 1px solid rgba(255,255,255,0.1);
            border-radius: 20px;
            padding: 25px;
            transition: all 0.3s ease;
            cursor: pointer;
                }
            .module-card:hover {
                border - color: var(--mod-color, #f97316);
            transform: translateY(-5px);
                }
            .module-header {display: flex; align-items: center; gap: 15px; margin-bottom: 15px; }
            .module-icon {
                width: 50px; height: 50px;
            background: var(--mod-color, #f97316)30;
            border-radius: 12px;
            display: flex; align-items: center; justify-content: center;
            font-size: 22px; color: var(--mod-color, #f97316);
                }
            .module-title {font - size: 1.2rem; font-weight: 700; color: #fff; }
            .module-desc {color: rgba(255,255,255,0.5); font-size: 13px; margin-bottom: 15px; }
            .module-skills {display: flex; gap: 8px; flex-wrap: wrap; }
            .module-skill {
                background: rgba(255,255,255,0.05);
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 11px;
            color: rgba(255,255,255,0.6);
                }

            /* Modules Filter Bar */
            .modules-filter-bar {
                display: flex;
            gap: 12px;
            margin-bottom: 25px;
            flex-wrap: wrap;
                }
            .modules-filter-bar select {
                padding: 12px 20px;
            background: rgba(255,255,255,0.05);
            border: 2px solid rgba(255,255,255,0.1);
            border-radius: 12px;
            color: #fff;
            font-size: 14px;
            cursor: pointer;
            min-width: 160px;
                }
            .modules-filter-bar select:focus {
                outline: none;
            border-color: #f97316;
                }
            .modules-filter-bar select option {
                background: #1a1a2e;
                }

            /* ============ NEW MODULES STYLES - Professional Dark Theme ============ */
            .modules-header {
                margin - bottom: 40px;
            text-align: center;
            padding: 40px 20px;
            background: linear-gradient(135deg, rgba(59, 130, 246, 0.1) 0%, rgba(139, 92, 246, 0.1) 100%);
            border-radius: 20px;
            border: 1px solid rgba(255,255,255,0.1);
                }
            .modules-header h1 {
                font - size: 2.5rem;
            font-weight: 800;
            background: linear-gradient(135deg, #fff 0%, #94a3b8 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            margin-bottom: 12px;
                }
            .modules-header p {
                color: rgba(255,255,255,0.6);
            font-size: 16px;
            max-width: 500px;
            margin: 0 auto;
                }

            /* Modules Filter Bar - Same as Paths */
            .modules-filter-bar-new {
                display: flex;
            gap: 20px;
            margin-bottom: 30px;
            flex-wrap: wrap;
            align-items: center;
                }
            .modules-filter-bar-new .search-box {
                flex: 1;
            min-width: 180px;
            max-width: 280px;
            position: relative;
                }
            .modules-filter-bar-new .search-box i {
                position: absolute;
            left: 12px;
            top: 50%;
            transform: translateY(-50%);
            color: rgba(255,255,255,0.4);
            font-size: 13px;
                }
            .modules-filter-bar-new .search-box input {
                width: 100%;
            padding: 10px 10px 10px 36px;
            background: rgba(255,255,255,0.05);
            border: 1px solid rgba(255,255,255,0.1);
            border-radius: 8px;
            color: #fff;
            font-size: 13px;
            transition: all 0.3s ease;
                }

            /* Paths Grid - TryHackMe Style */
            .paths-grid {
                display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 24px;
                }
            @media (max-width: 1400px) {
                    .paths - grid {grid - template - columns: repeat(3, 1fr); }
                }
            @media (max-width: 1000px) {
                    .paths - grid {grid - template - columns: repeat(2, 1fr); }
                }
            @media (max-width: 600px) {
                    .paths - grid {grid - template - columns: 1fr; }
                }

            .path-card {
                background: linear-gradient(145deg, rgba(30, 41, 59, 0.95) 0%, rgba(15, 23, 42, 0.98) 100%);
            border-radius: 18px;
            overflow: hidden;
            cursor: pointer;
            position: relative;
            transition: all 0.4s cubic-bezier(0.175, 0.885, 0.32, 1.275);
            box-shadow: 0 6px 25px rgba(0,0,0,0.25);
            border: 1px solid rgba(255,255,255,0.08);
                }
            .path-card::before {
                content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 4px;
            background: linear-gradient(90deg, var(--path-color), #8b5cf6, #ec4899);
            opacity: 0;
            transition: opacity 0.3s ease;
            z-index: 10;
                }
            .path-card:hover {
                transform: translateY(-12px) scale(1.02);
            box-shadow: 0 25px 50px rgba(0,0,0,0.35), 0 0 40px var(--path-color)30;
            border-color: var(--path-color)60;
                }
            .path-card:hover::before {
                opacity: 1;
                }
            .path-card.in-progress {
                border: 2px solid var(--path-color);
            box-shadow: 0 6px 25px rgba(0,0,0,0.25), 0 0 20px var(--path-color)20;
                }

            /* Image/Illustration Area */
            .path-image-area {
                height: 160px;
            background: var(--path-color);
            display: flex;
            align-items: center;
            justify-content: center;
            position: relative;
            overflow: hidden;
                }
            .path-image-area::before {
                content: '';
            position: absolute;
            inset: 0;
            background: linear-gradient(135deg, rgba(255,255,255,0.2) 0%, transparent 50%);
                }
            .path-image-area i {
                font - size: 64px;
            color: rgba(255,255,255,0.9);
            z-index: 1;
                }

            /* Progress Circle */
            .path-progress-circle {
                position: absolute;
            top: 12px;
            right: 12px;
            width: 44px;
            height: 44px;
            background: #1a1a2e;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 11px;
            font-weight: 700;
            color: #22c55e;
            z-index: 5;
            box-shadow: 0 2px 8px rgba(0,0,0,0.3);
                }

            /* Card Content */
            .path-content {
                padding: 22px;
            background: transparent;
            border-left: 4px solid var(--path-color);
                }
            .path-name {
                font - size: 1.15rem;
            font-weight: 700;
            color: #fff;
            margin-bottom: 10px;
            line-height: 1.3;
            transition: color 0.3s ease;
                }
            .path-card:hover .path-name {
                color: var(--path-color);
                }
            .path-description {
                color: rgba(255,255,255,0.55);
            font-size: 13px;
            line-height: 1.6;
            margin-bottom: 16px;
            display: -webkit-box;
            -webkit-line-clamp: 2;
            -webkit-box-orient: vertical;
            overflow: hidden;
            min-height: 42px;
                }

            /* Difficulty Badge */
            .path-difficulty {
                display: inline-flex;
            align-items: center;
            gap: 6px;
            font-size: 12px;
            font-weight: 600;
                }
            .path-difficulty i {
                font - size: 10px;
                }
            .path-difficulty.easy {color: #22c55e; }
            .path-difficulty.basic {color: #22c55e; }
            .path-difficulty.intermediate {color: #f59e0b; }
            .path-difficulty.medium {color: #f59e0b; }
            .path-difficulty.hard {color: #ef4444; }
            .path-difficulty.advanced {color: #ef4444; }

            /* Hide old path-icon, path-stats */
            .path-icon {display: none; }
            .path-stats {display: none; }
            .path-btn {
                flex: 1.2;
            padding: 14px 20px;
            background: linear-gradient(135deg, var(--path-color), var(--path-color)cc);
            border: none;
            border-radius: 12px;
            color: #fff;
            font-weight: 700;
            font-size: 14px;
            cursor: pointer;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 8px;
            transition: all 0.3s ease;
                }
            .path-btn:hover {
                transform: translateY(-2px);
            box-shadow: 0 8px 25px var(--path-color)50;
                }
            .path-view-btn {
                flex: 1;
            padding: 14px 16px;
            background: transparent;
            border: 2px solid var(--path-color)60;
            border-radius: 12px;
            color: var(--path-color);
            font-weight: 600;
            font-size: 14px;
            cursor: pointer;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 8px;
            transition: all 0.3s ease;
                }
            .path-view-btn:hover {
                background: var(--path-color)15;
            border-color: var(--path-color);
            transform: translateY(-2px);
                }
            .path-btn-group {
                display: flex;
            gap: 12px;
            margin-top: 5px;
                }

            /* Networks Grid - TryHackMe Design */
            .networks-filter-bar {
                display: flex;
            gap: 15px;
            margin-bottom: 30px;
            flex-wrap: wrap;
                }
            .net-filter {
                padding: 8px 15px;
            border: 1px solid rgba(255,255,255,0.1);
            background: rgba(255,255,255,0.05);
            border-radius: 6px;
            color: #fff;
            font-size: 14px;
            outline: none;
                }
            .networks-grid {
                display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 25px;
                }
            @media (max-width: 1400px) { .networks - grid {grid - template - columns: repeat(3, 1fr); } }
            @media (max-width: 1000px) { .networks - grid {grid - template - columns: repeat(2, 1fr); } }
            @media (max-width: 650px) { .networks - grid {grid - template - columns: 1fr; } }

            .network-card-new {
                background: #fff;
            border: 1px solid #e5e7eb;
            border-radius: 8px;
            padding: 20px;
            display: flex;
            flex-direction: column;
            justify-content: space-between;
            min-height: 280px;
            cursor: pointer;
            transition: all 0.3s ease;
            position: relative;
                }
            .network-card-new:hover {
                box - shadow: 0 10px 25px rgba(0,0,0,0.08);
            transform: translateY(-3px);
            border-color: #d1d5db;
                }
            .net-card-top {
                margin - bottom: 20px;
                }
            .net-icon-box {
                font - size: 32px;
            color: #1f2937;
            margin-bottom: 15px;
                }
            .net-title {
                font - size: 1.1rem;
            font-weight: 700;
            color: #111827;
            margin-bottom: 10px;
                }
            .net-desc {
                color: #6b7280;
            font-size: 13px;
            line-height: 1.6;
            display: -webkit-box;
            -webkit-line-clamp: 4;
            -webkit-box-orient: vertical;
            overflow: hidden;
                }
            .net-card-bottom {
                border - top: 1px solid #f3f4f6;
            padding-top: 15px;
            display: flex;
            flex-direction: column;
            gap: 12px;
                }
            .net-difficulty {
                display: flex;
            align-items: center;
            gap: 6px;
            font-size: 13px;
            font-weight: 600;
                }
            .net-difficulty.easy {color: #10b981; }
            .net-difficulty.medium {color: #f59e0b; }
            .net-difficulty.hard {color: #ef4444; }
            .net-difficulty.insane {color: #7c3aed; }
            .net-badges {
                display: flex;
            gap: 8px;
            flex-wrap: wrap;
                }
            .net-badge {
                font - size: 11px;
            padding: 4px 10px;
            border-radius: 20px;
            font-weight: 700;
            text-transform: uppercase;
                }
            .net-badge.premium {
                background: #1f2937;
            color: #fff;
                }
            .net-badge.free {
                background: #e5e7eb;
            color: #374151;
                }
            .net-badge.streak {
                background: #059669;
            color: #fff;
            display: flex;
            align-items: center;
            gap: 4px;
                }

            /* Modules Grid */
            .modules-grid {
                display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 25px;
                }
            .module-card {
                background: rgba(255,255,255,0.03);
            border: 1px solid rgba(255,255,255,0.1);
            border-radius: 20px;
            padding: 25px;
            transition: all 0.3s ease;
            cursor: pointer;
                }
            .module-card:hover {
                border - color: var(--mod-color, #f97316);
            transform: translateY(-5px);
                }
            .module-header {display: flex; align-items: center; gap: 15px; margin-bottom: 15px; }
            .module-icon {
                width: 50px; height: 50px;
            background: var(--mod-color, #f97316)30;
            border-radius: 12px;
            display: flex; align-items: center; justify-content: center;
            font-size: 22px; color: var(--mod-color, #f97316);
                }
            .module-title {font - size: 1.2rem; font-weight: 700; color: #fff; }
            .module-desc {color: rgba(255,255,255,0.5); font-size: 13px; margin-bottom: 15px; }
            .module-skills {display: flex; gap: 8px; flex-wrap: wrap; }
            .module-skill {
                background: rgba(255,255,255,0.05);
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 11px;
            color: rgba(255,255,255,0.6);
                }

            /* Modules Filter Bar */
            .modules-filter-bar {
                display: flex;
            gap: 12px;
            margin-bottom: 25px;
            flex-wrap: wrap;
                }
            .modules-filter-bar select {
                padding: 12px 20px;
            background: rgba(255,255,255,0.05);
            border: 2px solid rgba(255,255,255,0.1);
            border-radius: 12px;
            color: #fff;
            font-size: 14px;
            cursor: pointer;
            min-width: 160px;
                }
            .modules-filter-bar select:focus {
                outline: none;
            border-color: #f97316;
                }
            .modules-filter-bar select option {
                background: #1a1a2e;
                }

            /* ============ NEW MODULES STYLES - Professional Dark Theme ============ */
            .modules-header {
                margin - bottom: 40px;
            text-align: center;
            padding: 40px 20px;
            background: linear-gradient(135deg, rgba(59, 130, 246, 0.1) 0%, rgba(139, 92, 246, 0.1) 100%);
            border-radius: 20px;
            border: 1px solid rgba(255,255,255,0.1);
                }
            .modules-header h1 {
                font - size: 2.5rem;
            font-weight: 800;
            background: linear-gradient(135deg, #fff 0%, #94a3b8 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            margin-bottom: 12px;
                }
            .modules-header p {
                color: rgba(255,255,255,0.6);
            font-size: 16px;
            max-width: 500px;
            margin: 0 auto;
                }

            /* Modules Filter Bar - Same as Paths */
            .modules-filter-bar-new {
                display: flex;
            gap: 20px;
            margin-bottom: 30px;
            flex-wrap: wrap;
            align-items: center;
                }
            .modules-filter-bar-new .search-box {
                flex: 1;
            min-width: 180px;
            max-width: 280px;
            position: relative;
                }
            .modules-filter-bar-new .search-box i {
                position: absolute;
            left: 12px;
            top: 50%;
            transform: translateY(-50%);
            color: rgba(255,255,255,0.4);
            font-size: 13px;
                }
            .modules-filter-bar-new .search-box input {
                width: 100%;
            padding: 10px 10px 10px 36px;
            background: rgba(255,255,255,0.05);
            border: 1px solid rgba(255,255,255,0.1);
            border-radius: 8px;
            color: #fff;
            font-size: 13px;
            transition: all 0.3s ease;
                }

            /* Paths Grid - TryHackMe Style */
            .paths-grid {
                display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 24px;
                }
            @media (max-width: 1400px) {
                    .paths - grid {grid - template - columns: repeat(3, 1fr); }
                }
            @media (max-width: 1000px) {
                    .paths - grid {grid - template - columns: repeat(2, 1fr); }
                }
            @media (max-width: 600px) {
                    .paths - grid {grid - template - columns: 1fr; }
                }

            .path-card {
                background: linear-gradient(145deg, rgba(30, 41, 59, 0.95) 0%, rgba(15, 23, 42, 0.98) 100%);
            border-radius: 18px;
            overflow: hidden;
            cursor: pointer;
            position: relative;
            transition: all 0.4s cubic-bezier(0.175, 0.885, 0.32, 1.275);
            box-shadow: 0 6px 25px rgba(0,0,0,0.25);
            border: 1px solid rgba(255,255,255,0.08);
                }
            .path-card::before {
                content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 4px;
            background: linear-gradient(90deg, var(--path-color), #8b5cf6, #ec4899);
            opacity: 0;
            transition: opacity 0.3s ease;
            z-index: 10;
                }
            .path-card:hover {
                transform: translateY(-12px) scale(1.02);
            box-shadow: 0 25px 50px rgba(0,0,0,0.35), 0 0 40px var(--path-color)30;
            border-color: var(--path-color)60;
                }
            .path-card:hover::before {
                opacity: 1;
                }
            .path-card.in-progress {
                border: 2px solid var(--path-color);
            box-shadow: 0 6px 25px rgba(0,0,0,0.25), 0 0 20px var(--path-color)20;
                }

            /* Image/Illustration Area */
            .path-image-area {
                height: 160px;
            background: var(--path-color);
            display: flex;
            align-items: center;
            justify-content: center;
            position: relative;
            overflow: hidden;
                }
            .path-image-area::before {
                content: '';
            position: absolute;
            inset: 0;
            background: linear-gradient(135deg, rgba(255,255,255,0.2) 0%, transparent 50%);
                }
            .path-image-area i {
                font - size: 64px;
            color: rgba(255,255,255,0.9);
            z-index: 1;
                }

            /* Progress Circle */
            .path-progress-circle {
                position: absolute;
            top: 12px;
            right: 12px;
            width: 44px;
            height: 44px;
            background: #1a1a2e;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 11px;
            font-weight: 700;
            color: #22c55e;
            z-index: 5;
            box-shadow: 0 2px 8px rgba(0,0,0,0.3);
                }

            /* Card Content */
            .path-content {
                padding: 22px;
            background: transparent;
            border-left: 4px solid var(--path-color);
                }
            .path-name {
                font - size: 1.15rem;
            font-weight: 700;
            color: #fff;
            margin-bottom: 10px;
            line-height: 1.3;
            transition: color 0.3s ease;
                }
            .path-card:hover .path-name {
                color: var(--path-color);
                }
            .path-description {
                color: rgba(255,255,255,0.55);
            font-size: 13px;
            line-height: 1.6;
            margin-bottom: 16px;
            display: -webkit-box;
            -webkit-line-clamp: 2;
            -webkit-box-orient: vertical;
            overflow: hidden;
            min-height: 42px;
                }

            /* Difficulty Badge */
            .path-difficulty {
                display: inline-flex;
            align-items: center;
            gap: 6px;
            font-size: 12px;
            font-weight: 600;
                }
            .path-difficulty i {
                font - size: 10px;
                }
            .path-difficulty.easy {color: #22c55e; }
            .path-difficulty.basic {color: #22c55e; }
            .path-difficulty.intermediate {color: #f59e0b; }
            .path-difficulty.medium {color: #f59e0b; }
            .path-difficulty.hard {color: #ef4444; }
            .path-difficulty.advanced {color: #ef4444; }

            /* Hide old path-icon, path-stats */
            .path-icon {display: none; }
            .path-stats {display: none; }
            .path-btn {
                flex: 1.2;
            padding: 14px 20px;
            background: linear-gradient(135deg, var(--path-color), var(--path-color)cc);
            border: none;
            border-radius: 12px;
            color: #fff;
            font-weight: 700;
            font-size: 14px;
            cursor: pointer;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 8px;
            transition: all 0.3s ease;
                }
            .path-btn:hover {
                transform: translateY(-2px);
            box-shadow: 0 8px 25px var(--path-color)50;
                }
            .path-view-btn {
                flex: 1;
            padding: 14px 16px;
            background: transparent;
            border: 2px solid var(--path-color)60;
            border-radius: 12px;
            color: var(--path-color);
            font-weight: 600;
            font-size: 14px;
            cursor: pointer;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 8px;
            transition: all 0.3s ease;
                }
            .path-view-btn:hover {
                background: var(--path-color)15;
            border-color: var(--path-color);
            transform: translateY(-2px);
                }
            .path-btn-group {
                display: flex;
            gap: 12px;
            margin-top: 5px;
                }

            /* Networks Grid - TryHackMe Design */
            .networks-filter-bar {
                display: flex;
            gap: 15px;
            margin-bottom: 30px;
            flex-wrap: wrap;
                }
            .net-filter {
                padding: 8px 15px;
            border: 1px solid rgba(255,255,255,0.1);
            background: rgba(255,255,255,0.05);
            border-radius: 6px;
            color: #fff;
            font-size: 14px;
            outline: none;
                }
            .networks-grid {
                display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 25px;
                }
            @media (max-width: 1400px) { .networks - grid {grid - template - columns: repeat(3, 1fr); } }
            @media (max-width: 1000px) { .networks - grid {grid - template - columns: repeat(2, 1fr); } }
            @media (max-width: 650px) { .networks - grid {grid - template - columns: 1fr; } }

            .network-card-new {
                background: #fff;
            border: 1px solid #e5e7eb;
            border-radius: 8px;
            padding: 20px;
            display: flex;
            flex-direction: column;
            justify-content: space-between;
            min-height: 280px;
            cursor: pointer;
            transition: all 0.3s ease;
            position: relative;
                }
            .network-card-new:hover {
                box - shadow: 0 10px 25px rgba(0,0,0,0.08);
            transform: translateY(-3px);
            border-color: #d1d5db;
                }
            .net-card-top {
                margin - bottom: 20px;
                }
            .net-icon-box {
                font - size: 32px;
            color: #1f2937;
            margin-bottom: 15px;
                }
            .net-title {
                font - size: 1.1rem;
            font-weight: 700;
            color: #111827;
            margin-bottom: 10px;
                }
            .net-desc {
                color: #6b7280;
            font-size: 13px;
            line-height: 1.6;
            display: -webkit-box;
            -webkit-line-clamp: 4;
            -webkit-box-orient: vertical;
            overflow: hidden;
                }
            .net-card-bottom {
                border - top: 1px solid #f3f4f6;
            padding-top: 15px;
            display: flex;
            flex-direction: column;
            gap: 12px;
                }
            .net-difficulty {
                display: flex;
            align-items: center;
            gap: 6px;
            font-size: 13px;
            font-weight: 600;
                }
            .net-difficulty.easy {color: #10b981; }
            .net-difficulty.medium {color: #f59e0b; }
            .net-difficulty.hard {color: #ef4444; }
            .net-difficulty.insane {color: #7c3aed; }
            .net-badges {
                display: flex;
            gap: 8px;
            flex-wrap: wrap;
                }
            .net-badge {
                font - size: 11px;
            padding: 4px 10px;
            border-radius: 20px;
            font-weight: 700;
            text-transform: uppercase;
                }
            .net-badge.premium {
                background: #1f2937;
            color: #fff;
                }
            .net-badge.free {
                background: #e5e7eb;
            color: #374151;
                }
            .net-badge.streak {
                background: #059669;
            color: #fff;
            display: flex;
            align-items: center;
            gap: 4px;
                }

            /* Modules Grid */
            .modules-grid {
                display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 25px;
                }
            .module-card {
                background: rgba(30, 41, 59, 0.4);
                backdrop-filter: blur(10px);
                -webkit-backdrop-filter: blur(10px);
                border: 1px solid rgba(255, 255, 255, 0.08);
                border-radius: 20px;
                padding: 25px;
                transition: all 0.3s ease;
                cursor: pointer;
                box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            }
            .module-card:hover {
                border - color: var(--mod-color, #f97316);
            transform: translateY(-5px);
                }
            .module-header {display: flex; align-items: center; gap: 15px; margin-bottom: 15px; }
            .module-icon {
                width: 50px; height: 50px;
            background: var(--mod-color, #f97316)30;
            border-radius: 12px;
            display: flex; align-items: center; justify-content: center;
            font-size: 22px; color: var(--mod-color, #f97316);
                }
            .module-title {font - size: 1.2rem; font-weight: 700; color: #fff; }
            .module-desc {color: rgba(255,255,255,0.5); font-size: 13px; margin-bottom: 15px; }
            .module-skills {display: flex; gap: 8px; flex-wrap: wrap; }
            .module-skill {
                background: rgba(255,255,255,0.05);
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 11px;
            color: rgba(255,255,255,0.6);
                }

            /* Modules Filter Bar */
            .modules-filter-bar {
                display: flex;
            gap: 12px;
            margin-bottom: 25px;
            flex-wrap: wrap;
                }
            .modules-filter-bar select {
                padding: 12px 20px;
            background: rgba(255,255,255,0.05);
            border: 2px solid rgba(255,255,255,0.1);
            border-radius: 12px;
            color: #fff;
            font-size: 14px;
            cursor: pointer;
            min-width: 160px;
                }
            .modules-filter-bar select:focus {
                outline: none;
            border-color: #f97316;
                }
            .modules-filter-bar select option {
                background: #1a1a2e;
                }

            /* ============ NEW MODULES STYLES - Professional Dark Theme ============ */
            .modules-header {
                margin - bottom: 40px;
            text-align: center;
            padding: 40px 20px;
            background: linear-gradient(135deg, rgba(59, 130, 246, 0.1) 0%, rgba(139, 92, 246, 0.1) 100%);
            border-radius: 20px;
            border: 1px solid rgba(255,255,255,0.1);
                }
            .modules-header h1 {
                font - size: 2.5rem;
            font-weight: 800;
            background: linear-gradient(135deg, #fff 0%, #94a3b8 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            margin-bottom: 12px;
                }
            .modules-header p {
                color: rgba(255,255,255,0.6);
            font-size: 16px;
            max-width: 500px;
            margin: 0 auto;
                }

            /* Modules Filter Bar - Same as Paths */
            .modules-filter-bar-new {
                display: flex;
            gap: 20px;
            margin-bottom: 30px;
            flex-wrap: wrap;
            align-items: center;
                }
            .modules-filter-bar-new .search-box {
                flex: 1;
            min-width: 180px;
            max-width: 280px;
            position: relative;
                }
            .modules-filter-bar-new .search-box i {
                position: absolute;
            left: 12px;
            top: 50%;
            transform: translateY(-50%);
            color: rgba(255,255,255,0.4);
            font-size: 13px;
                }
            .modules-filter-bar-new .search-box input {
                width: 100%;
            padding: 10px 10px 10px 36px;
            background: rgba(255,255,255,0.05);
            border: 1px solid rgba(255,255,255,0.1);
            border-radius: 8px;
            color: #fff;
            font-size: 13px;
            transition: all 0.3s ease;
                }

            /* Enhanced Dark Theme Path Cards */
            .paths-grid {
                display: grid;
                grid-template-columns: repeat(auto-fill, minmax(320px, 1fr));
                gap: 30px;
                padding: 20px 0;
            }
            
            .path-card {
                background: linear-gradient(145deg, rgba(30, 41, 59, 0.95) 0%, rgba(15, 23, 42, 0.98) 100%);
                border-radius: 16px;
                overflow: hidden;
                cursor: pointer;
                position: relative;
                transition: all 0.4s cubic-bezier(0.175, 0.885, 0.32, 1.275);
                box-shadow: 0 8px 32px rgba(0, 0, 0, 0.25);
                border: 1px solid rgba(255, 255, 255, 0.08);
                height: 100%;
                display: flex;
                flex-direction: column;
            }
            
            .path-card::before {
                content: '';
                position: absolute;
                top: 0;
                left: 0;
                right: 0;
                height: 4px;
                background: linear-gradient(90deg, var(--path-color), #8b5cf6, #ec4899);
                opacity: 0;
                transition: opacity 0.3s ease;
                z-index: 10;
            }
            
            .path-card:hover {
                transform: translateY(-10px) scale(1.02);
                box-shadow: 0 20px 40px rgba(0, 0, 0, 0.35), 0 0 30px rgba(59, 130, 246, 0.2);
                border-color: rgba(255, 255, 255, 0.15);
            }
            
            .path-card:hover::before {
                opacity: 1;
            }
            
            /* Specialized Illustrations for Dark Theme */
            .path-illustration {
                height: 180px;
                position: relative;
                overflow: hidden;
                display: flex;
                align-items: center;
                justify-content: center;
            }
            
            .path-illustration::before {
                content: '';
                position: absolute;
                inset: 0;
                background: linear-gradient(135deg, rgba(255, 255, 255, 0.1) 0%, transparent 60%);
            }
            
            .path-illustration-img {
                width: 100%;
                height: 100%;
                object-fit: cover;
                position: absolute;
                top: 0;
                left: 0;
                z-index: 1;
            }
            
            .path-illustration-icon {
                font-size: 64px;
                color: rgba(255, 255, 255, 0.9);
                z-index: 2;
                text-shadow: 0 4px 20px rgba(0, 0, 0, 0.3);
            }
            
            /* Progress Indicator */
            .path-progress-circle {
                position: absolute;
                top: 16px;
                right: 16px;
                width: 50px;
                height: 50px;
                background: #0f172a;
                border-radius: 50%;
                display: flex;
                align-items: center;
                justify-content: center;
                font-size: 12px;
                font-weight: 700;
                color: #22c55e;
                box-shadow: 0 4px 15px rgba(0, 0, 0, 0.3);
                z-index: 5;
                border: 3px solid rgba(255, 255, 255, 0.1);
            }
            
            .path-progress-circle.completed {
                color: #38ef7d;
                border-color: #38ef7d;
            }
            
            .path-progress-circle.in-progress {
                color: #f5a623;
                border-color: #f5a623;
            }
            
            /* Content Area */
            .path-content {
                padding: 24px;
                flex-grow: 1;
                display: flex;
                flex-direction: column;
            }
            
            .path-name {
                font-size: 1.25rem;
                font-weight: 700;
                color: #fff;
                margin-bottom: 12px;
                line-height: 1.4;
            }
            
            .path-description {
                color: rgba(255, 255, 255, 0.65);
                font-size: 14px;
                line-height: 1.6;
                margin-bottom: 20px;
                flex-grow: 1;
            }
            
            .path-meta {
                display: flex;
                justify-content: space-between;
                align-items: center;
                margin-top: auto;
                padding-top: 16px;
                border-top: 1px solid rgba(255, 255, 255, 0.08);
            }
            
            .path-difficulty {
                display: inline-flex;
                align-items: center;
                gap: 6px;
                font-size: 12px;
                font-weight: 600;
                padding: 6px 12px;
                border-radius: 20px;
                background: rgba(255, 255, 255, 0.1);
                color: rgba(255, 255, 255, 0.8);
            }
            
            .path-difficulty.easy, .path-difficulty.basic {
                background: rgba(34, 197, 94, 0.15);
                color: #22c55e;
            }
            
            .path-difficulty.medium, .path-difficulty.intermediate {
                background: rgba(245, 158, 11, 0.15);
                color: #f59e0b;
            }
            
            .path-difficulty.hard, .path-difficulty.advanced {
                background: rgba(239, 68, 68, 0.15);
                color: #ef4444;
            }
            
            .path-hours {
                font-size: 12px;
                color: rgba(255, 255, 255, 0.5);
                display: flex;
                align-items: center;
                gap: 4px;
            }

            /* Networks Grid - TryHackMe Design */
            .networks-filter-bar {
                display: flex;
            gap: 15px;
            margin-bottom: 30px;
            flex-wrap: wrap;
                }
            .net-filter {
                padding: 8px 15px;
            border: 1px solid rgba(255,255,255,0.1);
            background: rgba(255,255,255,0.05);
            border-radius: 6px;
            color: #fff;
            font-size: 14px;
            outline: none;
                }
            .networks-grid {
                display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 25px;
                }
            @media (max-width: 1400px) { .networks - grid {grid - template - columns: repeat(3, 1fr); } }
            @media (max-width: 1000px) { .networks - grid {grid - template - columns: repeat(2, 1fr); } }
            @media (max-width: 650px) { .networks - grid {grid - template - columns: 1fr; } }

            .network-card-new {
                background: #fff;
            border: 1px solid #e5e7eb;
            border-radius: 8px;
            padding: 20px;
            display: flex;
            flex-direction: column;
            justify-content: space-between;
            min-height: 280px;
            cursor: pointer;
            transition: all 0.3s ease;
            position: relative;
                }
            .network-card-new:hover {
                box - shadow: 0 10px 25px rgba(0,0,0,0.08);
            transform: translateY(-3px);
            border-color: #d1d5db;
                }
            .net-card-top {
                margin - bottom: 20px;
                }
            .net-icon-box {
                font - size: 32px;
            color: #1f2937;
            margin-bottom: 15px;
                }
            .net-title {
                font - size: 1.1rem;
            font-weight: 700;
            color: #111827;
            margin-bottom: 10px;
                }
            .net-desc {
                color: #6b7280;
            font-size: 13px;
            line-height: 1.6;
            display: -webkit-box;
            -webkit-line-clamp: 4;
            -webkit-box-orient: vertical;
            overflow: hidden;
                }
            .net-card-bottom {
                border - top: 1px solid #f3f4f6;
            padding-top: 15px;
            display: flex;
            flex-direction: column;
            gap: 12px;
                }
            .net-difficulty {
                display: flex;
            align-items: center;
            gap: 6px;
            font-size: 13px;
            font-weight: 600;
                }
            .net-difficulty.easy {color: #10b981; }
            .net-difficulty.medium {color: #f59e0b; }
            .net-difficulty.hard {color: #ef4444; }
            .net-difficulty.insane {color: #7c3aed; }
            .net-badges {
                display: flex;
            gap: 8px;
            flex-wrap: wrap;
                }
            .net-badge {
                font - size: 11px;
            padding: 4px 10px;
            border-radius: 20px;
            font-weight: 700;
            text-transform: uppercase;
                }
            .net-badge.premium {
                background: #1f2937;
            color: #fff;
                }
            .net-badge.free {
                background: #e5e7eb;
            color: #374151;
                }
            .net-badge.streak {
                background: #059669;
            color: #fff;
            display: flex;
            align-items: center;
            gap: 4px;
                }

            /* Modules Grid */
            .modules-grid {
                display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 25px;
                }
            .module-card {
                background: rgba(255,255,255,0.03);
            border: 1px solid rgba(255,255,255,0.1);
            border-radius: 20px;
            padding: 25px;
            transition: all 0.3s ease;
            cursor: pointer;
                }
            .module-card:hover {
                border - color: var(--mod-color, #f97316);
            transform: translateY(-5px);
                }
            .module-header {display: flex; align-items: center; gap: 15px; margin-bottom: 15px; }
            .module-icon {
                width: 50px; height: 50px;
            background: var(--mod-color, #f97316)30;
            border-radius: 12px;
            display: flex; align-items: center; justify-content: center;
            font-size: 22px; color: var(--mod-color, #f97316);
                }
            .module-title {font - size: 1.2rem; font-weight: 700; color: #fff; }
            .module-desc {color: rgba(255,255,255,0.5); font-size: 13px; margin-bottom: 15px; }
            .module-skills {display: flex; gap: 8px; flex-wrap: wrap; }
            .module-skill {
                background: rgba(255,255,255,0.05);
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 11px;
            color: rgba(255,255,255,0.6);
                }

            /* Modules Filter Bar */
            .modules-filter-bar {
                display: flex;
            gap: 12px;
            margin-bottom: 25px;
            flex-wrap: wrap;
                }
            .modules-filter-bar select {
                padding: 12px 20px;
            background: rgba(255,255,255,0.05);
            border: 2px solid rgba(255,255,255,0.1);
            border-radius: 12px;
            color: #fff;
            font-size: 14px;
            cursor: pointer;
            min-width: 160px;
                }
            .modules-filter-bar select:focus {
                outline: none;
            border-color: #f97316;
                }
            .modules-filter-bar select option {
                background: #1a1a2e;
                }

            /* ============ NEW MODULES STYLES - Professional Dark Theme ============ */
            .modules-header {
                margin - bottom: 40px;
            text-align: center;
            padding: 40px 20px;
            background: linear-gradient(135deg, rgba(59, 130, 246, 0.1) 0%, rgba(139, 92, 246, 0.1) 100%);
            border-radius: 20px;
            border: 1px solid rgba(255,255,255,0.1);
                }
            .modules-header h1 {
                font - size: 2.5rem;
            font-weight: 800;
            background: linear-gradient(135deg, #fff 0%, #94a3b8 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            margin-bottom: 12px;
                }
            .modules-header p {
                color: rgba(255,255,255,0.6);
            font-size: 16px;
            max-width: 500px;
            margin: 0 auto;
                }

            /* Modules Filter Bar - Same as Paths */
            .modules-filter-bar-new {
                display: flex;
            gap: 20px;
            margin-bottom: 30px;
            flex-wrap: wrap;
            align-items: center;
                }
            .modules-filter-bar-new .search-box {
                flex: 1;
            min-width: 180px;
            max-width: 280px;
            position: relative;
                }
            .modules-filter-bar-new .search-box i {
                position: absolute;
            left: 12px;
            top: 50%;
            transform: translateY(-50%);
            color: rgba(255,255,255,0.4);
            font-size: 13px;
                }
            .modules-filter-bar-new .search-box input {
                width: 100%;
            padding: 10px 10px 10px 36px;
            background: rgba(255,255,255,0.05);
            border: 1px solid rgba(255,255,255,0.1);
            border-radius: 8px;
            color: #fff;
            font-size: 13px;
            transition: all 0.3s ease;
                }

            /* Paths Grid - TryHackMe Style */
            .paths-grid {
                display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 24px;
                }
            @media (max-width: 1400px) {
                    .paths - grid {grid - template - columns: repeat(3, 1fr); }
                }
            @media (max-width: 1000px) {
                    .paths - grid {grid - template - columns: repeat(2, 1fr); }
                }
            @media (max-width: 600px) {
                    .paths - grid {grid - template - columns: 1fr; }
                }

            .path-card {
                background: linear-gradient(145deg, rgba(30, 41, 59, 0.95) 0%, rgba(15, 23, 42, 0.98) 100%);
            border-radius: 18px;
            overflow: hidden;
            cursor: pointer;
            position: relative;
            transition: all 0.4s cubic-bezier(0.175, 0.885, 0.32, 1.275);
            box-shadow: 0 6px 25px rgba(0,0,0,0.25);
            border: 1px solid rgba(255,255,255,0.08);
                }
            .path-card::before {
                content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 4px;
            background: linear-gradient(90deg, var(--path-color), #8b5cf6, #ec4899);
            opacity: 0;
            transition: opacity 0.3s ease;
            z-index: 10;
                }
            .path-card:hover {
                transform: translateY(-12px) scale(1.02);
            box-shadow: 0 25px 50px rgba(0,0,0,0.35), 0 0 40px var(--path-color)30;
            border-color: var(--path-color)60;
                }
            .path-card:hover::before {
                opacity: 1;
                }
            .path-card.in-progress {
                border: 2px solid var(--path-color);
            box-shadow: 0 6px 25px rgba(0,0,0,0.25), 0 0 20px var(--path-color)20;
                }

            /* Image/Illustration Area */
            .path-image-area {
                height: 160px;
            background: var(--path-color);
            display: flex;
            align-items: center;
            justify-content: center;
            position: relative;
            overflow: hidden;
                }
            .path-image-area::before {
                content: '';
            position: absolute;
            inset: 0;
            background: linear-gradient(135deg, rgba(255,255,255,0.2) 0%, transparent 50%);
                }
            .path-image-area i {
                font - size: 64px;
            color: rgba(255,255,255,0.9);
            z-index: 1;
                }

            /* Progress Circle */
            .path-progress-circle {
                position: absolute;
            top: 12px;
            right: 12px;
            width: 44px;
            height: 44px;
            background: #1a1a2e;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 11px;
            font-weight: 700;
            color: #22c55e;
            z-index: 5;
            box-shadow: 0 2px 8px rgba(0,0,0,0.3);
                }

            /* Card Content */
            .path-content {
                padding: 22px;
            background: transparent;
            border-left: 4px solid var(--path-color);
                }
            .path-name {
                font - size: 1.15rem;
            font-weight: 700;
            color: #fff;
            margin-bottom: 10px;
            line-height: 1.3;
            transition: color 0.3s ease;
                }
            .path-card:hover .path-name {
                color: var(--path-color);
                }
            .path-description {
                color: rgba(255,255,255,0.55);
            font-size: 13px;
            line-height: 1.6;
            margin-bottom: 16px;
            display: -webkit-box;
            -webkit-line-clamp: 2;
            -webkit-box-orient: vertical;
            overflow: hidden;
            min-height: 42px;
                }

            /* Difficulty Badge */
            .path-difficulty {
                display: inline-flex;
            align-items: center;
            gap: 6px;
            font-size: 12px;
            font-weight: 600;
                }
            .path-difficulty i {
                font - size: 10px;
                }
            .path-difficulty.easy {color: #22c55e; }
            .path-difficulty.basic {color: #22c55e; }
            .path-difficulty.intermediate {color: #f59e0b; }
            .path-difficulty.medium {color: #f59e0b; }
            .path-difficulty.hard {color: #ef4444; }
            .path-difficulty.advanced {color: #ef4444; }

            /* Hide old path-icon, path-stats */
            .path-icon {display: none; }
            .path-stats {display: none; }
            .path-btn {
                flex: 1.2;
            padding: 14px 20px;
            background: linear-gradient(135deg, var(--path-color), var(--path-color)cc);
            border: none;
            border-radius: 12px;
            color: #fff;
            font-weight: 700;
            font-size: 14px;
            cursor: pointer;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 8px;
            transition: all 0.3s ease;
                }
            .path-btn:hover {
                transform: translateY(-2px);
            box-shadow: 0 8px 25px var(--path-color)50;
                }
            .path-view-btn {
                flex: 1;
            padding: 14px 16px;
            background: transparent;
            border: 2px solid var(--path-color)60;
            border-radius: 12px;
            color: var(--path-color);
            font-weight: 600;
            font-size: 14px;
            cursor: pointer;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 8px;
            transition: all 0.3s ease;
                }
            .path-view-btn:hover {
                background: var(--path-color)15;
            border-color: var(--path-color);
            transform: translateY(-2px);
                }
            .path-btn-group {
                display: flex;
            gap: 12px;
            margin-top: 5px;
                }

            /* Networks Grid - TryHackMe Design */
            .networks-filter-bar {
                display: flex;
            gap: 15px;
            margin-bottom: 30px;
            flex-wrap: wrap;
                }
            .net-filter {
                padding: 8px 15px;
            border: 1px solid rgba(255,255,255,0.1);
            background: rgba(255,255,255,0.05);
            border-radius: 6px;
            color: #fff;
            font-size: 14px;
            outline: none;
                }
            .networks-grid {
                display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 25px;
                }
            @media (max-width: 1400px) { .networks - grid {grid - template - columns: repeat(3, 1fr); } }
            @media (max-width: 1000px) { .networks - grid {grid - template - columns: repeat(2, 1fr); } }
            @media (max-width: 650px) { .networks - grid {grid - template - columns: 1fr; } }

            .network-card-new {
                background: #fff;
            border: 1px solid #e5e7eb;
            border-radius: 8px;
            padding: 20px;
            display: flex;
            flex-direction: column;
            justify-content: space-between;
            min-height: 280px;
            cursor: pointer;
            transition: all 0.3s ease;
            position: relative;
                }
            .network-card-new:hover {
                box - shadow: 0 10px 25px rgba(0,0,0,0.08);
            transform: translateY(-3px);
            border-color: #d1d5db;
                }
            .net-card-top {
                margin - bottom: 20px;
                }
            .net-icon-box {
                font - size: 32px;
            color: #1f2937;
            margin-bottom: 15px;
                }
            .net-title {
                font - size: 1.1rem;
            font-weight: 700;
            color: #111827;
            margin-bottom: 10px;
                }
            .net-desc {
                color: #6b7280;
            font-size: 13px;
            line-height: 1.6;
            display: -webkit-box;
            -webkit-line-clamp: 4;
            -webkit-box-orient: vertical;
            overflow: hidden;
                }
            .net-card-bottom {
                border - top: 1px solid #f3f4f6;
            padding-top: 15px;
            display: flex;
            flex-direction: column;
            gap: 12px;
                }
            .net-difficulty {
                display: flex;
            align-items: center;
            gap: 6px;
            font-size: 13px;
            transition: all 0.3s;
                }
            .modules-filter-bar-new .search-box input::placeholder {
                color: rgba(255,255,255,0.4);
                }
            .modules-filter-bar-new .search-box input:focus {
                outline: none;
            border-color: #3b82f6;
            background: rgba(255,255,255,0.08);
            box-shadow: 0 0 12px rgba(59, 130, 246, 0.15);
                }
            .modules-filter-bar-new .filter-dropdowns {
                display: flex;
            gap: 10px;
                }
            .modules-filter-bar-new .filter-dropdowns select {
                padding: 10px 14px;
            background: rgba(255,255,255,0.05);
            border: 1px solid rgba(255,255,255,0.1);
            border-radius: 8px;
            color: #fff;
            font-size: 13px;
            cursor: pointer;
            transition: all 0.3s;
                }
            .modules-filter-bar-new .filter-dropdowns select:hover {
                border - color: rgba(255,255,255,0.2);
                }
            .modules-filter-bar-new .filter-dropdowns select:focus {
                outline: none;
            border-color: #3b82f6;
            box-shadow: 0 0 12px rgba(59, 130, 246, 0.15);
                }
            .modules-filter-bar-new .filter-dropdowns select option {
                background: #1a1a2e;
            color: #fff;
                }

            /* Modules Grid - Professional Style */
            .modules-grid-new {
                display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 25px;
                }
            @media (max-width: 1400px) {
                    .modules - grid - new { grid- template - columns: repeat(3, 1fr); }
                }
            @media (max-width: 1000px) {
                    .modules - grid - new { grid- template - columns: repeat(2, 1fr); }
                }
            @media (max-width: 600px) {
                    .modules - grid - new { grid- template - columns: 1fr; }
                }

            /* Module Card - Professional Dark Style */
            .module-card-new {
                background: linear-gradient(145deg, rgba(30, 41, 59, 0.9) 0%, rgba(15, 23, 42, 0.95) 100%);
            border-radius: 16px;
            padding: 24px;
            cursor: pointer;
            transition: all 0.4s cubic-bezier(0.175, 0.885, 0.32, 1.275);
            box-shadow: 0 4px 20px rgba(0,0,0,0.2);
            border: 1px solid rgba(255,255,255,0.08);
            position: relative;
            overflow: hidden;
                }
            .module-card-new::before {
                content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 3px;
            background: linear-gradient(90deg, #3b82f6, #8b5cf6, #ec4899);
            opacity: 0;
            transition: opacity 0.3s ease;
                }
            .module-card-new:hover {
                transform: translateY(-8px) scale(1.02);
            box-shadow: 0 20px 40px rgba(0,0,0,0.3), 0 0 30px rgba(59, 130, 246, 0.15);
            border-color: rgba(59, 130, 246, 0.3);
                }
            .module-card-new:hover::before {
                opacity: 1;
                }

            .module-icon-box {
                width: 56px;
            height: 56px;
            border-radius: 14px;
            display: flex;
            align-items: center;
            justify-content: center;
            margin-bottom: 18px;
            position: relative;
            box-shadow: 0 8px 25px rgba(0,0,0,0.3);
                }
            .module-icon-box::after {
                content: '✦';
            position: absolute;
            top: -5px;
            right: -5px;
            font-size: 12px;
            color: #fbbf24;
            animation: sparkle 2s infinite;
                }
            @keyframes sparkle {
                0 %, 100 % { opacity: 0.3; transform: scale(0.8); }
                    50% {opacity: 1; transform: scale(1.2); }
                }
            .module-icon-box i {
                font - size: 24px;
            color: #fff;
            filter: drop-shadow(0 2px 4px rgba(0,0,0,0.3));
                }

            .module-title-new {
                font - size: 1.1rem;
            font-weight: 700;
            color: #fff;
            margin-bottom: 12px;
            line-height: 1.4;
            transition: color 0.3s ease;
                }
            .module-card-new:hover .module-title-new {
                color: #60a5fa;
                }

            .module-desc-new {
                color: rgba(255,255,255,0.55);
            font-size: 13px;
            line-height: 1.7;
            display: -webkit-box;
            -webkit-line-clamp: 3;
            -webkit-box-orient: vertical;
            overflow: hidden;
            margin-bottom: 12px;
                }

            .module-difficulty {
                display: inline-flex;
            align-items: center;
            gap: 6px;
            padding: 5px 12px;
            border-radius: 15px;
            font-size: 11px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-top: auto;
                }
            .module-difficulty i {font - size: 10px; }
            .module-difficulty.easy {
                background: rgba(34,197,94,0.15);
            color: #22c55e;
            border: 1px solid rgba(34,197,94,0.3);
                }
            .module-difficulty.medium {
                background: rgba(245,158,11,0.15);
            color: #f59e0b;
            border: 1px solid rgba(245,158,11,0.3);
                }
            .module-difficulty.hard {
                background: rgba(239,68,68,0.15);
            color: #ef4444;
            border: 1px solid rgba(239,68,68,0.3);
                }

            /* Module Card Enhancements */
            .module-icon-circle {
                width: 55px; height: 55px;
            background: linear-gradient(135deg, var(--mod-color, #f97316), var(--mod-color, #f97316)aa);
            border-radius: 50%;
            display: flex; align-items: center; justify-content: center;
            font-size: 24px; color: #fff;
            box-shadow: 0 6px 20px var(--mod-color, #f97316)40;
                }
            .module-badges {
                display: flex;
            gap: 8px;
            flex-wrap: wrap;
            margin-bottom: 15px;
                }
            .module-badge {
                padding: 5px 12px;
            border-radius: 20px;
            font-size: 11px;
            font-weight: 600;
            display: inline-flex;
            align-items: center;
            gap: 5px;
                }
            .module-badge i {font - size: 10px; }
            .module-badge.time {
                background: rgba(255,255,255,0.1);
            color: rgba(255,255,255,0.7);
                }
            .module-badge.premium {
                background: linear-gradient(135deg, #f59e0b, #d97706);
            color: #000;
                }
            .module-badge.free {
                background: rgba(34,197,94,0.2);
            color: #22c55e;
                }
            .module-badge.team.red {
                background: rgba(239,68,68,0.2);
            color: #ef4444;
                }
            .module-badge.team.blue {
                background: rgba(59,130,246,0.2);
            color: #3b82f6;
                }
            .module-footer {
                margin - top: 15px;
            padding-top: 12px;
            border-top: 1px solid rgba(255,255,255,0.05);
            display: flex;
            justify-content: space-between;
            align-items: center;
                }
            .module-difficulty {
                padding: 4px 12px;
            border-radius: 10px;
            font-size: 11px;
            font-weight: 600;
            text-transform: capitalize;
                }
            .module-difficulty.easy {background: rgba(34,197,94,0.2); color: #22c55e; }
            .module-difficulty.medium {background: rgba(245,158,11,0.2); color: #f59e0b; }
            .module-difficulty.hard {background: rgba(239,68,68,0.2); color: #ef4444; }

            /* ============ HTB ACADEMY INLINE STYLES ============ */
            .htb-modules-header-inline {
                display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 30px;
            flex-wrap: wrap;
            gap: 20px;
                }
            .htb-modules-header-inline h1 {
                font - size: 2.2rem;
            font-weight: 800;
            color: #fff;
            margin: 0;
                }

            /* HTB Tab Switcher */
            .htb-tabs-inline {
                display: flex;
            gap: 0;
            background: rgba(255,255,255,0.05);
            border-radius: 10px;
            padding: 4px;
                }
            .htb-tab-inline {
                padding: 12px 24px;
            font-size: 14px;
            font-weight: 600;
            color: rgba(255,255,255,0.6);
            cursor: pointer;
            border-radius: 8px;
            transition: all 0.3s ease;
            border: none;
            background: transparent;
                }
            .htb-tab-inline:hover {color: #fff; }
            .htb-tab-inline.active {
                background: rgba(159, 239, 0, 0.15);
            color: #9fef00;
            box-shadow: 0 2px 8px rgba(159, 239, 0, 0.2);
                }

            /* HTB Filter Bar Inline */
            .htb-filter-bar-inline {
                display: flex;
            gap: 12px;
            margin-bottom: 25px;
            flex-wrap: wrap;
            align-items: center;
                }
            .htb-filter-dropdown-inline {
                position: relative;
                }
            .htb-filter-dropdown-inline select {
                appearance: none;
            padding: 11px 38px 11px 16px;
            background: rgba(255,255,255,0.05);
            border: 1px solid rgba(255,255,255,0.12);
            border-radius: 10px;
            color: rgba(255,255,255,0.8);
            font-size: 13px;
            font-weight: 500;
            cursor: pointer;
            min-width: 130px;
            transition: all 0.3s ease;
                }
            .htb-filter-dropdown-inline select:hover {
                border - color: rgba(255,255,255,0.25);
            background: rgba(255,255,255,0.08);
                }
            .htb-filter-dropdown-inline select:focus {
                outline: none;
            border-color: #9fef00;
            box-shadow: 0 0 0 3px rgba(159, 239, 0, 0.1);
                }
            .htb-filter-dropdown-inline select option {
                background: #1a1f2e;
            color: #fff;
            padding: 10px;
                }
            .htb-filter-dropdown-inline::after {
                content: '\\f078';
            font-family: 'Font Awesome 6 Free';
            font-weight: 900;
            position: absolute;
            right: 14px;
            top: 50%;
            transform: translateY(-50%);
            color: rgba(255,255,255,0.4);
            font-size: 10px;
            pointer-events: none;
                }
            .htb-view-toggle-inline {
                margin - left: auto;
            display: flex;
            align-items: center;
            gap: 8px;
            color: rgba(255,255,255,0.5);
            font-size: 13px;
                }
            .htb-view-toggle-inline span {
                color: #9fef00;
            font-weight: 600;
                }

            /* HTB Section Title */
            .htb-section-title-inline {
                font - size: 1.2rem;
            font-weight: 700;
            color: #fff;
            margin-bottom: 20px;
            display: flex;
            align-items: center;
            gap: 10px;
                }
            .htb-section-title-inline::before {
                content: '';
            width: 4px;
            height: 22px;
            background: linear-gradient(180deg, #9fef00, #22c55e);
            border-radius: 2px;
                }

            /* HTB Modules Grid */
            .htb-modules-grid-inline {
                display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 22px;
                }
            @media (max-width: 1400px) { .htb - modules - grid - inline {grid - template - columns: repeat(3, 1fr); } }
            @media (max-width: 1000px) { .htb - modules - grid - inline {grid - template - columns: repeat(2, 1fr); } }
            @media (max-width: 650px) { .htb - modules - grid - inline {grid - template - columns: 1fr; } }

            /* HTB Module Card */
            .htb-module-card-inline {
                background: linear-gradient(165deg, #1e2a3a 0%, #141d2b 100%);
            border-radius: 14px;
            overflow: hidden;
            cursor: pointer;
            transition: all 0.4s cubic-bezier(0.175, 0.885, 0.32, 1.275);
            border: 1px solid rgba(255,255,255,0.06);
            position: relative;
                }
            .htb-module-card-inline:hover {
                transform: translateY(-6px) scale(1.02);
            border-color: rgba(159, 239, 0, 0.3);
            box-shadow: 0 15px 40px rgba(0,0,0,0.4), 0 0 30px rgba(159, 239, 0, 0.08);
                }

            /* Progress Badge */
            .htb-progress-badge-inline {
                position: absolute;
            top: 10px;
            right: 10px;
            padding: 5px 12px;
            background: linear-gradient(135deg, #22c55e, #16a34a);
            color: #fff;
            font-size: 10px;
            font-weight: 700;
            border-radius: 5px;
            z-index: 10;
            box-shadow: 0 3px 12px rgba(34, 197, 94, 0.4);
            text-transform: uppercase;
            letter-spacing: 0.5px;
                }
            .htb-progress-badge-inline.completed {
                background: linear-gradient(135deg, #9fef00, #22c55e);
            color: #000;
                }

            /* Card Image Area */
            .htb-card-image-inline {
                height: 140px;
            display: flex;
            align-items: center;
            justify-content: center;
            position: relative;
            overflow: hidden;
                }
            .htb-card-image-inline::after {
                content: '';
            position: absolute;
            bottom: 0;
            left: 0;
            right: 0;
            height: 50px;
            background: linear-gradient(to top, #141d2b, transparent);
                }

            /* Floating Decorations */
            .htb-card-decoration-inline {
                position: absolute;
            border-radius: 50%;
            opacity: 0.5;
            animation: htb-float-inline 4s ease-in-out infinite;
                }
            .htb-card-decoration-inline.d1 {
                width: 10px; height: 10px;
            background: #a855f7;
            top: 20%; left: 15%;
            animation-delay: 0s;
                }
            .htb-card-decoration-inline.d2 {
                width: 7px; height: 7px;
            background: #22d3ee;
            top: 30%; right: 20%;
            animation-delay: 1s;
                }
            .htb-card-decoration-inline.d3 {
                width: 8px; height: 8px;
            background: #9fef00;
            bottom: 40%; left: 25%;
            animation-delay: 2s;
                }
            @keyframes htb-float-inline {
                0 %, 100 % { transform: translateY(0) scale(1); opacity: 0.5; }
                    50% {transform: translateY(-6px) scale(1.15); opacity: 0.9; }
                }

            /* Module Visual */
            .htb-module-visual-inline {
                position: relative;
            z-index: 5;
                }
            .htb-module-visual-inline i {
                font - size: 52px;
            background: linear-gradient(135deg, #fff 20%, rgba(255,255,255,0.6) 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            filter: drop-shadow(0 3px 15px rgba(0,0,0,0.3));
            transition: all 0.4s ease;
                }
            .htb-module-card-inline:hover .htb-module-visual-inline i {
                transform: scale(1.1) rotate(3deg);
            filter: drop-shadow(0 6px 20px rgba(159, 239, 0, 0.2));
                }

            /* Card Content */
            .htb-card-content-inline {
                padding: 15px 18px 18px;
                }

            /* Tags Row */
            .htb-card-tags-inline {
                display: flex;
            gap: 8px;
            margin-bottom: 10px;
            flex-wrap: wrap;
                }
            .htb-tag-inline {
                display: inline-flex;
            align-items: center;
            gap: 4px;
            padding: 3px 8px;
            border-radius: 4px;
            font-size: 9px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.4px;
                }
            .htb-tag-inline.tier-regular {
                background: rgba(34, 197, 94, 0.15);
            color: #22c55e;
                }
            .htb-tag-inline.tier-premium {
                background: rgba(245, 158, 11, 0.15);
            color: #f59e0b;
                }
            .htb-tag-inline.type-general {
                background: rgba(59, 130, 246, 0.15);
            color: #60a5fa;
                }
            .htb-tag-inline.type-offensive {
                background: rgba(239, 68, 68, 0.15);
            color: #f87171;
                }
            .htb-tag-inline.type-defensive {
                background: rgba(139, 92, 246, 0.15);
            color: #a78bfa;
                }

            /* Card Title */
            .htb-card-title-inline {
                font - size: 14px;
            font-weight: 700;
            color: #fff;
            margin-bottom: 10px;
            line-height: 1.4;
                }
            .htb-module-card-inline:hover .htb-card-title-inline {
                color: #9fef00;
                }

            /* Progress Bar */
            .htb-progress-bar-container-inline {
                height: 5px;
            background: rgba(255,255,255,0.1);
            border-radius: 3px;
            overflow: hidden;
                }
            .htb-progress-bar-inline {
                height: 100%;
            background: linear-gradient(90deg, #9fef00, #22c55e);
            border-radius: 3px;
            transition: width 0.5s ease;
                }

            /* Difficulty Badge */
            .htb-difficulty-inline {
                display: inline-flex;
            align-items: center;
            gap: 5px;
            font-size: 11px;
            font-weight: 600;
            text-transform: capitalize;
                }
            .htb-difficulty-inline i {font - size: 10px; }
            .htb-difficulty-inline.easy {color: #22c55e; }
            .htb-difficulty-inline.medium {color: #f59e0b; }
            .htb-difficulty-inline.hard {color: #ef4444; }
            .htb-difficulty-inline.insane {color: #a855f7; }

            /* Walkthroughs Grid - TryHackMe Style */
            .walkthroughs-filter-bar {
                display: flex;
            gap: 20px;
            margin-bottom: 30px;
            flex-wrap: wrap;
            align-items: center;
                }
            .walkthroughs-grid {
                display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 20px;
                }
            @media (max-width: 1200px) { .walkthroughs - grid {grid - template - columns: repeat(3, 1fr); } }
            @media (max-width: 900px) { .walkthroughs - grid {grid - template - columns: repeat(2, 1fr); } }
            @media (max-width: 600px) { .walkthroughs - grid {grid - template - columns: 1fr; } }

            .walkthrough-card-new {
                background: #fff;
            border: 1px solid #e5e7eb;
            border-radius: 12px;
            padding: 20px;
            display: flex;
            flex-direction: column;
            gap: 15px;
            cursor: pointer;
            transition: all 0.3s ease;
            position: relative;
                }
            .walkthrough-card-new:hover {
                border - color: #3b82f6;
            box-shadow: 0 8px 25px rgba(59, 130, 246, 0.15);
            transform: translateY(-3px);
                }
            .wt-card-content {
                display: flex;
            justify-content: space-between;
            align-items: flex-start;
                }
            .wt-title {
                font - size: 1rem;
            font-weight: 700;
            color: #1f2937;
            margin: 0;
            line-height: 1.4;
            flex: 1;
            padding-right: 60px;
                }
            .wt-icon-circle {
                position: absolute;
            top: 15px;
            right: 15px;
            width: 50px;
            height: 50px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
                }
            .wt-icon-circle i {
                font - size: 22px;
            color: #fff;
                }
            .wt-card-footer {
                display: flex;
            justify-content: space-between;
            align-items: center;
            margin-top: auto;
            padding-top: 10px;
            border-top: 1px solid #f3f4f6;
                }
            .wt-meta-left {
                display: flex;
            align-items: center;
            gap: 12px;
                }
            .wt-download {
                color: #9ca3af;
            font-size: 14px;
                }
            .wt-difficulty {
                display: flex;
            align-items: center;
            gap: 5px;
            font-size: 12px;
            font-weight: 600;
                }
            .wt-difficulty i {font - size: 10px; }
            .wt-difficulty.easy {color: #22c55e; }
            .wt-difficulty.medium {color: #f59e0b; }
            .wt-difficulty.hard {color: #ef4444; }
            .wt-time {
                display: flex;
            align-items: center;
            gap: 5px;
            color: #6b7280;
            font-size: 12px;
                }
            .wt-time i {font - size: 11px; }
            .wt-favorite {
                color: #d1d5db;
            font-size: 16px;
            cursor: pointer;
            transition: color 0.2s;
                }
            .wt-favorite:hover {color: #ef4444; }

            /* Networks */
            .networks-grid {
                display: grid;
            grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
            gap: 30px;
                }
            .network-card {
                background: linear-gradient(135deg, rgba(245,158,11,0.1), rgba(0,0,0,0.3));
            border: 2px solid #f59e0b40;
            border-radius: 24px;
            padding: 30px;
            position: relative;
            transition: all 0.4s ease;
            cursor: pointer;
                }
            .network-card:hover {
                border - color: #f59e0b;
            box-shadow: 0 20px 50px rgba(245,158,11,0.2);
                }
            .network-badge {
                position: absolute;
            top: 20px; right: 20px;
            background: linear-gradient(135deg, #f59e0b, #d97706);
            padding: 6px 14px;
            border-radius: 20px;
            font-size: 11px;
            font-weight: 700;
            color: #000;
                }
            .network-header {display: flex; align-items: center; gap: 20px; margin-bottom: 20px; }
            .network-icon {
                width: 70px; height: 70px;
            background: linear-gradient(135deg, #f59e0b, #d97706);
            border-radius: 18px;
            display: flex; align-items: center; justify-content: center;
            font-size: 30px; color: #000;
                }
            .network-title {font - size: 1.6rem; font-weight: 700; color: #fff; margin-bottom: 5px; }
            .network-machines {color: #f59e0b; font-size: 14px; }
            .network-desc {color: rgba(255,255,255,0.6); font-size: 14px; line-height: 1.6; margin-bottom: 20px; }
            .network-topology {
                background: rgba(0,0,0,0.3);
            border-radius: 14px;
            padding: 20px;
            margin-bottom: 20px;
                }
            .network-machine {
                display: inline-flex;
            align-items: center;
            gap: 8px;
            background: rgba(255,255,255,0.05);
            padding: 8px 14px;
            border-radius: 8px;
            margin: 4px;
            font-size: 12px;
            color: rgba(255,255,255,0.7);
                }
            .network-machine i {color: #f59e0b; }
            .network-stats {display: flex; gap: 20px; margin-bottom: 20px; }
            .network-stat {text - align: center; }
            .network-stat-value {font - size: 1.3rem; font-weight: 700; color: #f59e0b; }
            .network-stat-label {font - size: 11px; color: rgba(255,255,255,0.4); text-transform: uppercase; }
            .network-vpn-btn:disabled {
                background: rgba(100,100,100,0.5);
            cursor: not-allowed;
                }

            /* Search and Filter Bar */
            .paths-filter-bar {
                display: flex;
            gap: 20px;
            margin-bottom: 30px;
            flex-wrap: wrap;
            align-items: center;
                }
            .search-box {
                flex: 1;
            min-width: 180px;
            max-width: 280px;
            position: relative;
                }
            .search-box i {
                position: absolute;
            left: 12px;
            top: 50%;
            transform: translateY(-50%);
            color: rgba(255,255,255,0.4);
            font-size: 13px;
                }
            .search-box input {
                width: 100%;
            padding: 10px 10px 10px 36px;
            background: rgba(255,255,255,0.05);
            border: 1px solid rgba(255,255,255,0.1);
            border-radius: 8px;
            color: #fff;
            font-size: 13px;
            transition: all 0.3s;
                }
            .search-box input:focus {
                outline: none;
            border-color: #3b82f6;
            background: rgba(255,255,255,0.08);
            box-shadow: 0 0 12px rgba(59, 130, 246, 0.15);
                }
            .filter-dropdowns {
                display: flex;
            gap: 10px;
                }
            .filter-dropdowns select {
                padding: 10px 14px;
            background: rgba(255,255,255,0.05);
            border: 1px solid rgba(255,255,255,0.1);
            border-radius: 8px;
            color: #fff;
            font-size: 13px;
            cursor: pointer;
            transition: all 0.3s;
                }
            .filter-dropdowns select:focus {
                outline: none;
            border-color: #ef4444;
                }
            .filter-dropdowns select option {
                background: #1a1a2e;
            color: #fff;
                }

            /* Enrolled Badge - Corner Ribbon Style */
            .latest-enrolled-badge {
                position: absolute;
            top: 12px;
            left: 12px;
            background: linear-gradient(135deg, #22c55e 0%, #16a34a 100%);
            color: #fff;
            padding: 6px 14px;
            border-radius: 20px;
            font-size: 11px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            white-space: nowrap;
            z-index: 10;
            box-shadow: 0 4px 12px rgba(34, 197, 94, 0.4);
            display: flex;
            align-items: center;
            gap: 6px;
            animation: enrolledGlow 2s infinite ease-in-out;
                }
            @keyframes enrolledGlow {
                0 %, 100 % {
                    box- shadow: 0 4px 12px rgba(34, 197, 94, 0.4);
                    }
            50% {
                box - shadow: 0 4px 20px rgba(34, 197, 94, 0.6), 0 0 15px rgba(34, 197, 94, 0.3);
                    }
                }
            .latest-enrolled-badge i {
                font - size: 10px;
                }

            /* Path Progress Bar */
            .path-progress-bar {
                position: relative;
            height: 8px;
            background: rgba(255,255,255,0.1);
            border-radius: 4px;
            margin-bottom: 15px;
            overflow: hidden;
                }
            .path-progress-bar .progress-fill {
                height: 100%;
            background: linear-gradient(90deg, #22c55e, #16a34a);
            border-radius: 4px;
            transition: width 0.5s ease;
                }
            .path-progress-bar .progress-text {
                position: absolute;
            right: 0;
            top: 12px;
            font-size: 11px;
            color: #22c55e;
            font-weight: 600;
                }

            /* Difficulty Badges */
            .difficulty-badge {
                padding: 4px 10px !important;
            border-radius: 12px !important;
            font-weight: 600 !important;
            text-transform: capitalize !important;
                }
            .difficulty-badge.easy {background: rgba(34,197,94,0.2); color: #22c55e !important; }
            .difficulty-badge.medium {background: rgba(245,158,11,0.2); color: #f59e0b !important; }
            .difficulty-badge.hard {background: rgba(239,68,68,0.2); color: #ef4444 !important; }

            /* Network Lock Overlay */
            .network-card.locked {
                opacity: 0.7;
            cursor: not-allowed;
            position: relative;
                }
            .network-lock-overlay {
                position: absolute;
            inset: 0;
            background: rgba(0,0,0,0.85);
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            z-index: 10;
            border-radius: 22px;
            gap: 10px;
                }
            .network-lock-overlay i {
                font - size: 40px;
            color: #ef4444;
                }
            .network-lock-overlay span {
                color: #fff;
            font-weight: 700;
            font-size: 16px;
                }
            .network-lock-overlay small {
                color: rgba(255,255,255,0.5);
            font-size: 13px;
                }

            /* Network Badges */
            .network-badges {
                display: flex;
            gap: 8px;
            margin-bottom: 15px;
            flex-wrap: wrap;
                }
            .network-badge {
                padding: 6px 12px;
            border-radius: 20px;
            font-size: 11px;
            font-weight: 700;
                }
            .network-badge.premium {
                background: linear-gradient(135deg, #f59e0b, #d97706);
            color: #000;
                }
            .network-badge.free {
                background: rgba(34,197,94,0.2);
            color: #22c55e;
                }
            .network-badge.streak {
                background: rgba(239,68,68,0.2);
            color: #ef4444;
                }
            .network-badge.streak i {margin - right: 4px; }
            .network-badge.difficulty {
                background: rgba(255,255,255,0.1);
            color: rgba(255,255,255,0.7);
                }

            /* Improved Learn Tabs */
            .learn-tabs-thm-container {
                display: flex;
                justify-content: center;
                margin-bottom: 40px;
                border-bottom: 1px solid rgba(255,255,255,0.1);
                padding-bottom: 0;
            }
            
            /* Tab Content Visibility */
            .learn-tab-content {
                display: none;
            }
            .learn-tab-content.active {
                display: block;
            }
            .learn-tabs-thm {
                display: flex;
                gap: 30px;
            }
            .learn-tab-thm {
                background: transparent;
                border: none;
                color: #64748b; /* Darker color for visibility on white bg */
                padding: 15px 5px;
                font-size: 1.1rem;
                font-weight: 600;
                cursor: pointer;
                transition: all 0.3s ease;
                display: flex;
                align-items: center;
                gap: 10px;
                border-bottom: 3px solid transparent;
                margin-bottom: -1px; /* Align with container border */
            }

            .htb-modules-header-inline {
                display: flex;
                justify-content: space-between;
                align-items: flex-end; /* Align tabs to bottom of header text */
                flex-wrap: wrap;
                gap: 20px;
                margin-bottom: 30px;
            }
            
            /* Section Headers Styling - DARK THEME */
            .modules-header h1 {
                color: #fff;
                font-size: 2rem;
                font-weight: 700;
                margin-bottom: 10px;
            }
            .modules-header p {
                color: #94a3b8;
                font-size: 1rem;
                margin-bottom: 30px;
            }

            /* Modules Tab Switcher - Reference Match */
            .htb-tabs-inline {
                display: flex;
                gap: 10px;
                margin-bottom: 20px;
                border: none;
                background: transparent;
                padding: 0;
            }

            .htb-tab-inline {
                background: transparent;
                border: none;
                color: #cbd5e1; /* Light gray for visibility */
                padding: 8px 16px;
                font-size: 0.95rem;
                font-weight: 600;
                cursor: pointer;
                border-radius: 6px; 
                transition: all 0.2s ease;
            }

            .htb-tab-inline:hover {
                color: #ffffff;
                background: rgba(255,255,255,0.05);
            }

            .htb-tab-inline.active {
                background: #1e293b; 
                color: #ffffff;
                box-shadow: 0 1px 2px rgba(0,0,0,0.2);
            }
            .learn-tab-thm:hover {
                color: #fff;
            }
            .learn-tab-thm.active {
                color: #22c55e; /* Green active state to match theme */
                border-bottom-color: #22c55e;
            }
            .learn-tab-thm i {
                font-size: 1.2rem;
            }

            @media (max-width: 768px) {
                .learn-title { font-size: 2rem; }
                .paths-grid, .networks-grid { grid-template-columns: 1fr; }
                .learn-tabs-thm { gap: 15px; overflow-x: auto; padding-bottom: 5px; width: 100%; justify-content: flex-start; }
                .learn-tab-thm { font-size: 0.9rem; white-space: nowrap; }
                .paths-filter-bar { flex-direction: column; }
                .search-box { width: 100%; }
                .filter-dropdowns { width: 100%; }
                .filter-dropdowns select { flex: 1; }
            }
        </style>

            <!-- Hero Section - Dark Navy Centered -->
            <div class="learn-hero-thm" style="text-align: center;">
                <div style="max-width: 900px; margin: 0 auto; padding: 30px 20px;">
                    <h1 style="font-size: 2.2rem; font-weight: 700; color: #fff; margin-bottom: 10px; font-family: 'Inter', sans-serif;">
                        <i class="fa-solid fa-graduation-cap" style="margin-right: 12px; color: #22c55e;"></i>Learn
                    </h1>
                    <p style="font-size: 15px; color: rgba(255,255,255,0.7); line-height: 1.5; margin-bottom: 20px; max-width: 600px; margin-left: auto; margin-right: auto;">
                        Whether you're a complete beginner or an advanced security professional, ShadowHack has the resources and structured paths to help you master cybersecurity.
                    </p>
                    <div class="learn-stats-row" style="justify-content: center;">
                        <div class="learn-stat-item">
                            <span class="learn-stat-number">${modules.length}+</span>
                            <span class="learn-stat-label">Hands-on Labs</span>
                        </div>
                        <div class="learn-stat-item">
                            <span class="learn-stat-number">${paths.length}+</span>
                            <span class="learn-stat-label">Learning Paths</span>
                        </div>
                        <div class="learn-stat-item">
                            <span class="learn-stat-number">${walkthroughs.length}+</span>
                            <span class="learn-stat-label">Walkthroughs</span>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Tab Navigation -->
            <div class="learn-tabs-thm-container">
                <div class="learn-tabs-thm" style="justify-content: center;">
                    <button class="learn-tab-thm active" onclick="switchLearnTab('paths')" id="tab-paths">
                        <i class="fa-solid fa-route"></i> Paths
                    </button>
                    <button class="learn-tab-thm" onclick="switchLearnTab('modules')" id="tab-modules">
                        <i class="fa-solid fa-cube"></i> Modules
                    </button>
                    <button class="learn-tab-thm" onclick="switchLearnTab('walkthroughs')" id="tab-walkthroughs">
                        <i class="fa-solid fa-book-open"></i> Walkthroughs
                    </button>
                    <button class="learn-tab-thm" onclick="switchLearnTab('networks')" id="tab-networks">
                        <i class="fa-solid fa-network-wired"></i> Networks
                    </button>
                </div>
            </div>

            <!-- Main Content Area -->
            <div class="learn-main-content">

            <!-- Paths Tab - TryHackMe Style -->
            <div class="learn-tab-content active" id="content-paths">
                <style>
                    /* ============ PATHS TAB - DARK THEME ============ */
                    #content-paths {
                        background: #141d2b;
                        padding: 40px;
                        min-height: 100vh;
                    }
                    .paths-header-thm {
                        margin-bottom: 30px;
                    }
                    .paths-header-thm h1 {
                        font-size: 1.8rem;
                        font-weight: 700;
                        color: #fff;
                        margin-bottom: 8px;
                    }
                    .paths-header-thm p {
                        color: #94a3b8;
                        font-size: 1rem;
                    }
                    .paths-toolbar-thm {
                        display: flex;
                        justify-content: space-between;
                        align-items: center;
                        margin-bottom: 30px;
                        gap: 20px;
                        flex-wrap: wrap;
                    }
                    .paths-search-thm {
                        display: flex;
                        align-items: center;
                        background: #1e293b;
                        border: 1px solid #334155;
                        border-radius: 8px;
                        padding: 10px 16px;
                        flex: 1;
                        max-width: 350px;
                    }
                    .paths-search-thm i {
                        color: #94a3b8;
                        margin-right: 10px;
                    }
                    .paths-search-thm input {
                        border: none;
                        outline: none;
                        background: transparent;
                        font-size: 0.95rem;
                        color: #fff;
                        width: 100%;
                    }
                    .paths-search-thm input::placeholder {
                        color: #64748b;
                    }
                    /* Paths Sub-tabs Styles */
                    .paths-subtabs-thm {
                        display: flex;
                        gap: 10px;
                        margin-bottom: 25px;
                        flex-wrap: wrap;
                    }
                    .paths-subtab {
                        padding: 12px 24px;
                        background: #1e293b;
                        border: 1px solid #334155;
                        border-radius: 8px;
                        color: #94a3b8;
                        font-size: 0.95rem;
                        font-weight: 600;
                        cursor: pointer;
                        transition: all 0.3s ease;
                        display: flex;
                        align-items: center;
                        gap: 8px;
                    }
                    .paths-subtab:hover {
                        border-color: #22c55e;
                        color: #fff;
                        background: rgba(34, 197, 94, 0.1);
                    }
                    .paths-subtab.active {
                        background: #22c55e;
                        border-color: #22c55e;
                        color: #0d1117;
                    }
                    .paths-subtab i {
                        font-size: 0.9rem;
                    }
                    .paths-filters-thm {
                        display: flex;
                        gap: 12px;
                    }
                    .paths-filters-thm select {
                        padding: 10px 16px;
                        border: 1px solid #334155;
                        border-radius: 8px;
                        background: #1e293b;
                        color: #94a3b8;
                        font-size: 0.9rem;
                        cursor: pointer;
                        min-width: 130px;
                    }
                    .paths-filters-thm select:hover {
                        border-color: #9fef00;
                    }
                    .paths-grid-thm {
                        display: grid;
                        grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
                        gap: 24px;
                    }
                    .path-card-thm {
                        background: #1a2332;
                        border-radius: 12px;
                        overflow: hidden;
                        box-shadow: 0 2px 8px rgba(0,0,0,0.3);
                        cursor: pointer;
                        transition: all 0.25s ease;
                        border: 1px solid transparent;
                    }
                    .path-card-thm:hover {
                        transform: translateY(-8px) scale(1.01);
                        border-color: #9fef00;
                        box-shadow: 0 15px 40px rgba(0,0,0,0.5), 0 0 30px rgba(159, 239, 0, 0.15);
                    }
                    .path-card-image-thm {
                        height: 180px;
                        background: var(--card-bg, #22c55e);
                        position: relative;
                        display: flex;
                        align-items: center;
                        justify-content: center;
                        overflow: hidden;
                    }
                    .path-card-image-thm::before {
                        content: '';
                        position: absolute;
                        inset: 0;
                        background: linear-gradient(180deg, transparent 40%, rgba(0,0,0,0.6) 100%);
                        z-index: 1;
                    }
                    .path-card-img {
                        width: 100%;
                        height: 100%;
                        object-fit: cover;
                        transition: transform 0.4s ease;
                    }
                    .path-card-thm:hover .path-card-img {
                        transform: scale(1.08);
                    }
                    .path-card-image-thm i {
                        font-size: 4rem;
                        color: rgba(255,255,255,0.3);
                        position: absolute;
                        z-index: 2;
                    }
                    .path-progress-badge {
                        position: absolute;
                        top: 12px;
                        right: 12px;
                        width: 50px;
                        height: 50px;
                        border-radius: 50%;
                        background: rgba(0,0,0,0.7);
                        backdrop-filter: blur(8px);
                        display: flex;
                        flex-direction: column;
                        align-items: center;
                        justify-content: center;
                        font-size: 0.85rem;
                        font-weight: 700;
                        color: #9fef00;
                        border: 2px solid #9fef00;
                        z-index: 5;
                    }
                    .path-progress-badge span {
                        font-size: 1rem;
                        line-height: 1;
                    }
                    .path-progress-badge.completed {
                        background: #9fef00;
                        color: #0d1117;
                    }
                    .path-enrolled-badge {
                        position: absolute;
                        top: 12px;
                        left: 12px;
                        background: rgba(159, 239, 0, 0.95);
                        color: #0d1117;
                        padding: 6px 12px;
                        font-size: 0.7rem;
                        font-weight: 700;
                        border-radius: 20px;
                        z-index: 5;
                        display: flex;
                        align-items: center;
                        gap: 6px;
                    }
                    .path-card-body-thm {
                        padding: 20px;
                        border-left: 4px solid var(--card-bg, #22c55e);
                        background: linear-gradient(180deg, #1a2332 0%, #151d29 100%);
                    }
                    .path-type-badge {
                        display: inline-block;
                        font-size: 0.65rem;
                        font-weight: 700;
                        text-transform: uppercase;
                        letter-spacing: 0.5px;
                        padding: 4px 10px;
                        border-radius: 4px;
                        margin-bottom: 10px;
                    }
                    .path-type-badge.job {
                        background: rgba(236, 72, 153, 0.2);
                        color: #ec4899;
                        border: 1px solid rgba(236, 72, 153, 0.3);
                    }
                    .path-type-badge.skill {
                        background: rgba(59, 130, 246, 0.2);
                        color: #3b82f6;
                        border: 1px solid rgba(59, 130, 246, 0.3);
                    }
                    .path-card-body-thm h3 {
                        font-size: 1.15rem;
                        font-weight: 700;
                        color: #fff;
                        margin-bottom: 10px;
                        line-height: 1.3;
                    }
                    .path-card-body-thm p {
                        color: #8b949e;
                        font-size: 0.85rem;
                        line-height: 1.6;
                        margin-bottom: 15px;
                        display: -webkit-box;
                        -webkit-line-clamp: 2;
                        -webkit-box-orient: vertical;
                        overflow: hidden;
                    }
                    .path-meta-thm {
                        display: flex;
                        justify-content: space-between;
                        align-items: center;
                        padding-top: 12px;
                        border-top: 1px solid rgba(255,255,255,0.1);
                    }
                    .path-stats-row {
                        display: flex;
                        gap: 15px;
                    }
                    .path-stat {
                        display: flex;
                        align-items: center;
                        gap: 5px;
                        font-size: 0.75rem;
                        color: #8b949e;
                    }
                    .path-stat i {
                        font-size: 0.7rem;
                        color: #6e7681;
                    }
                    .path-difficulty-badge {
                        display: inline-flex;
                        align-items: center;
                        gap: 6px;
                        font-size: 0.75rem;
                        font-weight: 600;
                        padding: 5px 10px;
                        border-radius: 6px;
                    }
                    .path-difficulty-badge.easy, .path-difficulty-badge.basic {
                        color: #22c55e;
                        background: rgba(34, 197, 94, 0.15);
                    }
                    .path-difficulty-badge.medium, .path-difficulty-badge.intermediate {
                        color: #f59e0b;
                        background: rgba(245, 158, 11, 0.15);
                    }
                    .path-difficulty-badge.hard, .path-difficulty-badge.advanced {
                        color: #ef4444;
                        background: rgba(239, 68, 68, 0.15);
                    }
                    .path-difficulty-badge i {
                        font-size: 0.65rem;
                    }
                    @media (max-width: 768px) {
                        #content-paths { padding: 20px; }
                        .paths-toolbar-thm { flex-direction: column; align-items: stretch; }
                        .paths-search-thm { max-width: 100%; }
                        .paths-grid-thm { grid-template-columns: 1fr; }
                    }
                </style>
                
                <!-- Paths Header -->
                <div class="paths-header-thm">
                    <h1>Cyber Security Learning Paths</h1>
                    <p>Learn about cyber security and sharpen your skills by following a structured learning path.</p>
                </div>

                <!-- Sub-tabs Navigation -->
                <div class="paths-subtabs-thm">
                    <button class="paths-subtab active" onclick="switchPathsSubtab('all')" data-subtab="all">
                        <i class="fas fa-layer-group"></i> All Paths
                    </button>
                    <button class="paths-subtab" onclick="switchPathsSubtab('skill')" data-subtab="skill">
                        <i class="fas fa-tools"></i> Skill Paths
                    </button>
                    <button class="paths-subtab" onclick="switchPathsSubtab('job')" data-subtab="job">
                        <i class="fas fa-briefcase"></i> Job Role Paths
                    </button>
                </div>

                <!-- Search and Filter Toolbar -->
                <div class="paths-toolbar-thm">
                    <div class="paths-search-thm">
                        <i class="fas fa-search"></i>
                        <input type="text" id="paths-search" placeholder="Search learning paths..." oninput="filterPaths()">
                    </div>
                    <div class="paths-filters-thm">
                        <select id="filter-difficulty" onchange="filterPaths()">
                            <option value="">Difficulty</option>
                            <option value="basic">Basic</option>
                            <option value="easy">Easy</option>
                            <option value="medium">Medium</option>
                            <option value="hard">Hard</option>
                        </select>
                        <select id="filter-status" onchange="filterPaths()">
                            <option value="">Status</option>
                            <option value="not-started">Not Started</option>
                            <option value="in-progress">In Progress</option>
                            <option value="completed">Completed</option>
                        </select>
                    </div>
                </div>

                <!-- Paths Grid -->
                <div class="paths-grid-thm" id="paths-grid-container">
                    ${paths.map(path => {
        const isEnrolled = typeof EnrollmentSystem !== 'undefined' ? EnrollmentSystem.isEnrolled(path.id) : false;
        const pathProgress = typeof getPathProgress === 'function' ? getPathProgress(path.id) : { completedRooms: [] };
        const totalRooms = path.totalRooms || path.units?.reduce((acc, u) => acc + (u.rooms?.length || 0), 0) || 1;
        const completedCount = pathProgress.completedRooms?.length || 0;
        const progress = Math.round((completedCount / totalRooms) * 100);
        const statusClass = progress >= 100 ? 'completed' : (isEnrolled ? 'in-progress' : 'not-started');
        const difficultyClass = (path.difficulty || 'easy').toLowerCase();
        const pathType = path.type || 'skill'; // Default to 'skill' if not specified

        // Determine illustration based on exact path ID
        const getPathImage = (pathId, pathName) => {
            const imageMap = {
                'pre-security': './assets/path-images/pre-security.png',
                'cyber-security-101': './assets/path-images/cyber-security-101.png',
                'security-engineer': './assets/path-images/security-engineer.png',
                'comptia-pentest-plus': './assets/path-images/comptia-pentest.png',
                'web-fundamentals': './assets/path-images/web-fundamentals.png',
                'soc-level-1': './assets/path-images/soc-level-1.png',
                'soc-level-2': './assets/path-images/soc-level-2.png',
                'devsecops': './assets/path-images/devsecops.png',
                'red-teaming': './assets/path-images/red-teaming.png',
                'offensive-pentesting': './assets/path-images/offensive-pentesting.png',
                'defending-azure': './assets/path-images/defending-azure.png',
                'advanced-endpoint-investigations': './assets/path-images/endpoint-investigations.png',
                'attacking-defending-aws': './assets/path-images/attacking-aws.png',
                'web-application-pentesting': './assets/path-images/web-app-pentesting.png',
                'penetration-tester': './assets/path-images/penetration-tester.png',
                'soc-analyst': './assets/path-images/soc-analyst-new.png',
                'senior-web-pentester': './assets/path-images/senior-web-pentester.png',
                'active-directory-pentester': './assets/path-images/ad-pentester.png',
                'ai-red-teamer': './assets/path-images/ai-red-teamer.png',
                'junior-cybersecurity-analyst': './assets/path-images/junior-analyst.png',
                'wifi-pentester': './assets/path-images/wifi-pentester.png'
            };

            // Check exact match first
            if (imageMap[pathId]) {
                return imageMap[pathId];
            }

            // Fallback to keyword matching for legacy paths
            const id = pathId.toLowerCase();
            const name = pathName.toLowerCase();
            if (id.includes('penetration') || id.includes('pentester')) {
                return './assets/path-images/penetration-testing.png';
            } else if (id.includes('soc') || name.includes('soc')) {
                return './assets/path-images/soc-analyst.png';
            } else if (id.includes('web')) {
                return './assets/path-images/web-security.png';
            } else if (id.includes('aws') || id.includes('cloud')) {
                return './assets/path-images/cloud-security.png';
            } else if (id.includes('azure')) {
                return './assets/path-images/defending-azure.png';
            } else if (id.includes('ai') || id.includes('machine')) {
                return './assets/path-images/ai-security.png';
            } else if (id.includes('wifi') || id.includes('wireless')) {
                return './assets/path-images/wifi-security.png';
            } else if (id.includes('active-directory') || id.includes('ad-')) {
                return './assets/path-images/active-directory.png';
            } else {
                return './assets/path-images/penetration-testing.png';
            }
        };
        const illustrationPath = getPathImage(path.id, path.name);

        return `
                        <div class="path-card-thm" style="--card-bg: ${path.color || '#3b82f6'};" 
                             data-name="${path.name.toLowerCase()}" 
                             data-difficulty="${difficultyClass}" 
                             data-status="${statusClass}"
                             data-type="${pathType}"
                             onclick="openLearningPath('${path.id}')">
                            <div class="path-card-image-thm" style="background: linear-gradient(135deg, ${path.color}dd 0%, ${path.color}99 100%);">
                                ${isEnrolled ? '<div class="path-enrolled-badge"><i class="fas fa-check-circle"></i> Enrolled</div>' : ''}
                                <img src="${illustrationPath}" alt="${path.name}" class="path-card-img" onerror="this.style.display='none'" />
                                
                                <!-- SVG Circular Progress -->
                                ${(() => {
                const r = 18;
                const c = 2 * Math.PI * r;
                const offset = c - ((progress || 0) / 100) * c;
                return `
                                    <div class="path-progress-ring-container" style="position: absolute; bottom: 15px; right: 15px; width: 44px; height: 44px; display: flex; align-items: center; justify-content: center; background: rgba(15, 23, 42, 0.6); backdrop-filter: blur(4px); border-radius: 50%; box-shadow: 0 4px 6px rgba(0,0,0,0.3);">
                                        <svg width="44" height="44" style="transform: rotate(-90deg);">
                                            <circle cx="22" cy="22" r="${r}" fill="transparent" stroke="rgba(255,255,255,0.1)" stroke-width="3"></circle>
                                            <circle cx="22" cy="22" r="${r}" fill="transparent" stroke="${path.color || '#22c55e'}" stroke-width="3" 
                                                    style="stroke-dasharray: ${c}; stroke-dashoffset: ${offset}; transition: stroke-dashoffset 1s ease; stroke-linecap: round;"></circle>
                                        </svg>
                                        <span style="position: absolute; color: #fff; font-size: 10px; font-weight: 700;">${progress}%</span>
                                    </div>
                                    `;
            })()}
                            </div>
                            <div class="path-card-body-thm">
                                <div class="path-type-badge ${pathType}">${pathType === 'job' ? 'Job Role Path' : 'Skill Path'}</div>
                                <h3>${path.name}</h3>
                                <p>${path.description}</p>
                                <div class="path-meta-thm">
                                    <div class="path-stats-row">
                                        <span class="path-stat"><i class="fas fa-layer-group"></i> ${path.totalRooms || 0} Modules</span>
                                        <span class="path-stat"><i class="fas fa-clock"></i> ${path.estimatedHours || 0}h</span>
                                    </div>
                                    <div class="path-difficulty-badge ${difficultyClass}">
                                        <i class="fas fa-signal"></i> ${difficultyClass.charAt(0).toUpperCase() + difficultyClass.slice(1)}
                                    </div>
                                </div>
                            </div>
                        </div>
                    `}).join('')}
                </div>
            </div>

            <div class="learn-tab-content" id="content-modules">
                <style>
                    /* ============ PHASE 3: MODULES REDESIGN - GLASSMORPHISM CYBERPUNK ============ */
                    #content-modules {
                        background: #0f172a;
                        padding: 40px;
                        min-height: 100vh;
                        background-image: 
                            radial-gradient(circle at 10% 20%, rgba(34, 197, 94, 0.05) 0%, transparent 20%),
                            radial-gradient(circle at 90% 80%, rgba(139, 92, 246, 0.05) 0%, transparent 20%);
                    }

                    /* 1. Professional Header with Animated Background */
                    .modules-hero {
                        text-align: center;
                        padding: 60px 40px;
                        background: linear-gradient(135deg, rgba(30, 41, 59, 0.7) 0%, rgba(15, 23, 42, 0.9) 100%);
                        border-radius: 24px;
                        border: 1px solid rgba(255, 255, 255, 0.1);
                        margin-bottom: 40px;
                        position: relative;
                        overflow: hidden;
                        backdrop-filter: blur(20px);
                        box-shadow: 0 20px 50px rgba(0,0,0,0.3);
                    }
                    .modules-hero::before {
                        content: '';
                        position: absolute;
                        top: -50%; left: -50%; width: 200%; height: 200%;
                        background: conic-gradient(from 0deg at 50% 50%, transparent 0deg, rgba(34, 197, 94, 0.1) 60deg, transparent 120deg);
                        animation: rotateHero 10s linear infinite;
                        pointer-events: none;
                    }
                    @keyframes rotateHero { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }
                    
                    .modules-hero h1 {
                        font-size: 3.5rem;
                        font-weight: 800;
                        margin-bottom: 15px;
                        background: linear-gradient(to right, #fff, #4ade80);
                        -webkit-background-clip: text;
                        -webkit-text-fill-color: transparent;
                        position: relative;
                        z-index: 1;
                        text-shadow: 0 0 30px rgba(34, 197, 94, 0.3);
                    }
                    .modules-hero p {
                        font-size: 1.1rem;
                        color: #94a3b8;
                        max-width: 600px;
                        margin: 0 auto;
                        position: relative;
                        z-index: 1;
                    }

                    /* 2. Filter Bar */
                    .modules-filter-container {
                        display: flex;
                        justify-content: space-between;
                        align-items: center;
                        flex-wrap: wrap;
                        gap: 20px;
                        margin-bottom: 40px;
                        background: rgba(30, 41, 59, 0.4);
                        padding: 15px 25px;
                        border-radius: 16px;
                        border: 1px solid rgba(255, 255, 255, 0.05);
                        backdrop-filter: blur(10px);
                    }
                    .filter-group {
                        display: flex;
                        gap: 12px;
                        flex-wrap: wrap;
                    }
                    .cyber-select {
                        background: rgba(15, 23, 42, 0.6);
                        border: 1px solid rgba(255, 255, 255, 0.1);
                        color: #fff;
                        padding: 10px 16px;
                        border-radius: 8px;
                        font-size: 0.9rem;
                        outline: none;
                        cursor: pointer;
                        transition: all 0.3s ease;
                    }
                    .cyber-select:hover, .cyber-select:focus {
                        border-color: #22c55e;
                        box-shadow: 0 0 10px rgba(34, 197, 94, 0.2);
                    }
                    .cyber-search {
                        position: relative;
                        min-width: 250px;
                    }
                    .cyber-search input {
                        width: 100%;
                        background: rgba(15, 23, 42, 0.6);
                        border: 1px solid rgba(255, 255, 255, 0.1);
                        color: #fff;
                        padding: 10px 16px 10px 40px;
                        border-radius: 8px;
                        font-size: 0.9rem;
                        outline: none;
                        transition: all 0.3s ease;
                    }
                    .cyber-search i {
                        position: absolute;
                        left: 14px;
                        top: 50%;
                        transform: translateY(-50%);
                        color: #64748b;
                    }
                    .cyber-search input:focus {
                        border-color: #22c55e;
                        box-shadow: 0 0 15px rgba(34, 197, 94, 0.2);
                    }

                    /* 3. Grid Layout */
                    .modules-grid-glass {
                        display: grid;
                        grid-template-columns: repeat(auto-fill, minmax(340px, 1fr));
                        gap: 30px;
                    }

                    /* 4. Module Card Design */
                    .module-card-glass {
                        background: rgba(30, 41, 59, 0.4);
                        backdrop-filter: blur(20px);
                        -webkit-backdrop-filter: blur(20px);
                        border: 1px solid rgba(255, 255, 255, 0.08);
                        border-radius: 20px;
                        overflow: hidden;
                        transition: all 0.4s cubic-bezier(0.175, 0.885, 0.32, 1.275);
                        position: relative;
                        display: flex;
                        flex-direction: column;
                    }
                    .module-card-glass:hover {
                        transform: translateY(-10px);
                        border-color: #22c55e;
                        box-shadow: 0 20px 40px rgba(0,0,0,0.4), 0 0 20px rgba(34, 197, 94, 0.2);
                    }
                    .module-card-glass::before {
                        content: '';
                        position: absolute;
                        top: 0; left: 0; right: 0; height: 3px;
                        background: linear-gradient(90deg, #22c55e, #3b82f6);
                        opacity: 0;
                        transition: opacity 0.3s;
                    }
                    .module-card-glass:hover::before { opacity: 1; }

                    .card-header-glass {
                        padding: 20px;
                        display: flex;
                        justify-content: space-between;
                        align-items: flex-start;
                    }
                    .card-icon-box {
                        width: 50px; height: 50px;
                        background: rgba(34, 197, 94, 0.1);
                        border-radius: 12px;
                        display: flex; align-items: center; justify-content: center;
                        font-size: 24px; color: #22c55e;
                        border: 1px solid rgba(34, 197, 94, 0.2);
                    }
                    .card-difficulty {
                        padding: 4px 10px;
                        border-radius: 20px;
                        font-size: 11px;
                        font-weight: 700;
                        text-transform: uppercase;
                        background: rgba(255, 255, 255, 0.05);
                        border: 1px solid rgba(255, 255, 255, 0.1);
                    }
                    .card-difficulty.easy { color: #22c55e; border-color: rgba(34, 197, 94, 0.3); background: rgba(34, 197, 94, 0.1); }
                    .card-difficulty.medium { color: #f59e0b; border-color: rgba(245, 158, 11, 0.3); background: rgba(245, 158, 11, 0.1); }
                    .card-difficulty.hard { color: #ef4444; border-color: rgba(239, 68, 68, 0.3); background: rgba(239, 68, 68, 0.1); }

                    .card-body-glass {
                        padding: 0 20px 20px;
                        flex: 1;
                        display: flex;
                        flex-direction: column;
                    }
                    .card-title {
                        font-size: 1.2rem;
                        font-weight: 700;
                        color: #fff;
                        margin-bottom: 8px;
                    }
                    .card-desc {
                        font-size: 0.9rem;
                        color: #94a3b8;
                        line-height: 1.5;
                        margin-bottom: 15px;
                        display: -webkit-box;
                        -webkit-line-clamp: 2;
                        -webkit-box-orient: vertical;
                        overflow: hidden;
                    }
                    .card-skills {
                        display: flex;
                        gap: 8px;
                        flex-wrap: wrap;
                        margin-bottom: 20px;
                    }
                    .skill-tag {
                        background: rgba(255, 255, 255, 0.03);
                        border: 1px solid rgba(255, 255, 255, 0.05);
                        padding: 4px 8px;
                        border-radius: 6px;
                        font-size: 11px;
                        color: #cbd5e1;
                    }

                    .card-footer-glass {
                        padding: 15px 20px;
                        border-top: 1px solid rgba(255, 255, 255, 0.05);
                        background: rgba(0, 0, 0, 0.2);
                        display: flex;
                        justify-content: space-between;
                        align-items: center;
                    }
                    .card-meta {
                        display: flex;
                        gap: 15px;
                        font-size: 12px;
                        color: #64748b;
                    }
                    .card-meta span { display: flex; align-items: center; gap: 5px; }
                    .card-meta i { color: #22c55e; }

                    .start-btn {
                        padding: 8px 16px;
                        background: linear-gradient(135deg, #22c55e 0%, #16a34a 100%);
                        border-radius: 8px;
                        color: #fff;
                        font-weight: 600;
                        font-size: 12px;
                        text-decoration: none;
                        transition: all 0.3s ease;
                        box-shadow: 0 4px 10px rgba(34, 197, 94, 0.3);
                        border: none;
                        cursor: pointer;
                    }
                    .start-btn:hover {
                        transform: translateY(-2px);
                        box-shadow: 0 6px 15px rgba(34, 197, 94, 0.4);
                    }
                </style>

                <!-- 1. Hero Section -->
                <div class="modules-hero">
                    <h1>Explore Modules</h1>
                    <p>Master specific techniques with hands-on labs. Filter by difficulty, category, or team to find your next challenge.</p>
                </div>

                <!-- 2. Filter Bar -->
                <div class="modules-filter-container">
                    <div class="filter-group">
                        <select id="filter-category" class="cyber-select" onchange="filterModulesCyber()">
                            <option value="">All Categories</option>
                            <option value="web">Web Exploitation</option>
                            <option value="network">Network Security</option>
                            <option value="forensics">Digital Forensics</option>
                            <option value="linux">Linux Privilege Escalation</option>
                        </select>
                        <select id="filter-difficulty" class="cyber-select" onchange="filterModulesCyber()">
                            <option value="">All Difficulties</option>
                            <option value="easy">Easy</option>
                            <option value="medium">Medium</option>
                            <option value="hard">Hard</option>
                        </select>
                        <select id="filter-team" class="cyber-select" onchange="filterModulesCyber()">
                            <option value="">All Teams</option>
                            <option value="red">Red Team (Offensive)</option>
                            <option value="blue">Blue Team (Defensive)</option>
                        </select>
                    </div>
                    <div class="cyber-search">
                        <i class="fas fa-search"></i>
                        <input type="text" id="module-search" placeholder="Search modules..." oninput="filterModulesCyber()">
                    </div>
                </div>

                <!-- 3. Module Grid -->
                <div class="modules-grid-glass" id="modules-grid-container">
                    ${modules.map(mod => {
                const difficulty = (mod.difficulty || 'medium').toLowerCase();
                const type = (mod.type || 'general').toLowerCase();
                const team = type === 'offensive' ? 'red' : (type === 'defensive' ? 'blue' : 'purple');
                const icon = mod.icon || 'fa-cube';

                return `
                        <div class="module-card-glass" 
                             data-category="${(mod.category || 'general').toLowerCase()}" 
                             data-difficulty="${difficulty}" 
                             data-team="${team}"
                             data-title="${mod.title.toLowerCase()}">
                            
                            <div class="card-header-glass">
                                <div class="card-icon-box">
                                    <i class="fas ${icon}"></i>
                                </div>
                                <div class="card-difficulty ${difficulty}">
                                    ${difficulty}
                                </div>
                            </div>

                            <div class="card-body-glass">
                                <h3 class="card-title">${mod.title}</h3>
                                <p class="card-desc">${mod.description || 'Learn key cybersecurity concepts in this hands-on module. Master tools and techniques used by professionals.'}</p>
                                
                                <div class="card-skills">
                                    ${(mod.tags || ['Security', 'Basics']).slice(0, 3).map(tag => `<span class="skill-tag">#${tag}</span>`).join('')}
                                </div>
                            </div>

                            <div class="card-footer-glass">
                                <div class="card-meta">
                                    <span><i class="fas fa-clock"></i> ${mod.time || '1h'}</span>
                                    <span><i class="fas fa-server"></i> ${mod.rooms || '1'} Lab</span>
                                    <span><i class="fas fa-coins"></i> Free</span>
                                </div>
                                <button class="start-btn" onclick="openModule('${mod.id}')">Start Module</button>
                            </div>
                        </div>
                        `;
            }).join('')}
                </div>

                <script>
                    function filterModulesCyber() {
                        const search = document.getElementById('module-search').value.toLowerCase();
                        const category = document.getElementById('filter-category').value.toLowerCase();
                        const difficulty = document.getElementById('filter-difficulty').value.toLowerCase();
                        const team = document.getElementById('filter-team').value.toLowerCase();
                        const cards = document.querySelectorAll('.module-card-glass');

                        cards.forEach(card => {
                            const cTitle = card.getAttribute('data-title');
                            const cCategory = card.getAttribute('data-category');
                            const cDifficulty = card.getAttribute('data-difficulty');
                            const cTeam = card.getAttribute('data-team');

                            const matchesSearch = cTitle.includes(search);
                            const matchesCategory = !category || cCategory === category || (category === 'web' && cCategory.includes('web'));
                            const matchesDifficulty = !difficulty || cDifficulty === difficulty;
                            const matchesTeam = !team || cTeam === team;

                            if (matchesSearch && matchesCategory && matchesDifficulty && matchesTeam) {
                                card.style.display = 'flex';
                            } else {
                                card.style.display = 'none';
                            }
                        });
                    }
                </script>
            </div>

            <!-- Walkthroughs Tab -->
            <div class="learn-tab-content" id="content-walkthroughs">
                <style>
                    #content-walkthroughs {
                        background: #141d2b;
                        padding: 40px;
                        min-height: 100vh;
                    }
                    #content-walkthroughs .modules-header h1 {
                        color: #fff;
                    }
                    #content-walkthroughs .modules-header p {
                        color: #94a3b8;
                    }
                    .walkthroughs-filter-bar {
                        display: flex;
                        gap: 15px;
                        margin-bottom: 30px;
                        flex-wrap: wrap;
                        align-items: center;
                    }
                    .walkthroughs-filter-bar .search-box {
                        display: flex;
                        align-items: center;
                        background: #1e293b;
                        border: 1px solid #334155;
                        border-radius: 8px;
                        padding: 10px 16px;
                        flex: 1;
                        max-width: 350px;
                    }
                    .walkthroughs-filter-bar .search-box i {
                        color: #64748b;
                        margin-right: 10px;
                    }
                    .walkthroughs-filter-bar .search-box input {
                        border: none;
                        outline: none;
                        background: transparent;
                        color: #fff;
                        font-size: 0.95rem;
                        width: 100%;
                    }
                    .walkthroughs-filter-bar .search-box input::placeholder {
                        color: #64748b;
                    }
                    .walkthroughs-filter-bar select {
                        padding: 10px 16px;
                        border: 1px solid #334155;
                        border-radius: 8px;
                        background: #1e293b;
                        color: #94a3b8;
                        font-size: 0.9rem;
                        cursor: pointer;
                    }
                    .walkthroughs-filter-bar select:hover {
                        border-color: #9fef00;
                    }
                    .walkthroughs-grid {
                        display: grid;
                        grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
                        gap: 20px;
                    }
                    .walkthrough-card-new {
                        background: #1a2332;
                        border-radius: 12px;
                        padding: 20px;
                        cursor: pointer;
                        transition: all 0.25s ease;
                        border: 1px solid transparent;
                        position: relative;
                    }
                    .walkthrough-card-new:hover {
                        transform: translateY(-5px);
                        border-color: #9fef00;
                        box-shadow: 0 10px 30px rgba(0,0,0,0.4);
                    }
                    .wt-title {
                        color: #fff;
                        font-size: 1rem;
                        font-weight: 700;
                        margin-bottom: 15px;
                    }
                    .wt-icon-circle {
                        width: 50px;
                        height: 50px;
                        border-radius: 50%;
                        display: flex;
                        align-items: center;
                        justify-content: center;
                        position: absolute;
                        top: 20px;
                        right: 20px;
                    }
                    .wt-icon-circle i {
                        color: #fff;
                        font-size: 1.3rem;
                    }
                    .wt-card-footer {
                        display: flex;
                        justify-content: space-between;
                        align-items: center;
                        margin-top: 15px;
                        padding-top: 15px;
                        border-top: 1px solid #334155;
                    }
                    .wt-meta-left {
                        display: flex;
                        gap: 15px;
                        color: #64748b;
                        font-size: 0.8rem;
                    }
                    .wt-meta-left i {
                        margin-right: 5px;
                    }
                    .wt-difficulty.easy { color: #22c55e; }
                    .wt-difficulty.medium { color: #f59e0b; }
                    .wt-difficulty.hard { color: #ef4444; }
                    .wt-favorite {
                        color: #64748b;
                        cursor: pointer;
                    }
                    .wt-favorite:hover {
                        color: #ef4444;
                    }
                </style>
                <!-- Walkthroughs Header -->
                <div class="modules-header">
                    <h1>Walkthroughs</h1>
                    <p>Guided labs and lessons teaching you specific cyber topics.</p>
                </div>

                <!-- Walkthroughs Filter Bar -->
                <div class="walkthroughs-filter-bar">
                    <div class="search-box">
                        <i class="fas fa-search"></i>
                        <input type="text" id="walkthroughs-search" placeholder="Search" oninput="filterWalkthroughs()">
                    </div>
                    <div class="filter-dropdowns">
                        <select id="filter-difficulty-wt" onchange="filterWalkthroughs()">
                            <option value="">Difficulty</option>
                            <option value="easy">Easy</option>
                            <option value="medium">Medium</option>
                            <option value="hard">Hard</option>
                        </select>
                        <select id="filter-status-wt" onchange="filterWalkthroughs()">
                            <option value="">Status</option>
                            <option value="not-started">Not Started</option>
                            <option value="in-progress">In Progress</option>
                            <option value="completed">Completed</option>
                        </select>
                    </div>
                </div>

                <!-- Walkthroughs Grid -->
                <div class="walkthroughs-grid" id="walkthroughs-grid-container">
                    ${walkthroughs.map(wt => {
                const difficulty = wt.difficulty || 'medium';
                const icon = wt.icon || (wt.os === 'windows' ? 'fa-windows' : 'fa-linux');
                const color = wt.color || (wt.os === 'windows' ? '#0078d4' : '#f59e0b');
                return `
                            <div class="walkthrough-card-new" 
                                 data-difficulty="${difficulty}"
                                 data-title="${wt.title.toLowerCase()}"
                                 data-status="not-started"
                                 onclick="openWalkthrough('${wt.id}')">
                                <div class="wt-card-content">
                                    <h3 class="wt-title">${wt.title}</h3>
                                </div>
                                <div class="wt-icon-circle" style="background: ${color};">
                                    <i class="fa-solid ${icon}"></i>
                                </div>
                                <div class="wt-card-footer">
                                    <div class="wt-meta-left">
                                        <span class="wt-download"><i class="fas fa-download"></i></span>
                                        <span class="wt-difficulty ${difficulty}"><i class="fas fa-signal"></i> ${difficulty.charAt(0).toUpperCase() + difficulty.slice(1)}</span>
                                        <span class="wt-time"><i class="fas fa-clock"></i> ${wt.estimatedTime}</span>
                                    </div>
                                    <span class="wt-favorite"><i class="far fa-heart"></i></span>
                                </div>
                            </div>
                        `}).join('')}
                </div>
            </div>


            <!-- Modules Tab -->
            <div class="learn-tab-content" id="content-modules">
                <!-- Modules content will be injected by pageModulesEnhanced() -->
                <div style="text-align: center; padding: 50px;">
                    <i class="fas fa-circle-notch fa-spin" style="font-size: 2rem; color: #3b82f6;"></i>
                    <p style="margin-top: 15px; color: #94a3b8;">Loading Modules...</p>
                </div>
            </div>

            <!-- Networks Tab -->
            <div class="learn-tab-content" id="content-networks">
                <style>
                    #content-networks {
                        background: #141d2b;
                        padding: 40px;
                        min-height: 100vh;
                    }
                    #content-networks .modules-header h1 {
                        color: #fff;
                    }
                    #content-networks .modules-header p {
                        color: #94a3b8;
                    }
                    .net-filter {
                        padding: 10px 16px;
                        border: 1px solid #334155;
                        border-radius: 8px;
                        background: #1e293b;
                        color: #94a3b8;
                        font-size: 0.9rem;
                        cursor: pointer;
                    }
                    .net-filter:hover {
                        border-color: #9fef00;
                    }
                    .networks-grid {
                        display: grid;
                        grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
                        gap: 20px;
                    }
                    .network-card-new {
                        background: #1a2332;
                        border-radius: 12px;
                        overflow: hidden;
                        cursor: pointer;
                        transition: all 0.25s ease;
                        border: 1px solid transparent;
                    }
                    .network-card-new:hover {
                        transform: translateY(-5px);
                        border-color: #9fef00;
                        box-shadow: 0 10px 30px rgba(0,0,0,0.4);
                    }
                    .net-card-top {
                        padding: 20px;
                        display: flex;
                        align-items: flex-start;
                        gap: 15px;
                    }
                    .net-icon-box {
                        width: 50px;
                        height: 50px;
                        border-radius: 10px;
                        background: linear-gradient(135deg, #3b82f6, #8b5cf6);
                        display: flex;
                        align-items: center;
                        justify-content: center;
                        flex-shrink: 0;
                    }
                    .net-icon-box i {
                        color: #fff;
                        font-size: 1.3rem;
                    }
                    .net-info h3 {
                        color: #fff;
                        font-size: 1rem;
                        font-weight: 700;
                        margin-bottom: 8px;
                    }
                    .net-info p {
                        color: #64748b;
                        font-size: 0.8rem;
                        line-height: 1.5;
                    }
                    .net-card-bottom {
                        padding: 15px 20px;
                        border-top: 1px solid #334155;
                        display: flex;
                        justify-content: space-between;
                        align-items: center;
                    }
                    .net-meta {
                        display: flex;
                        gap: 15px;
                        color: #64748b;
                        font-size: 0.8rem;
                    }
                    .net-difficulty.easy { color: #22c55e; }
                    .net-difficulty.medium { color: #f59e0b; }
                    .net-difficulty.hard { color: #ef4444; }
                    .net-difficulty.insane { color: #dc2626; }
                    .net-badge {
                        padding: 4px 10px;
                        border-radius: 4px;
                        font-size: 0.7rem;
                        font-weight: 600;
                    }
                    .net-badge.premium {
                        background: rgba(245,158,11,0.15);
                        color: #f59e0b;
                    }
                    .net-badge.free {
                        background: rgba(34,197,94,0.15);
                        color: #22c55e;
                    }
                </style>
            <!-- Networks Tab -->
            <div class="learn-tab-content" id="content-networks">
                <style>
                    /* Reuse glassmorphism module styles */
                </style>
                <div class="modules-header">
                    <h1>Networks</h1>
                    <p>Content that uses virtual vulnerable networks.</p>
                </div>

                <!-- Networks Filter Bar -->
                <div class="networks-filter-bar" style="display: flex; gap: 15px; margin-bottom: 30px; flex-wrap: wrap;">
                    <select class="net-filter" id="net-sort" onchange="filterNetworks()">
                        <option value="">Sort by</option>
                        <option value="newest">Newest</option>
                        <option value="popular">Most Popular</option>
                    </select>
                    <select class="net-filter" id="net-difficulty" onchange="filterNetworks()">
                        <option value="">Difficulty</option>
                        <option value="easy">Easy</option>
                        <option value="medium">Medium</option>
                        <option value="hard">Hard</option>
                        <option value="insane">Insane</option>
                    </select>
                    <select class="net-filter" id="net-type" onchange="filterNetworks()">
                        <option value="">Room Type</option>
                        <option value="network">Network</option>
                        <option value="ctf">CTF</option>
                    </select>
                    <select class="net-filter" id="net-sub" onchange="filterNetworks()">
                        <option value="">Subscription type</option>
                        <option value="free">Free</option>
                        <option value="premium">Premium</option>
                    </select>
                    <select class="net-filter" id="net-status" onchange="filterNetworks()">
                        <option value="">Status</option>
                        <option value="todo">To Do</option>
                        <option value="completed">Completed</option>
                    </select>
                </div>

                <div class="networks-grid" id="networks-grid-container">
                    ${networks.map(net => {
                    const isPremium = net.type === 'premium';
                    const streakReq = net.streakRequired || 0;
                    const difficulty = net.difficulty || 'medium';
                    const status = net.status || 'todo';

                    return `
                            <div class="network-card-new" 
                                 data-difficulty="${difficulty}"
                                 data-type="${net.type}"
                                 data-status="${status}"
                                 data-id="${net.id}"
                                 onclick="openNetwork('${net.id}')">
                                <div class="net-card-top">
                                    <div class="net-icon-box">
                                        <i class="fa-solid ${net.icon || 'fa-network-wired'}"></i>
                                    </div>
                                    <div class="net-content">
                                        <h3 class="net-title">${net.title}</h3>
                                        <p class="net-desc">${net.description}</p>
                                    </div>
                                </div>
                                <div class="net-card-bottom">
                                    <div class="net-difficulty ${difficulty}">
                                        <i class="fas fa-signal"></i> ${difficulty.charAt(0).toUpperCase() + difficulty.slice(1)}
                                    </div>
                                    <div class="net-badges">
                                        <span class="net-badge ${isPremium ? 'premium' : 'free'}">${isPremium ? 'Premium' : 'Free'}</span>
                                        ${streakReq > 0 ? `<span class="net-badge streak">Streak required: ${streakReq} <i class="fas fa-bolt"></i></span>` : ''}
                                    </div>
                                </div>
                            </div>
                            `;
                }).join('')}
                </div>
            </div>
            </div>
        </div>
    </div>
    `;
}

// Duplicate switchLearnTab removed - using global one at end of file

// Make switchLearnTab globally available
// switchLearnTab is now handled globally in app.js

// Filter paths based on search and dropdowns
function filterPaths() {
    const searchTerm = (document.getElementById('paths-search')?.value || '').toLowerCase().trim();
    const difficultyFilter = document.getElementById('filter-difficulty')?.value || '';
    const statusFilter = document.getElementById('filter-status')?.value || '';

    const pathCards = document.querySelectorAll('#paths-grid-container .path-card');

    pathCards.forEach(card => {
        const name = card.dataset.name || '';
        const difficulty = card.dataset.difficulty || '';
        const status = card.dataset.status || '';

        // Check search match
        const matchesSearch = !searchTerm || name.includes(searchTerm);

        // Check difficulty match
        const matchesDifficulty = !difficultyFilter || difficulty === difficultyFilter;

        // Check status match
        const matchesStatus = !statusFilter || status === statusFilter;

        // Show/hide based on all filters
        if (matchesSearch && matchesDifficulty && matchesStatus) {
            card.style.display = '';
        } else {
            card.style.display = 'none';
        }
    });
}

// Make filterPaths globally available
window.filterPaths = filterPaths;

// Filter and sort modules based on dropdowns
function filterModules() {
    const searchTerm = (document.getElementById('modules-search')?.value || '').toLowerCase().trim();
    const difficultyFilter = document.getElementById('filter-difficulty-modules')?.value || '';
    const statusFilter = document.getElementById('filter-status-modules')?.value || '';

    const container = document.getElementById('modules-grid-container');
    if (!container) return;

    const moduleCards = Array.from(container.querySelectorAll('.module-card-new'));

    // Filter cards
    moduleCards.forEach(card => {
        const title = card.dataset.title || '';
        const difficulty = card.dataset.difficulty || '';
        const status = card.dataset.status || 'not-started';

        const matchesSearch = !searchTerm || title.includes(searchTerm);
        const matchesDifficulty = !difficultyFilter || difficulty === difficultyFilter;
        const matchesStatus = !statusFilter || status === statusFilter;

        if (matchesSearch && matchesDifficulty && matchesStatus) {
            card.style.display = '';
        } else {
            card.style.display = 'none';
        }
    });
}

// Make filterModules globally available
window.filterModules = filterModules;

// Filter walkthroughs based on search and dropdowns
function filterWalkthroughs() {
    const searchTerm = (document.getElementById('walkthroughs-search')?.value || '').toLowerCase().trim();
    const difficultyFilter = document.getElementById('filter-difficulty-wt')?.value || '';
    const statusFilter = document.getElementById('filter-status-wt')?.value || '';

    const container = document.getElementById('walkthroughs-grid-container');
    if (!container) return;

    const cards = Array.from(container.querySelectorAll('.walkthrough-card-new'));

    cards.forEach(card => {
        const title = card.dataset.title || '';
        const difficulty = card.dataset.difficulty || '';
        const status = card.dataset.status || 'not-started';

        const matchesSearch = !searchTerm || title.includes(searchTerm);
        const matchesDifficulty = !difficultyFilter || difficulty === difficultyFilter;
        const matchesStatus = !statusFilter || status === statusFilter;

        if (matchesSearch && matchesDifficulty && matchesStatus) {
            card.style.display = '';
        } else {
            card.style.display = 'none';
        }
    });
}

// Make filterWalkthroughs globally available
window.filterWalkthroughs = filterWalkthroughs;

// Filter Networks based on dropdowns
function filterNetworks() {
    const sortValue = document.getElementById('net-sort')?.value || '';
    const difficultyFilter = document.getElementById('net-difficulty')?.value || '';
    const typeFilter = document.getElementById('net-type')?.value || '';
    const subFilter = document.getElementById('net-sub')?.value || '';
    const statusFilter = document.getElementById('net-status')?.value || '';

    const container = document.getElementById('networks-grid-container');
    if (!container) return;

    const cards = Array.from(container.querySelectorAll('.network-card-new'));

    // Filter Logic
    cards.forEach(card => {
        const difficulty = card.dataset.difficulty || '';
        const type = card.dataset.type || '';
        const status = card.dataset.status || 'todo';

        // Map premium/free type to subscription filter
        // If subFilter is 'free', we want type != 'premium'
        // If subFilter is 'premium', we want type == 'premium'
        let matchesSub = true;
        if (subFilter === 'free') matchesSub = (type !== 'premium');
        if (subFilter === 'premium') matchesSub = (type === 'premium');

        const matchesDifficulty = !difficultyFilter || difficulty === difficultyFilter;
        // Room type filter: "network" is default for now as all are networks, but we check if type matches
        // For simplicity assuming all here are "network" unless specified otherwise, but data has type='premium'/'free'
        // The "Room Type" dropdown had options "network" and "ctf". 
        // Our data doesn't currently strictly separate CTF/Network in a 'roomType' field, 
        // but let's assume all current items are networks.
        const matchesType = !typeFilter || typeFilter === 'network';

        const matchesStatus = !statusFilter || status === statusFilter;

        if (matchesDifficulty && matchesSub && matchesType && matchesStatus) {
            card.style.display = '';
        } else {
            card.style.display = 'none';
        }
    });

    // Sort Logic (Basic Implementation)
    if (sortValue === 'newest') {
        // Assuming current order is roughly newest or custom. 
        // To implement true sorting we need data attributes for date.
        // For now, we can reverse the array to simulate "newest" if default is oldest.
        // Or leave as is if no date data.
    }
    // Additional sort logic can be added here if dates/popularity stats are available in DOM
}

// Make filterNetworks globally available
window.filterNetworks = filterNetworks;

// Handle path enrollment with proper UI feedback
async function handleEnrollPath(pathId, buttonElement) {
    try {
        // Check if EnrollmentSystem exists
        if (typeof EnrollmentSystem === 'undefined') {
            console.error('EnrollmentSystem not found');
            showEnrollmentToast('خطأ: نظام التسجيل غير متاح', 'error');
            return;
        }

        // Get path data to check if premium
        const pathData = window.UnifiedLearningData?.paths?.find(p => p.id === pathId);

        // Check if premium
        if (pathData?.premium === true) {
            // Check if user has premium subscription
            const user = JSON.parse(sessionStorage.getItem('user') || '{}');
            const hasPremium = user.premium === true || user.subscription === 'premium';

            if (!hasPremium) {
                // Show premium modal
                EnrollmentSystem.showPremiumRequired(pathId, pathData?.name);
                return;
            }
        }

        // Enroll in path
        const result = await EnrollmentSystem.enrollInPath(pathId);

        if (result.success) {
            // Save last enrolled
            localStorage.setItem('shadowhack_last_enrolled', pathId);

            // Show success notification
            showEnrollmentToast('🎉 You are enrolled now!', 'success');

            // Re-render the path detail page to show enrolled view
            setTimeout(() => {
                navigateToPath(pathId);
            }, 500);
        }
    } catch (error) {
        console.error('Enrollment error:', error);
        showEnrollmentToast('حدث خطأ أثناء التسجيل', 'error');
    }
}

// Show enrollment toast notification
function showEnrollmentToast(message, type = 'success') {
    // Remove existing toast
    const existingToast = document.querySelector('.enrollment-toast');
    if (existingToast) existingToast.remove();

    const toast = document.createElement('div');
    toast.className = 'enrollment-toast';
    toast.innerHTML = `
        < i class="fas ${type === 'success' ? 'fa-check-circle' : 'fa-exclamation-circle'}" ></i >
            <span>${message}</span>
    `;
    toast.style.cssText = `
    position: fixed;
    top: 100px;
    right: 30px;
    background: ${type === 'success' ? 'linear-gradient(135deg, #22c55e, #16a34a)' : 'linear-gradient(135deg, #ef4444, #dc2626)'};
    color: white;
    padding: 16px 28px;
    border - radius: 14px;
    font - weight: 600;
    font - size: 15px;
    display: flex;
    align - items: center;
    gap: 12px;
    box - shadow: 0 10px 40px rgba(0, 0, 0, 0.4);
    z - index: 10000;
    animation: slideInRight 0.4s ease;
    `;

    // Add animation keyframes
    if (!document.querySelector('#enrollment-toast-styles')) {
        const style = document.createElement('style');
        style.id = 'enrollment-toast-styles';
        style.textContent = `
    @keyframes slideInRight {
                from { transform: translateX(100 %); opacity: 0; }
                to { transform: translateX(0); opacity: 1; }
    }
    `;
        document.head.appendChild(style);
    }

    document.body.appendChild(toast);

    // Auto remove after 4 seconds
    setTimeout(() => {
        toast.style.animation = 'slideInRight 0.3s ease reverse';
        setTimeout(() => toast.remove(), 300);
    }, 4000);
}

// Update Enroll button to Enrolled/Resume
function updateEnrollButton(pathId) {
    // Find the enroll button container
    const buttonContainer = document.querySelector('.units-section > div:first-child');
    if (!buttonContainer) return;

    // Replace button with green "Enrolled" button
    const enrollButton = buttonContainer.querySelector('button');
    if (enrollButton) {
        enrollButton.innerHTML = '<i class="fa-solid fa-check"></i> Enrolled ✓';
        enrollButton.style.background = 'linear-gradient(135deg, #22c55e, #16a34a)';
        enrollButton.style.boxShadow = '0 10px 30px rgba(34, 197, 94, 0.4)';
        enrollButton.disabled = true;
        enrollButton.style.cursor = 'default';

        // Add animation
        enrollButton.style.animation = 'pulse 0.5s ease';
    }

    // Hide the "Enroll to unlock" message
    const lockMessage = buttonContainer.querySelector('span');
    if (lockMessage && lockMessage.textContent.includes('Enroll')) {
        lockMessage.style.display = 'none';
    }
}

// Unlock all room items after enrollment
function unlockRoomItems() {
    const roomItems = document.querySelectorAll('.room-item.locked');
    roomItems.forEach((room, index) => {
        // Add delay for staggered animation
        setTimeout(() => {
            room.classList.remove('locked');
            room.style.opacity = '1';

            // Update icon from lock to door
            const icon = room.querySelector('.room-icon i');
            if (icon && icon.classList.contains('fa-lock')) {
                icon.classList.remove('fa-lock');
                icon.classList.add('fa-door-open');
            }

            // Reset icon style
            const iconDiv = room.querySelector('.room-icon');
            if (iconDiv) {
                iconDiv.style.background = '';
                iconDiv.style.color = '';
            }

            // Update onclick to open room instead of enrollment popup
            const roomId = room.getAttribute('onclick')?.match(/openRoom\('([^']+)'\)/)?.[1];
            if (roomId) {
                room.setAttribute('onclick', `openRoom('${roomId}')`);
            }

            // Add unlock animation
            room.style.animation = 'unlockRoom 0.4s ease';
        }, index * 100);
    });

    // Add unlock animation keyframes
    if (!document.querySelector('#unlock-room-styles')) {
        const style = document.createElement('style');
        style.id = 'unlock-room-styles';
        style.textContent = `
    @keyframes unlockRoom {
                from { transform: scale(0.95); opacity: 0.5; }
                to { transform: scale(1); opacity: 1; }
    }
    @keyframes pulse {
        0 %, 100 % { transform: scale(1); }
        50 % { transform: scale(1.05); }
    }
    `;
        document.head.appendChild(style);
    }
}

// Make functions globally available
window.handleEnrollPath = handleEnrollPath;
window.showEnrollmentToast = showEnrollmentToast;

// Navigate to a specific path from roadmap step
function navigateToPath(pathId) {
    const pathData = window.UnifiedLearningData?.getPathById(pathId);
    if (pathData) {
        openLearningPath(pathId);
    } else {
        // Might be a module, try to find it
        const module = window.UnifiedLearningData?.modules?.find(m => m.id === pathId);
        if (module) {
            showNotification('Module: ' + module.title, 'info');
            // Switch to modules tab and highlight
            switchLearnTab('modules');
        } else {
            console.warn('Path/Module not found:', pathId);
        }
    }
}

// Open roadmap detail view
function openRoadmapDetail(roadmapId) {
    const roadmap = window.UnifiedLearningData?.roadmaps?.find(r => r.id === roadmapId);
    if (!roadmap) return;

    // Store current roadmap for navigation
    window.currentRoadmap = roadmap;
    window.currentPage = 'roadmap-detail';

    document.getElementById('content').innerHTML = renderRoadmapDetailPage(roadmap);
}

// Render full roadmap detail page with paths list
function renderRoadmapDetailPage(roadmap) {
    const paths = window.UnifiedLearningData?.paths || [];
    const flow = roadmap.flow_structure || { steps: [] };

    // Calculate progress
    const totalPaths = flow.steps.length;
    const completedPaths = flow.steps.filter(step => isPathFullyCompleted(step.path_id)).length;
    const progressPercent = totalPaths > 0 ? (completedPaths / totalPaths) * 100 : 0;

    return `
        < div class="roadmap-detail-page" >
            <style>
                .roadmap-detail-page {
                    min-height: 100vh;
                    background: linear-gradient(135deg, #0f0c29 0%, #302b63 50%, #24243e 100%);
                    padding: 40px 20px;
                }
                .roadmap-detail-container { max-width: 1200px; margin: 0 auto; }
                .roadmap-back-btn {
                    background: rgba(255,255,255,0.05);
                    border: 1px solid rgba(255,255,255,0.1);
                    color: rgba(255,255,255,0.7);
                    padding: 12px 20px;
                    border-radius: 10px;
                    cursor: pointer;
                    display: inline-flex;
                    align-items: center;
                    gap: 10px;
                    margin-bottom: 30px;
                    transition: all 0.3s ease;
                }
                .roadmap-back-btn:hover { background: rgba(255,255,255,0.1); color: #fff; }
                
                .roadmap-detail-header {
                    background: rgba(255,255,255,0.03);
                    border: 2px solid rgba(255,255,255,0.1);
                    border-radius: 24px;
                    padding: 40px;
                    margin-bottom: 40px;
                    position: relative;
                    overflow: hidden;
                }
                .roadmap-detail-header::before {
                    content: '';
                    position: absolute;
                    inset: 0;
                    background: linear-gradient(135deg, ${roadmap.color}15, transparent);
                    pointer-events: none;
                }
                .roadmap-detail-top { display: flex; align-items: center; gap: 30px; margin-bottom: 30px; }
                .roadmap-detail-icon {
                    width: 100px; height: 100px;
                    background: linear-gradient(135deg, ${roadmap.color}, ${roadmap.color}cc);
                    border-radius: 24px;
                    display: flex; align-items: center; justify-content: center;
                    font-size: 45px; color: #fff;
                    box-shadow: 0 15px 40px ${roadmap.color}40;
                }
                .roadmap-detail-info { flex: 1; }
                .roadmap-detail-title { font-size: 2.5rem; font-weight: 800; color: #fff; margin-bottom: 10px; }
                .roadmap-detail-desc { color: rgba(255,255,255,0.6); font-size: 16px; line-height: 1.6; }
                
                .roadmap-progress-section {
                    background: rgba(0,0,0,0.2);
                    border-radius: 16px;
                    padding: 25px;
                    margin-top: 25px;
                }
                .roadmap-progress-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px; }
                .roadmap-progress-label { color: rgba(255,255,255,0.7); font-size: 14px; }
                .roadmap-progress-value { color: ${roadmap.color}; font-weight: 700; font-size: 16px; }
                .roadmap-progress-bar {
                    height: 12px;
                    background: rgba(255,255,255,0.1);
                    border-radius: 6px;
                    overflow: hidden;
                }
                .roadmap-progress-fill {
                    height: 100%;
                    background: linear-gradient(90deg, ${roadmap.color}, ${roadmap.color}cc);
                    border-radius: 6px;
                    transition: width 0.5s ease;
                }
                
                .roadmap-start-btn-large {
                    margin-top: 25px;
                    padding: 16px 40px;
                    background: linear-gradient(135deg, ${roadmap.color}, ${roadmap.color}dd);
                    border: none;
                    border-radius: 14px;
                    color: #fff;
                    font-weight: 700;
                    font-size: 16px;
                    cursor: pointer;
                    display: inline-flex;
                    align-items: center;
                    gap: 12px;
                    transition: all 0.3s ease;
                }
                .roadmap-start-btn-large:hover { transform: translateY(-2px); box-shadow: 0 10px 30px ${roadmap.color}40; }
                
                .roadmap-paths-section { margin-top: 30px; }
                .roadmap-paths-title { color: #fff; font-size: 1.5rem; font-weight: 700; margin-bottom: 25px; }
                .roadmap-paths-title i { color: ${roadmap.color}; margin-right: 12px; }
                
                .roadmap-path-list { display: flex; flex-direction: column; gap: 20px; }
                .roadmap-path-item {
                    background: rgba(255,255,255,0.03);
                    border: 2px solid rgba(255,255,255,0.1);
                    border-radius: 18px;
                    padding: 25px;
                    display: flex;
                    align-items: center;
                    gap: 25px;
                    cursor: pointer;
                    transition: all 0.3s ease;
                    position: relative;
                }
                .roadmap-path-item:hover { border-color: ${roadmap.color}60; transform: translateX(5px); }
                .roadmap-path-item.completed { border-color: #22c55e60; }
                .roadmap-path-item.current { border-color: ${roadmap.color}; box-shadow: 0 0 20px ${roadmap.color}30; }
                .roadmap-path-item.locked { opacity: 0.5; cursor: not-allowed; }
                
                .path-step-number {
                    width: 55px; height: 55px;
                    background: linear-gradient(135deg, ${roadmap.color}40, ${roadmap.color}20);
                    border: 2px solid ${roadmap.color}60;
                    border-radius: 50%;
                    display: flex; align-items: center; justify-content: center;
                    font-size: 22px; font-weight: 800; color: ${roadmap.color};
                    flex-shrink: 0;
                }
                .roadmap-path-item.completed .path-step-number {
                    background: linear-gradient(135deg, #22c55e, #16a34a);
                    border-color: #22c55e;
                    color: #fff;
                }
                .roadmap-path-item.locked .path-step-number {
                    background: rgba(255,255,255,0.05);
                    border-color: rgba(255,255,255,0.2);
                    color: rgba(255,255,255,0.3);
                }
                
                .path-item-content { flex: 1; }
                .path-item-label { color: ${roadmap.color}; font-size: 12px; font-weight: 600; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 5px; }
                .path-item-title { color: #fff; font-size: 1.3rem; font-weight: 700; margin-bottom: 8px; }
                .path-item-desc { color: rgba(255,255,255,0.5); font-size: 14px; }
                .path-item-meta { display: flex; gap: 20px; margin-top: 12px; }
                .path-item-meta span { color: rgba(255,255,255,0.4); font-size: 13px; display: flex; align-items: center; gap: 6px; }
                .path-item-meta i { color: ${roadmap.color}; }
                
                .path-item-status {
                    padding: 10px 20px;
                    border-radius: 10px;
                    font-size: 13px;
                    font-weight: 600;
                    display: flex;
                    align-items: center;
                    gap: 8px;
                }
                .path-item-status.completed { background: rgba(34, 197, 94, 0.2); color: #22c55e; }
                .path-item-status.current { background: linear-gradient(135deg, ${roadmap.color}30, ${roadmap.color}20); color: ${roadmap.color}; }
                .path-item-status.locked { background: rgba(255,255,255,0.05); color: rgba(255,255,255,0.4); }
            </style>
            
            <div class="roadmap-detail-container">
                <button class="roadmap-back-btn" onclick="loadPage('learn')">
                    <i class="fa-solid fa-arrow-left"></i>
                    Back to Learning Center
                </button>
                
                <div class="roadmap-detail-header">
                    <div class="roadmap-detail-top">
                        <div class="roadmap-detail-icon">
                            <i class="fa-solid ${roadmap.icon}"></i>
                        </div>
                        <div class="roadmap-detail-info">
                            <h1 class="roadmap-detail-title">${roadmap.title}</h1>
                            <p class="roadmap-detail-desc">${roadmap.description}</p>
                        </div>
                    </div>
                    
                    <div class="roadmap-progress-section">
                        <div class="roadmap-progress-header">
                            <span class="roadmap-progress-label"><i class="fa-solid fa-chart-line" style="margin-right: 8px;"></i>Your Progress</span>
                            <span class="roadmap-progress-value">${completedPaths}/${totalPaths} Paths Completed</span>
                        </div>
                        <div class="roadmap-progress-bar">
                            <div class="roadmap-progress-fill" style="width: ${progressPercent}%;"></div>
                        </div>
                    </div>
                    
                    <button class="roadmap-start-btn-large" onclick="startRoadmapSequence('${roadmap.id}')">
                        <i class="fa-solid fa-play"></i>
                        ${completedPaths > 0 ? 'Continue Roadmap' : 'Start Roadmap'}
                    </button>
                </div>
                
                <div class="roadmap-paths-section">
                    <h2 class="roadmap-paths-title"><i class="fa-solid fa-route"></i>Learning Paths in this Roadmap</h2>
                    
                    <div class="roadmap-path-list">
                        ${flow.steps.map((step, index) => {
        const pathData = paths.find(p => p.id === step.path_id);
        const isCompleted = isPathFullyCompleted(step.path_id);
        const isLocked = !isCompleted && index > 0 && !isPathFullyCompleted(flow.steps[index - 1]?.path_id);
        const isCurrent = !isCompleted && !isLocked;
        const statusClass = isCompleted ? 'completed' : (isLocked ? 'locked' : 'current');

        return `
                                <div class="roadmap-path-item ${statusClass}" onclick="${isLocked ? '' : `openLearningPath('${step.path_id}')`}">
                                    <div class="path-step-number">
                                        ${isCompleted ? '<i class="fa-solid fa-check"></i>' : (index + 1)}
                                    </div>
                                    <div class="path-item-content">
                                        <div class="path-item-label">${step.label || 'Step ' + (index + 1)}</div>
                                        <div class="path-item-title">${pathData?.name || step.path_id}</div>
                                        <div class="path-item-desc">${pathData?.description || 'Learn and practice cybersecurity skills'}</div>
                                        <div class="path-item-meta">
                                            <span><i class="fa-solid fa-clock"></i> ${pathData?.estimatedHours || 'N/A'}h</span>
                                            <span><i class="fa-solid fa-layer-group"></i> ${pathData?.units?.length || 0} Units</span>
                                            <span><i class="fa-solid fa-door-open"></i> ${countPathRooms(step.path_id)} Rooms</span>
                                        </div>
                                    </div>
                                    <div class="path-item-status ${statusClass}">
                                        <i class="fa-solid fa-${isCompleted ? 'check-circle' : (isLocked ? 'lock' : 'play-circle')}"></i>
                                        ${isCompleted ? 'Completed' : (isLocked ? 'Locked' : 'In Progress')}
                                    </div>
                                </div>
                            `;
    }).join('')}
                    </div>
                </div>
            </div>
        </div >
        `;
}

// Count total rooms in a path
function countPathRooms(pathId) {
    const pathData = window.UnifiedLearningData?.getPathById(pathId);
    if (!pathData || !pathData.units) return 0;
    return pathData.units.reduce((sum, unit) => sum + (unit.rooms?.length || 0), 0);
}

// Check if a path is fully completed (all rooms done)
function isPathFullyCompleted(pathId) {
    const pathData = window.UnifiedLearningData?.getPathById(pathId);
    if (!pathData || !pathData.units) return false;

    const progress = getPathProgress(pathId);
    const totalRooms = countPathRooms(pathId);

    return progress.completedRooms.length >= totalRooms && totalRooms > 0;
}

// Get roadmap progress
function getRoadmapProgress(roadmapId) {
    const savedProgress = localStorage.getItem('roadmapProgress_' + roadmapId);
    if (savedProgress) {
        return JSON.parse(savedProgress);
    }
    return {
        roadmapId: roadmapId,
        completedPaths: [],
        currentPathIndex: 0,
        startedAt: Date.now()
    };
}

function saveRoadmapProgress(progress) {
    progress.lastAccessedAt = Date.now();
    localStorage.setItem('roadmapProgress_' + progress.roadmapId, JSON.stringify(progress));
}

// Start roadmap in sequence - find next incomplete path
function startRoadmapSequence(roadmapId) {
    const roadmap = window.UnifiedLearningData?.roadmaps?.find(r => r.id === roadmapId);
    if (!roadmap) return;

    const flow = roadmap.flow_structure || { steps: [] };

    // Find first incomplete path
    for (const step of flow.steps) {
        if (!isPathFullyCompleted(step.path_id)) {
            // Store that we're in a roadmap sequence
            window.currentRoadmapId = roadmapId;
            startPath(step.path_id);
            return;
        }
    }

    // All paths completed - show roadmap completion!
    showRoadmapCompletion(roadmapId);
}

// Show roadmap completion celebration
function showRoadmapCompletion(roadmapId) {
    const roadmap = window.UnifiedLearningData?.roadmaps?.find(r => r.id === roadmapId);
    if (!roadmap) return;

    // Mark roadmap as complete
    const completedRoadmaps = JSON.parse(localStorage.getItem('completedRoadmaps') || '[]');
    if (!completedRoadmaps.includes(roadmapId)) {
        completedRoadmaps.push(roadmapId);
        localStorage.setItem('completedRoadmaps', JSON.stringify(completedRoadmaps));
    }

    const flow = roadmap.flow_structure || { steps: [] };
    const totalPaths = flow.steps.length;
    const totalXP = totalPaths * 500; // Estimate XP

    document.getElementById('content').innerHTML = `
        < div class="roadmap-completion-page" >
            <style>
                .roadmap-completion-page {
                    min - height: 100vh;
                background: linear-gradient(135deg, #0f0c29 0%, #302b63 50%, #24243e 100%);
                display: flex;
                align-items: center;
                justify-content: center;
                padding: 40px;
                position: relative;
                overflow: hidden;
                }
                .roadmap-completion-page::before {
                    content: '';
                position: absolute;
                inset: 0;
                background: radial-gradient(circle at 50% 30%, ${roadmap.color}30, transparent 70%);
                animation: pulse-bg 3s ease-in-out infinite;
                }
                @keyframes pulse-bg {
                    0 %, 100 % { opacity: 0.5; }
                    50% {opacity: 1; }
                }
                .completion-card {
                    background: rgba(255,255,255,0.05);
                border: 2px solid ${roadmap.color}60;
                border-radius: 32px;
                padding: 60px;
                text-align: center;
                max-width: 600px;
                position: relative;
                z-index: 1;
                animation: pop-in 0.5s ease-out;
                }
                @keyframes pop-in {
                    from {transform: scale(0.8); opacity: 0; }
                to {transform: scale(1); opacity: 1; }
                }
                .completion-trophy {
                    font - size: 80px;
                margin-bottom: 30px;
                animation: bounce 2s ease-in-out infinite;
                }
                @keyframes bounce {
                    0 %, 100 % { transform: translateY(0); }
                    50% {transform: translateY(-15px); }
                }
                .completion-title {
                    font - size: 2.5rem;
                font-weight: 800;
                color: #fff;
                margin-bottom: 15px;
                background: linear-gradient(90deg, #fff, ${roadmap.color});
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
                }
                .completion-subtitle {color: rgba(255,255,255,0.7); font-size: 18px; margin-bottom: 40px; }

                .completion-stats {
                    display: flex;
                justify-content: center;
                gap: 40px;
                margin-bottom: 40px;
                }
                .completion-stat {
                    text - align: center;
                }
                .completion-stat-value {
                    font - size: 2.5rem;
                font-weight: 800;
                color: ${roadmap.color};
                font-family: 'Orbitron', sans-serif;
                }
                .completion-stat-label {color: rgba(255,255,255,0.5); font-size: 14px; }

                .completion-badge-preview {
                    width: 150px; height: 150px;
                margin: 0 auto 30px;
                background: linear-gradient(135deg, ${roadmap.color}, ${roadmap.color}80);
                border-radius: 50%;
                display: flex; align-items: center; justify-content: center;
                font-size: 60px; color: #fff;
                box-shadow: 0 15px 50px ${roadmap.color}50;
                animation: glow 2s ease-in-out infinite alternate;
                }
                @keyframes glow {
                    from {box - shadow: 0 15px 50px ${roadmap.color}30; }
                to {box - shadow: 0 15px 80px ${roadmap.color}60; }
                }

                .completion-actions {display: flex; gap: 15px; justify-content: center; flex-wrap: wrap; }
                .completion-btn {
                    padding: 16px 30px;
                border-radius: 12px;
                font-weight: 700;
                font-size: 15px;
                cursor: pointer;
                display: flex;
                align-items: center;
                gap: 10px;
                transition: all 0.3s ease;
                }
                .completion-btn.primary {
                    background: linear-gradient(135deg, ${roadmap.color}, ${roadmap.color}cc);
                border: none;
                color: #fff;
                }
                .completion-btn.secondary {
                    background: transparent;
                border: 2px solid ${roadmap.color}60;
                color: ${roadmap.color};
                }
                .completion-btn:hover {transform: translateY(-2px); }

                .confetti {
                    position: absolute;
                width: 10px;
                height: 10px;
                border-radius: 50%;
                animation: confetti-fall 3s ease-in-out infinite;
                }
                @keyframes confetti-fall {
                    0 % { transform: translateY(-100vh) rotate(0deg); opacity: 1; }
                    100% {transform: translateY(100vh) rotate(720deg); opacity: 0; }
                }
            </style>
            
            ${generateConfetti(30)}

    <div class="completion-card">
        <div class="completion-trophy">🏆</div>
        <h1 class="completion-title">Roadmap Complete!</h1>
        <p class="completion-subtitle">You've mastered "${roadmap.title}"</p>

        <div class="completion-badge-preview">
            <i class="fa-solid ${roadmap.icon}"></i>
        </div>

        <div class="completion-stats">
            <div class="completion-stat">
                <div class="completion-stat-value">${totalPaths}</div>
                <div class="completion-stat-label">Paths Completed</div>
            </div>
            <div class="completion-stat">
                <div class="completion-stat-value">${totalXP}</div>
                <div class="completion-stat-label">XP Earned</div>
            </div>
        </div>

        <div class="completion-actions">
            <button class="completion-btn primary" onclick="viewRoadmapCertificate('${roadmapId}')">
                <i class="fa-solid fa-certificate"></i>
                View Certificate
            </button>
            <button class="completion-btn secondary" onclick="viewRoadmapBadge('${roadmapId}')">
                <i class="fa-solid fa-award"></i>
                View Badge
            </button>
            <button class="completion-btn secondary" onclick="loadPage('learn')">
                <i class="fa-solid fa-arrow-left"></i>
                Back to Roadmaps
            </button>
        </div>
    </div>
        </div >
        `;
}

// Generate confetti HTML
function generateConfetti(count) {
    const colors = ['#ef4444', '#f59e0b', '#22c55e', '#3b82f6', '#8b5cf6', '#ec4899'];
    let html = '';
    for (let i = 0; i < count; i++) {
        const color = colors[Math.floor(Math.random() * colors.length)];
        const left = Math.random() * 100;
        const delay = Math.random() * 3;
        const size = 5 + Math.random() * 10;
        html += `< div class="confetti" style = "left: ${left}%; background: ${color}; width: ${size}px; height: ${size}px; animation-delay: ${delay}s;" ></div > `;
    }
    return html;
}

// View roadmap badge
function viewRoadmapBadge(roadmapId) {
    const roadmap = window.UnifiedLearningData?.roadmaps?.find(r => r.id === roadmapId);
    if (!roadmap) return;

    const modal = document.createElement('div');
    modal.innerHTML = `
        < div style = "position: fixed; inset: 0; background: rgba(0,0,0,0.8); display: flex; align-items: center; justify-content: center; z-index: 10000;" >
            <div style="background: linear-gradient(135deg, #1a1a2e, #16213e); border: 2px solid ${roadmap.color}60; border-radius: 24px; padding: 50px; text-align: center; max-width: 400px;">
                <div style="width: 150px; height: 150px; margin: 0 auto 25px; background: linear-gradient(135deg, ${roadmap.color}, ${roadmap.color}80); border-radius: 50%; display: flex; align-items: center; justify-content: center; box-shadow: 0 15px 50px ${roadmap.color}50;">
                    <i class="fa-solid ${roadmap.icon}" style="font-size: 60px; color: #fff;"></i>
                </div>
                <h2 style="color: #fff; font-size: 24px; margin-bottom: 10px;">${roadmap.title}</h2>
                <p style="color: rgba(255,255,255,0.6); margin-bottom: 20px;">Roadmap Mastery Badge</p>
                <p style="background: rgba(34, 197, 94, 0.1); border: 1px solid rgba(34, 197, 94, 0.3); padding: 10px 20px; border-radius: 10px; color: #22c55e; font-weight: 600;">
                    <i class="fa-solid fa-check-circle"></i> Earned ${new Date().toLocaleDateString()}
                </p>
                <button style="margin-top: 25px; padding: 12px 30px; background: transparent; border: 1px solid rgba(255,255,255,0.2); border-radius: 10px; color: #fff; cursor: pointer;" onclick="this.closest('div[style*=fixed]').remove()">Close</button>
            </div>
        </div >
        `;
    document.body.appendChild(modal);
}

// View roadmap certificate
function viewRoadmapCertificate(roadmapId) {
    const roadmap = window.UnifiedLearningData?.roadmaps?.find(r => r.id === roadmapId);
    if (!roadmap) return;

    const modal = document.createElement('div');
    modal.innerHTML = `
        < div style = "position: fixed; inset: 0; background: rgba(0,0,0,0.9); display: flex; align-items: center; justify-content: center; z-index: 10000; padding: 20px;" >
            <div style="background: linear-gradient(135deg, #fffef0, #fff8dc); border: 8px double #c9a227; border-radius: 8px; padding: 60px 80px; text-align: center; max-width: 700px; box-shadow: 0 20px 60px rgba(0,0,0,0.5);">
                <div style="font-family: 'Times New Roman', serif; color: #2c3e50;">
                    <p style="color: #c9a227; font-size: 14px; letter-spacing: 3px; margin-bottom: 10px;">CERTIFICATE OF COMPLETION</p>
                    <div style="border-top: 2px solid #c9a227; border-bottom: 2px solid #c9a227; padding: 20px 0; margin: 20px 0;">
                        <p style="font-size: 16px; color: #666; margin-bottom: 15px;">This is to certify that</p>
                        <p style="font-size: 28px; font-weight: bold; color: #2c3e50; margin-bottom: 15px;">Cybersecurity Student</p>
                        <p style="font-size: 16px; color: #666;">has successfully completed the</p>
                    </div>
                    <h1 style="font-size: 32px; color: ${roadmap.color}; margin: 20px 0; font-weight: bold;">${roadmap.title}</h1>
                    <p style="font-size: 14px; color: #666; margin-bottom: 30px;">Demonstrating proficiency in cybersecurity fundamentals and practical skills</p>
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-top: 40px;">
                        <div style="text-align: center;">
                            <p style="font-family: 'Brush Script MT', cursive; font-size: 24px; color: #2c3e50;">ShadowHack</p>
                            <p style="font-size: 12px; color: #666; border-top: 1px solid #ccc; padding-top: 5px;">Platform</p>
                        </div>
                        <div style="text-align: center;">
                            <p style="font-size: 14px; color: #2c3e50; font-weight: bold;">${new Date().toLocaleDateString()}</p>
                            <p style="font-size: 12px; color: #666; border-top: 1px solid #ccc; padding-top: 5px;">Date</p>
                        </div>
                    </div>
                </div>
                <button style="margin-top: 30px; padding: 12px 30px; background: ${roadmap.color}; border: none; border-radius: 8px; color: #fff; cursor: pointer; font-weight: bold;" onclick="this.closest('div[style*=fixed]').remove()">Close Certificate</button>
            </div>
        </div >
        `;
    document.body.appendChild(modal);
}

// Check if should show "Next Path" after path completion
function checkForNextPathInRoadmap() {
    if (!window.currentRoadmapId) return null;

    const roadmap = window.UnifiedLearningData?.roadmaps?.find(r => r.id === window.currentRoadmapId);
    if (!roadmap) return null;

    const flow = roadmap.flow_structure || { steps: [] };

    // Find current path index
    const currentPathId = window.currentRoom?.path?.id;
    const currentIndex = flow.steps.findIndex(s => s.path_id === currentPathId);

    if (currentIndex >= 0 && currentIndex < flow.steps.length - 1) {
        return {
            nextPath: flow.steps[currentIndex + 1],
            roadmap: roadmap,
            isLast: currentIndex === flow.steps.length - 2
        };
    }

    return null;
}

// Helper notification function - TryHackMe style centered toast
function showNotification(message, type = 'info') {
    // Remove any existing notifications
    document.querySelectorAll('.thm-toast-notification').forEach(el => el.remove());

    const notification = document.createElement('div');
    const bgColor = type === 'info' ? '#3b82f6' : (type === 'success' ? '#22c55e' : (type === 'warning' ? '#f59e0b' : '#ef4444'));
    const iconClass = type === 'info' ? 'fa-info-circle' : (type === 'success' ? 'fa-check-circle' : (type === 'warning' ? 'fa-exclamation-triangle' : 'fa-times-circle'));
    const emoji = type === 'success' ? '🎉' : (type === 'error' ? '❌' : (type === 'warning' ? '⚠️' : 'ℹ️'));

    notification.className = 'thm-toast-notification';
    notification.innerHTML = `
        < div class="toast-icon" > ${emoji}</div >
            <div class="toast-content">
                <i class="fa-solid ${iconClass}"></i>
                <span>${message}</span>
            </div>
    `;
    notification.style.cssText = `
    position: fixed;
    top: 50 %;
    left: 50 %;
    transform: translate(-50 %, -50 %) scale(0.8);
    background: linear - gradient(135deg, ${bgColor}, ${bgColor}dd);
    color: #fff;
    padding: 25px 40px;
    border - radius: 20px;
    font - weight: 700;
    font - size: 18px;
    z - index: 100000;
    display: flex;
    flex - direction: column;
    align - items: center;
    gap: 15px;
    box - shadow: 0 20px 60px rgba(0, 0, 0, 0.5), 0 0 0 4px ${bgColor} 40;
    animation: toastPopIn 0.4s cubic - bezier(0.175, 0.885, 0.32, 1.275) forwards;
    text - align: center;
    min - width: 200px;
    `;

    // Add animation style if not exists
    if (!document.getElementById('toast-animation-style')) {
        const style = document.createElement('style');
        style.id = 'toast-animation-style';
        style.textContent = `
    @keyframes toastPopIn {
        0 % { transform: translate(-50 %, -50 %) scale(0.5); opacity: 0; }
        100 % { transform: translate(-50 %, -50 %) scale(1); opacity: 1; }
    }
    @keyframes toastPopOut {
        0 % { transform: translate(-50 %, -50 %) scale(1); opacity: 1; }
        100 % { transform: translate(-50 %, -50 %) scale(0.5); opacity: 0; }
    }
            .thm - toast - notification.toast - icon {
        font - size: 50px;
        line - height: 1;
    }
            .thm - toast - notification.toast - content {
        display: flex;
        align - items: center;
        gap: 10px;
    }
            .thm - toast - notification.toast - content i {
        font - size: 20px;
    }
    `;
        document.head.appendChild(style);
    }

    document.body.appendChild(notification);

    // Animate out and remove
    setTimeout(() => {
        notification.style.animation = 'toastPopOut 0.3s ease forwards';
        setTimeout(() => notification.remove(), 300);
    }, 2000);
}

// Make functions globally available
window.navigateToPath = navigateToPath;
window.openRoadmapDetail = openRoadmapDetail;
window.startRoadmapSequence = startRoadmapSequence;
window.showRoadmapCompletion = showRoadmapCompletion;
window.viewRoadmapBadge = viewRoadmapBadge;
window.viewRoadmapCertificate = viewRoadmapCertificate;
window.isPathFullyCompleted = isPathFullyCompleted;
window.getRoadmapProgress = getRoadmapProgress;

// ==================== START LEARNING FUNCTIONS ====================
// Start a roadmap - opens the first path's first room
function startRoadmap(roadmapId) {
    const roadmap = window.UnifiedLearningData?.roadmaps?.find(r => r.id === roadmapId);
    if (!roadmap) {
        showNotification('Roadmap not found', 'error');
        return;
    }

    // Find the first available step
    const firstStep = roadmap.flow_structure?.steps.find(s => s.status === 'available');
    if (firstStep) {
        startPath(firstStep.path_id);
    } else {
        showNotification('Starting ' + roadmap.title + '...', 'info');
        // Try first path
        const firstPath = roadmap.flow_structure?.steps[0];
        if (firstPath) {
            startPath(firstPath.path_id);
        }
    }
}

// Start a path - opens the first room of the first unit
function startPath(pathId) {
    const pathData = window.UnifiedLearningData?.getPathById(pathId);
    if (!pathData) {
        showNotification('Path not found', 'error');
        return;
    }

    // Find the first unit with rooms
    const firstUnit = pathData.units?.find(u => u.rooms && u.rooms.length > 0);
    if (firstUnit && firstUnit.rooms[0]) {
        showNotification('Starting ' + pathData.name + '...', 'success');
        // Prevent hash change from re-routing
        window.currentPage = 'room';
        openRoom(firstUnit.rooms[0].id);
    } else {
        // No rooms yet, open the path detail page
        openLearningPath(pathId);
        showNotification('This path is under development', 'info');
    }
}

// Start a module - opens linked rooms or shows coming soon
function startModule(moduleId) {
    const mod = window.UnifiedLearningData?.modules?.find(m => m.id === moduleId);
    if (!mod) {
        showNotification('Module not found', 'error');
        return;
    }

    if (mod.roomIds && mod.roomIds.length > 0) {
        showNotification('Starting ' + mod.title + '...', 'success');
        setTimeout(() => {
            openRoom(mod.roomIds[0]);
        }, 500);
    } else {
        openModule(moduleId);
        showNotification('Content coming soon!', 'info');
    }
}

// Start a machine (walkthrough or network) - shows machine simulation
// Start a machine (walkthrough, network, or room) - CONNECTS TO BACKEND
async function startMachine(type, id) {
    const btn = event?.currentTarget;
    const originalText = btn ? btn.innerHTML : '';
    if (btn) {
        btn.disabled = true;
        btn.innerHTML = '<i class="fa-solid fa-circle-notch fa-spin"></i> Spawning...';
    }

    // Resolve Machine details
    let machineTitle = id;
    if (type === 'walkthrough') {
        machineTitle = window.UnifiedLearningData?.walkthroughs?.find(w => w.id === id)?.title || id;
    } else if (type === 'network') {
        machineTitle = window.UnifiedLearningData?.networks?.find(n => n.id === id)?.title || id;
    }

    try {
        if (typeof showNotification === 'function') showNotification('Deploying container...', 'info');

        const response = await fetch('http://localhost:5000/api/labs/spawn', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                user_id: 1, // Default user
                lab_id: id, // Matches backend AVAILABLE_LABS keys
                image_name: 'nginx:alpine' // Default fallback
            })
        });

        const data = await response.json();

        if (data.success) {
            console.log('Machine Spawned:', data);
            if (typeof showNotification === 'function') showNotification('Machine Deployed Successfully!', 'success');

            // Pass the REAL data to the renderer
            const machineData = {
                id: id,
                title: machineTitle,
                ip: data.ip || '127.0.0.1',
                port: data.port || 80,
                internal_port: data.internal_port,
                container_id: data.container_id,
                expires_at: data.expires_at
            };

            // Switch view with Error Boundary
            try {
                const contentEl = document.getElementById('content');
                if (!contentEl) throw new Error('Content container not found');

                const renderedHtml = renderMachineStartPage(machineData, type);
                if (!renderedHtml) throw new Error('Render function returned empty content');

                contentEl.innerHTML = renderedHtml;

                // Initialize timer if available
                if (window.startMachineTimer) window.startMachineTimer(data.expires_at);

            } catch (renderError) {
                console.error('Render Error:', renderError);
                showNotification('UI Render Failed: ' + renderError.message, 'error');
                // Don't leave button spinning
                if (btn) {
                    btn.disabled = false;
                    btn.innerHTML = originalText || 'Start Machine';
                }
            }
        } else {
            throw new Error(data.error || 'Unknown error from backend');
        }

    } catch (e) {
        console.error('Spawn error:', e);
        if (typeof showNotification === 'function') showNotification('Failed: ' + e.message, 'error');
        if (btn) {
            btn.disabled = false;
            btn.innerHTML = originalText || 'Start Machine';
        }
    }
}

// Render machine starting page with timer
// Render machine starting page with REAL DATA
function renderMachineStartPage(machine, type) {
    // machine contains: ip, port, title, etc.
    const ipDisplay = machine.ip + (machine.port !== 80 && machine.port !== 443 ? ':' + machine.port : '');

    return `
        <div class="machine-start-page">
            <style>
                .machine-start-page {
                    min-height: 100vh;
                    background: linear-gradient(135deg, #0a0a1a 0%, #1a1a2e 50%, #0f0c29 100%);
                    display: flex;
                    flex-direction: column;
                }
                .machine-topbar {
                    background: rgba(0,0,0,0.5);
                    border-bottom: 1px solid rgba(255,255,255,0.1);
                    padding: 15px 30px;
                    display: flex;
                    align-items: center;
                    justify-content: space-between;
                }
                .machine-info { display: flex; align-items: center; gap: 20px; }
                .machine-icon {
                    width: 50px; height: 50px;
                    background: linear-gradient(135deg, #22c55e, #16a34a);
                    border-radius: 12px;
                    display: flex; align-items: center; justify-content: center;
                    font-size: 24px; color: #fff;
                }
                .machine-name-large { color: #fff; font-weight: 700; font-size: 1.2rem; }
                .machine-os { color: rgba(255,255,255,0.5); font-size: 14px; }
                .machine-stats { display: flex; gap: 30px; }
                .machine-stat-box {
                    background: rgba(255,255,255,0.05);
                    padding: 12px 20px;
                    border-radius: 10px;
                    text-align: center;
                }
                .stat-label { color: rgba(255,255,255,0.5); font-size: 12px; margin-bottom: 5px; }
                .stat-value { color: #22c55e; font-family: 'Orbitron', monospace; font-weight: 700; font-size: 1.1rem; }
                .ip-value { color: #f59e0b; font-size: 1.2rem; background: rgba(245, 158, 11, 0.1); padding: 5px 10px; border-radius: 4px; }
                .machine-content {
                    flex: 1;
                    display: flex;
                }
                .machine-terminal {
                    flex: 1;
                    background: #0a0a0a;
                    margin: 20px;
                    border-radius: 14px;
                    overflow: hidden;
                    font-family: 'JetBrains Mono', 'Fira Code', monospace;
                }
                .terminal-header {
                    background: rgba(255,255,255,0.05);
                    padding: 12px 20px;
                    display: flex;
                    align-items: center;
                    gap: 10px;
                }
                .terminal-dot { width: 12px; height: 12px; border-radius: 50%; }
                .terminal-dot.red { background: #ef4444; }
                .terminal-dot.yellow { background: #f59e0b; }
                .terminal-dot.green { background: #22c55e; }
                .terminal-title { color: rgba(255,255,255,0.6); font-size: 14px; margin-left: 15px; }
                .terminal-body {
                    padding: 20px;
                    color: #22c55e;
                    font-size: 14px;
                    line-height: 1.8;
                    height: 400px;
                    overflow-y: auto;
                }
                .terminal-line { margin-bottom: 5px; }
                .terminal-prompt { color: #3b82f6; }
                .terminal-output { color: rgba(255,255,255,0.7); }
                .terminal-success { color: #22c55e; }
                .terminal-warning { color: #f59e0b; }
                .terminal-input {
                    display: flex;
                    align-items: center;
                    gap: 10px;
                    margin-top: 20px;
                }
                .terminal-input input {
                    flex: 1;
                    background: transparent;
                    border: none;
                    color: #22c55e;
                    font-family: inherit;
                    font-size: 14px;
                    outline: none;
                }
                .machine-sidebar {
                    width: 350px;
                    background: rgba(0,0,0,0.3);
                    border-left: 1px solid rgba(255,255,255,0.1);
                    padding: 25px;
                }
                .sidebar-section { margin-bottom: 25px; }
                .sidebar-title {
                    color: #fff;
                    font-weight: 600;
                    font-size: 14px;
                    margin-bottom: 15px;
                    display: flex;
                    align-items: center;
                    gap: 10px;
                }
                .sidebar-title i { color: #22c55e; }
                .flag-submit-box {
                    background: rgba(0,0,0,0.3);
                    border: 1px solid rgba(255,255,255,0.1);
                    border-radius: 12px;
                    padding: 15px;
                    margin-bottom: 15px;
                }
                .flag-label { color: rgba(255,255,255,0.5); font-size: 12px; margin-bottom: 8px; }
                .flag-input-box {
                    display: flex;
                    gap: 10px;
                }
                .flag-input-box input {
                    flex: 1;
                    padding: 10px;
                    background: rgba(0,0,0,0.3);
                    border: 1px solid rgba(255,255,255,0.1);
                    border-radius: 8px;
                    color: #fff;
                    font-family: 'Fira Code', monospace;
                    font-size: 12px;
                }
                .flag-input-box button {
                    padding: 10px 15px;
                    background: #22c55e;
                    border: none;
                    border-radius: 8px;
                    color: #000;
                    font-weight: 600;
                    cursor: pointer;
                }
                .hint-list { list-style: none; padding: 0; }
                .hint-item {
                    padding: 12px;
                    background: rgba(255,255,255,0.03);
                    border-radius: 8px;
                    margin-bottom: 8px;
                    color: rgba(255,255,255,0.6);
                    font-size: 13px;
                    cursor: pointer;
                    transition: all 0.3s ease;
                }
                .hint-item:hover { background: rgba(255,255,255,0.08); }
                .back-btn-machine {
                    position: fixed;
                    top: 15px;
                    left: 15px;
                    padding: 10px 20px;
                    background: rgba(255,255,255,0.1);
                    border: none;
                    border-radius: 8px;
                    color: #fff;
                    cursor: pointer;
                    z-index: 100;
                }
            </style>
            
            <button class="back-btn-machine" onclick="loadPage('learn'); setTimeout(() => switchLearnTab('${type === 'walkthrough' ? 'walkthroughs' : 'networks'}'), 100);">
                <i class="fa-solid fa-arrow-left"></i> Back
            </button>
            
            <div class="machine-topbar">
                <div class="machine-info">
                    <div class="machine-icon">
                        <i class="${machine.os === 'windows' ? 'fab fa-windows' : 'fab fa-linux'}"></i>
                    </div>
                    <div>
                        <div class="machine-name-large">${machine.title}</div>
                        <div class="machine-os">${machine.os || 'Linux'} • ${machine.difficulty}</div>
                    </div>
                </div>
                <div class="machine-stats">
                    <div class="machine-stat-box">
                        <div class="stat-label">IP Address</div>
                        <div class="stat-value ip-value">${ipDisplay}</div>
                    </div>
                    <div class="machine-stat-box">
                        <div class="stat-label">Status</div>
                        <div class="stat-value">RUNNING</div>
                    </div>
                    <div class="machine-stat-box">
                        <div class="stat-label">Time Remaining</div>
                        <div class="stat-value" id="machine-timer">01:00:00</div>
                    </div>
                    <div class="machine-stat-box">
                        <div class="stat-label">Points</div>
                        <div class="stat-value">${machine.points}</div>
                    </div>
                </div>
            </div>
            
            <div class="machine-content">
                <div class="machine-terminal">
                    <div class="terminal-header">
                        <span class="terminal-dot red"></span>
                        <span class="terminal-dot yellow"></span>
                        <span class="terminal-dot green"></span>
                        ${(machine.steps || []).slice(0, 3).map((step, i) => `
                            <div class="terminal-line terminal-output">  ${i + 1}. ${step}</div>
                        `).join('')}
                        <div class="terminal-line terminal-output"> </div>
                        <div class="terminal-line terminal-success">Ready to hack! Good luck.</div>
                        <div class="terminal-line terminal-output"> </div>
                    </div>
                </div>
                
                <div class="machine-sidebar">
                    <div class="sidebar-section">
                        <div class="sidebar-title"><i class="fa-solid fa-flag"></i> Submit Flags</div>
                        ${(machine.flags || ['FLAG{example}']).map((flag, i) => `
                            <div class="flag-submit-box">
                                <div class="flag-label">Flag ${i + 1}</div>
                                <div class="flag-input-box">
                                    <input type="text" id="machine-flag-${i}" placeholder="FLAG{...}">
                                    <button onclick="submitMachineFlag(${i}, '${flag}')">Submit</button>
                                </div>
                            </div>
                        `).join('')}
                    </div>
                    
                    <div class="sidebar-section">
                        <div class="sidebar-title"><i class="fa-solid fa-lightbulb"></i> Hints</div>
                        <ul class="hint-list">
                            <li class="hint-item" onclick="revealMachineHint(this, 'Start with port scanning using nmap')">Hint 1 - Enumeration</li>
                            <li class="hint-item" onclick="revealMachineHint(this, 'Look for common web vulnerabilities')">Hint 2 - Exploitation</li>
                            <li class="hint-item" onclick="revealMachineHint(this, 'Check for SUID binaries or sudo permissions')">Hint 3 - Privilege Escalation</li>
                        </ul>
                    </div>
                    
                    <div class="sidebar-section">
                        <div class="sidebar-title"><i class="fa-solid fa-book"></i> Resources</div>
                        <ul class="hint-list">
                            <li class="hint-item">📖 Nmap Cheatsheet</li>
                            <li class="hint-item">📖 GTFOBins</li>
                            <li class="hint-item">📖 LinPEAS Guide</li>
                            <li class="hint-item">📖 Reverse Shell Cheatsheet</li>
                        </ul>
                    </div>
                </div>
            </div>
        </div >
        `;
}

function submitMachineFlag(flagIndex, correctFlag) {
    const input = document.getElementById('machine-flag-' + flagIndex);
    const answer = input.value.trim();

    if (answer === correctFlag) {
        input.style.borderColor = '#22c55e';
        input.disabled = true;
        showNotification('🎉 Correct flag! +100 XP', 'success');
        // Add to terminal
        const terminal = document.getElementById('terminal-output');
        terminal.innerHTML += '<div class="terminal-line terminal-success">✓ Flag ' + (flagIndex + 1) + ' captured!</div>';
    } else {
        input.style.borderColor = '#ef4444';
        setTimeout(() => { input.style.borderColor = 'rgba(255,255,255,0.1)'; }, 1500);
        showNotification('Incorrect flag, try again!', 'error');
    }
}

function revealMachineHint(element, hint) {
    element.innerHTML = '<i class="fa-solid fa-lightbulb" style="color: #f59e0b; margin-right: 8px;"></i>' + hint;
    element.style.background = 'rgba(245, 158, 11, 0.1)';
    element.style.borderLeft = '3px solid #f59e0b';
    element.onclick = null;
}

// Export all start functions
window.startRoadmap = startRoadmap;
window.startPath = startPath;
window.startModule = startModule;
window.startMachine = startMachine;
window.submitMachineFlag = submitMachineFlag;
window.revealMachineHint = revealMachineHint;

// ==================== PATH PROGRESS TRACKING ====================
// Helper to check if user is logged in
function isUserLoggedIn() {
    // Check AuthState first
    if (typeof AuthState !== 'undefined' && AuthState.isLoggedIn && AuthState.isLoggedIn()) {
        return true;
    }
    // Check EnrollmentSystem
    if (typeof EnrollmentSystem !== 'undefined' && EnrollmentSystem.checkUserLoggedIn) {
        return EnrollmentSystem.checkUserLoggedIn();
    }
    // Fallback to localStorage/sessionStorage
    if (localStorage.getItem('isLoggedIn') === 'true' ||
        sessionStorage.getItem('isLoggedIn') === 'true') {
        return true;
    }
    return false;
}

// Initialize or get path progress from localStorage
function getPathProgress(pathId) {
    // If user is not logged in, return empty progress
    if (!isUserLoggedIn()) {
        return {
            pathId: pathId,
            currentUnitIndex: 0,
            currentRoomIndex: 0,
            completedRooms: [],
            completedUnits: [],
            startedAt: null,
            lastAccessedAt: null
        };
    }

    const savedProgress = localStorage.getItem('pathProgress_' + pathId);
    if (savedProgress) {
        return JSON.parse(savedProgress);
    }
    return {
        pathId: pathId,
        currentUnitIndex: 0,
        currentRoomIndex: 0,
        completedRooms: [],
        completedUnits: [],
        startedAt: Date.now(),
        lastAccessedAt: Date.now()
    };
}

function savePathProgress(progress) {
    progress.lastAccessedAt = Date.now();
    localStorage.setItem('pathProgress_' + progress.pathId, JSON.stringify(progress));
}

function markRoomComplete(pathId, roomId) {
    const progress = getPathProgress(pathId);
    if (!progress.completedRooms.includes(roomId)) {
        progress.completedRooms.push(roomId);
    }
    savePathProgress(progress);
    return progress;
}

function isRoomCompleted(pathId, roomId) {
    const progress = getPathProgress(pathId);
    return progress.completedRooms.includes(roomId);
}

// ==================== TASK COMPLETION TRACKING ====================
// Get task progress for a room
function getRoomTaskProgress(roomId) {
    const savedProgress = localStorage.getItem('roomTasks_' + roomId);
    if (savedProgress) {
        return JSON.parse(savedProgress);
    }
    return {
        roomId: roomId,
        completedTasks: [],
        startedAt: Date.now()
    };
}

function saveRoomTaskProgress(roomId, progress) {
    localStorage.setItem('roomTasks_' + roomId, JSON.stringify(progress));
}

function markTaskComplete(roomId, taskIndex) {
    const progress = getRoomTaskProgress(roomId);
    if (!progress.completedTasks.includes(taskIndex)) {
        progress.completedTasks.push(taskIndex);
    }
    saveRoomTaskProgress(roomId, progress);
    return progress;
}

function isTaskCompleted(roomId, taskIndex) {
    const progress = getRoomTaskProgress(roomId);
    return progress.completedTasks.includes(taskIndex);
}

function areAllRoomTasksCompleted(roomId, totalTasks) {
    const progress = getRoomTaskProgress(roomId);
    return progress.completedTasks.length >= totalTasks;
}

function getCompletedTaskCount(roomId) {
    const progress = getRoomTaskProgress(roomId);
    return progress.completedTasks.length;
}

// Export task tracking functions
window.getRoomTaskProgress = getRoomTaskProgress;
window.markTaskComplete = markTaskComplete;
window.isTaskCompleted = isTaskCompleted;
window.areAllRoomTasksCompleted = areAllRoomTasksCompleted;
window.getCompletedTaskCount = getCompletedTaskCount;

// Get navigation info for current room
function getRoomNavigationInfo(pathId, currentRoomId) {
    const pathData = window.UnifiedLearningData?.getPathById(pathId);
    if (!pathData || !pathData.units) return null;

    let allRooms = [];
    let currentIndex = -1;

    // Flatten all rooms from all units
    pathData.units.forEach((unit, unitIndex) => {
        if (unit.rooms) {
            unit.rooms.forEach((room, roomIndex) => {
                allRooms.push({
                    room: room,
                    unit: unit,
                    unitIndex: unitIndex,
                    roomIndex: roomIndex
                });
                if (room.id === currentRoomId) {
                    currentIndex = allRooms.length - 1;
                }
            });
        }
    });

    if (currentIndex === -1) return null;

    return {
        current: allRooms[currentIndex],
        prev: currentIndex > 0 ? allRooms[currentIndex - 1] : null,
        next: currentIndex < allRooms.length - 1 ? allRooms[currentIndex + 1] : null,
        isFirst: currentIndex === 0,
        isLast: currentIndex === allRooms.length - 1,
        totalRooms: allRooms.length,
        currentPosition: currentIndex + 1,
        allRooms: allRooms
    };
}

// Navigate to next room/module
function goToNextRoom() {
    const roomData = window.currentRoom;
    if (!roomData) return;

    const { room, path } = roomData;
    const navInfo = getRoomNavigationInfo(path.id, room.id);

    if (navInfo && navInfo.next) {
        // Mark current room as complete
        markRoomComplete(path.id, room.id);
        showNotification('Moving to next module...', 'success');
        openRoom(navInfo.next.room.id);
    } else if (navInfo && navInfo.isLast) {
        // Mark current room as complete and show completion
        markRoomComplete(path.id, room.id);
        showPathCompletion(path.id);
    }
}

// Navigate to previous room/module
function goToPrevRoom() {
    const roomData = window.currentRoom;
    if (!roomData) return;

    const { room, path } = roomData;
    const navInfo = getRoomNavigationInfo(path.id, room.id);

    if (navInfo && navInfo.prev) {
        openRoom(navInfo.prev.room.id);
    }
}

// Show path completion celebration
function showPathCompletion(pathId) {
    const pathData = window.UnifiedLearningData?.getPathById(pathId);
    if (!pathData) return;

    // Mark path as complete
    const completedPaths = JSON.parse(localStorage.getItem('completedPaths') || '[]');
    if (!completedPaths.includes(pathId)) {
        completedPaths.push(pathId);
        localStorage.setItem('completedPaths', JSON.stringify(completedPaths));
    }

    document.getElementById('content').innerHTML = `
        < div class="path-completion-page" >
            <style>
                .path-completion-page {
                    min-height: 100vh;
                    background: linear-gradient(135deg, #0f0c29 0%, #302b63 50%, #24243e 100%);
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    padding: 40px 20px;
                    position: relative;
                    overflow: hidden;
                }
                
                .confetti {
                    position: absolute;
                    width: 100%;
                    height: 100%;
                    top: 0;
                    left: 0;
                    pointer-events: none;
                    overflow: hidden;
                }
                .confetti-piece {
                    position: absolute;
                    width: 10px;
                    height: 10px;
                    background: linear-gradient(135deg, #f59e0b, #ec4899);
                    animation: confetti-fall 4s ease-out infinite;
                }
                @keyframes confetti-fall {
                    0% { transform: translateY(-100vh) rotate(0deg); opacity: 1; }
                    100% { transform: translateY(100vh) rotate(720deg); opacity: 0; }
                }
                
                .completion-card {
                    background: rgba(255,255,255,0.05);
                    backdrop-filter: blur(20px);
                    border: 1px solid rgba(255,255,255,0.1);
                    border-radius: 30px;
                    padding: 60px 50px;
                    text-align: center;
                    max-width: 600px;
                    position: relative;
                    z-index: 10;
                }
                
                .completion-icon {
                    width: 120px;
                    height: 120px;
                    margin: 0 auto 30px;
                    background: linear-gradient(135deg, #22c55e, #16a34a);
                    border-radius: 50%;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    box-shadow: 0 20px 60px rgba(34, 197, 94, 0.4);
                    animation: pulse-glow 2s ease-in-out infinite;
                }
                @keyframes pulse-glow {
                    0%, 100% { box-shadow: 0 20px 60px rgba(34, 197, 94, 0.4); }
                    50% { box-shadow: 0 20px 80px rgba(34, 197, 94, 0.6); }
                }
                .completion-icon i {
                    font-size: 50px;
                    color: #fff;
                }
                
                .completion-title {
                    font-size: 36px;
                    font-weight: 800;
                    color: #fff;
                    margin-bottom: 15px;
                    background: linear-gradient(135deg, #22c55e, #3b82f6);
                    -webkit-background-clip: text;
                    -webkit-text-fill-color: transparent;
                }
                
                .completion-subtitle {
                    font-size: 18px;
                    color: rgba(255,255,255,0.7);
                    margin-bottom: 30px;
                }
                
                .path-badge {
                    background: linear-gradient(135deg, ${pathData.color || '#667eea'}, ${pathData.color ? pathData.color + '99' : '#764ba2'});
                    padding: 20px 40px;
                    border-radius: 20px;
                    margin: 30px 0;
                    display: inline-block;
                }
                .path-badge-icon {
                    font-size: 40px;
                    margin-bottom: 10px;
                }
                .path-badge-title {
                    font-size: 22px;
                    font-weight: 700;
                    color: #fff;
                }
                .path-badge-subtitle {
                    font-size: 14px;
                    color: rgba(255,255,255,0.8);
                    margin-top: 5px;
                }
                
                .completion-stats {
                    display: flex;
                    justify-content: center;
                    gap: 40px;
                    margin: 30px 0;
                }
                .stat-item {
                    text-align: center;
                }
                .stat-value {
                    font-size: 28px;
                    font-weight: 700;
                    color: #22c55e;
                }
                .stat-label {
                    font-size: 13px;
                    color: rgba(255,255,255,0.5);
                    margin-top: 5px;
                }
                
                .completion-actions {
                    display: flex;
                    gap: 20px;
                    justify-content: center;
                    margin-top: 40px;
                    flex-wrap: wrap;
                }
                
                .comp-btn {
                    padding: 16px 35px;
                    border-radius: 14px;
                    font-weight: 600;
                    font-size: 15px;
                    cursor: pointer;
                    transition: all 0.3s ease;
                    display: flex;
                    align-items: center;
                    gap: 10px;
                }
                .comp-btn-primary {
                    background: linear-gradient(135deg, #22c55e, #16a34a);
                    border: none;
                    color: #fff;
                }
                .comp-btn-primary:hover {
                    transform: translateY(-3px);
                    box-shadow: 0 10px 30px rgba(34, 197, 94, 0.4);
                }
                .comp-btn-secondary {
                    background: transparent;
                    border: 2px solid rgba(255,255,255,0.2);
                    color: #fff;
                }
                .comp-btn-secondary:hover {
                    background: rgba(255,255,255,0.1);
                    border-color: rgba(255,255,255,0.3);
                }
            </style>
            
            <div class="confetti">
                ${Array(30).fill().map((_, i) => `
                    <div class="confetti-piece" style="
                        left: ${Math.random() * 100}%;
                        animation-delay: ${Math.random() * 4}s;
                        background: ${['#22c55e', '#3b82f6', '#f59e0b', '#ec4899', '#8b5cf6'][Math.floor(Math.random() * 5)]};
                        width: ${5 + Math.random() * 10}px;
                        height: ${5 + Math.random() * 10}px;
                        border-radius: ${Math.random() > 0.5 ? '50%' : '0'};
                    "></div>
                `).join('')}
            </div>
            
            <div class="completion-card">
                <div class="completion-icon">
                    <i class="fa-solid fa-trophy"></i>
                </div>
                
                <h1 class="completion-title">🎉 Path Completed!</h1>
                <p class="completion-subtitle">Congratulations! You've mastered all modules in this learning path</p>
                
                <div class="path-badge">
                    <div class="path-badge-icon"><i class="${pathData.icon?.includes('fab') ? pathData.icon : 'fa-solid ' + pathData.icon}"></i></div>
                    <div class="path-badge-title">${pathData.name}</div>
                    <div class="path-badge-subtitle">Path Completion Badge</div>
                </div>
                
                <div class="completion-stats">
                    <div class="stat-item">
                        <div class="stat-value">${pathData.units?.length || 0}</div>
                        <div class="stat-label">Modules Completed</div>
                    </div>
                    <div class="stat-item">
                        <div class="stat-value">${pathData.units?.reduce((acc, u) => acc + (u.rooms?.length || 0), 0) || 0}</div>
                        <div class="stat-label">Rooms Mastered</div>
                    </div>
                    <div class="stat-item">
                        <div class="stat-value">+${pathData.totalXP || 500}</div>
                        <div class="stat-label">XP Earned</div>
                    </div>
                </div>
                
                <div class="completion-actions">
                    <button class="comp-btn comp-btn-primary" onclick="viewCompletionBadge('${pathId}')">
                        <i class="fa-solid fa-award"></i> View Badge
                    </button>
                    <button class="comp-btn comp-btn-secondary" onclick="loadPage('learn'); setTimeout(() => switchLearnTab('paths'), 100);">
                        <i class="fa-solid fa-arrow-left"></i> Back to Paths
                    </button>
                </div>
            </div>
        </div >
        `;
}

// View completion badge in a modal
function viewCompletionBadge(pathId) {
    const pathData = window.UnifiedLearningData?.getPathById(pathId);
    if (!pathData) return;

    const modal = document.createElement('div');
    modal.innerHTML = `
        < div style = "
    position: fixed;
    inset: 0;
    background: rgba(0, 0, 0, 0.8);
    backdrop - filter: blur(10px);
    display: flex;
    align - items: center;
    justify - content: center;
    z - index: 10000;
    padding: 20px;
    " onclick="this.remove()">
        < div style = "
    background: linear - gradient(135deg, #1a1a2e 0 %, #16213e 100 %);
    border: 2px solid ${pathData.color || '#667eea'};
    border - radius: 30px;
    padding: 50px;
    text - align: center;
    max - width: 400px;
    box - shadow: 0 30px 100px rgba(0, 0, 0, 0.5);
    " onclick="event.stopPropagation()">
        < div style = "
    width: 150px;
    height: 150px;
    margin: 0 auto 25px;
    background: linear - gradient(135deg, ${pathData.color || '#667eea'}, ${pathData.color ? pathData.color + '99' : '#764ba2'});
    border - radius: 50 %;
    display: flex;
    align - items: center;
    justify - content: center;
    box - shadow: 0 15px 50px ${pathData.color || '#667eea'} 66;
    ">
        < i class="${pathData.icon?.includes('fab') ? pathData.icon : 'fa-solid ' + pathData.icon}" style = "font-size: 60px; color: #fff;" ></i >
                </div >
                
                <h2 style="color: #fff; font-size: 24px; margin-bottom: 10px;">${pathData.name}</h2>
                <p style="color: rgba(255,255,255,0.6); margin-bottom: 20px;">Path Mastery Badge</p>
                <p style="
                    background: rgba(34, 197, 94, 0.1);
                    border: 1px solid rgba(34, 197, 94, 0.3);
                    padding: 10px 20px;
                    border-radius: 10px;
                    color: #22c55e;
                    font-weight: 600;
                ">
                    <i class="fa-solid fa-check-circle"></i> Earned ${new Date().toLocaleDateString()}
                </p>
                
                <button style="
                    margin-top: 25px;
                    padding: 12px 30px;
                    background: transparent;
                    border: 1px solid rgba(255,255,255,0.2);
                    border-radius: 10px;
                    color: #fff;
                    cursor: pointer;
                " onclick="this.closest('div[style*=fixed]').remove()">Close</button>
            </div >
        </div >
        `;
    document.body.appendChild(modal);
}

// Complete the current room and show next navigation
function completeCurrentRoom() {
    const roomData = window.currentRoom;
    if (!roomData) return;

    const { room, path } = roomData;

    // Check if all tasks are completed
    if (!areAllRoomTasksCompleted(room.id, room.tasks.length)) {
        const completedCount = getCompletedTaskCount(room.id);
        const remaining = room.tasks.length - completedCount;
        showNotification(`⚠️ Complete all tasks first!(${remaining} remaining)`, 'warning');

        // Highlight incomplete tasks
        room.tasks.forEach((task, i) => {
            if (!isTaskCompleted(room.id, i)) {
                const taskItem = document.getElementById(`task - item - ${i} `);
                if (taskItem) {
                    taskItem.style.animation = 'pulse 1s ease-in-out 2';
                    taskItem.style.borderColor = '#f59e0b';
                    setTimeout(() => {
                        taskItem.style.animation = '';
                        taskItem.style.borderColor = '';
                    }, 2000);
                }
            }
        });
        return;
    }

    // All tasks done - mark room as complete
    markRoomComplete(path.id, room.id);

    const navInfo = getRoomNavigationInfo(path.id, room.id);
    if (!navInfo) return;

    // Show completion notification with next action
    if (navInfo.isLast) {
        showNotification('🎉 Module complete! You finished the path!', 'success');
        // Show next module button in the UI
        showNavigationPrompt(true, navInfo);
    } else {
        showNotification('Module complete! Ready for the next one?', 'success');
        showNavigationPrompt(false, navInfo);
    }
}

// Show navigation prompt at bottom of room
function showNavigationPrompt(isPathComplete, navInfo) {
    const container = document.querySelector('.room-main');
    if (!container) return;

    const existingPrompt = document.querySelector('.nav-prompt');
    if (existingPrompt) existingPrompt.remove();

    const prompt = document.createElement('div');
    prompt.className = 'nav-prompt';
    prompt.innerHTML = `
        < style >
            .nav - prompt {
        margin - top: 30px;
        padding: 25px;
        background: linear - gradient(135deg, rgba(34, 197, 94, 0.1), rgba(59, 130, 246, 0.1));
        border: 1px solid rgba(34, 197, 94, 0.3);
        border - radius: 16px;
        display: flex;
        justify - content: space - between;
        align - items: center;
        gap: 20px;
        flex - wrap: wrap;
    }
            .nav - prompt - text {
        color: #22c55e;
        font - weight: 600;
        font - size: 16px;
    }
            .nav - prompt - btns {
        display: flex;
        gap: 15px;
    }
            .nav - btn {
        padding: 12px 25px;
        border - radius: 10px;
        font - weight: 600;
        cursor: pointer;
        display: flex;
        align - items: center;
        gap: 8px;
        transition: all 0.3s ease;
    }
            .nav - btn - next {
        background: linear - gradient(135deg, #22c55e, #16a34a);
        border: none;
        color: #fff;
    }
            .nav - btn - next:hover {
        transform: translateY(-2px);
        box - shadow: 0 8px 25px rgba(34, 197, 94, 0.4);
    }
            .nav - btn - complete {
        background: linear - gradient(135deg, #f59e0b, #d97706);
        border: none;
        color: #fff;
    }
        </style >
        
        <div class="nav-prompt-text">
            <i class="fa-solid fa-check-circle"></i> 
            ${isPathComplete ? '🎉 Congratulations! You completed the entire path!' : `Great work! Ready for ${navInfo.next?.room.title || 'the next module'}?`}
        </div>
        
        <div class="nav-prompt-btns">
            ${isPathComplete ? `
                <button class="nav-btn nav-btn-complete" onclick="showPathCompletion('${navInfo.current.room.path_id || window.currentRoom?.path?.id}')">
                    <i class="fa-solid fa-trophy"></i> View Completion!
                </button>
            ` : `
                <button class="nav-btn nav-btn-next" onclick="goToNextRoom()">
                    <i class="fa-solid fa-arrow-right"></i> Next Module
                </button>
            `}
        </div>
    `;
    container.appendChild(prompt);
}

// Export navigation functions
window.getPathProgress = getPathProgress;
window.savePathProgress = savePathProgress;
window.markRoomComplete = markRoomComplete;
window.getRoomNavigationInfo = getRoomNavigationInfo;
window.goToNextRoom = goToNextRoom;
window.goToPrevRoom = goToPrevRoom;
window.showPathCompletion = showPathCompletion;
window.viewCompletionBadge = viewCompletionBadge;
window.completeCurrentRoom = completeCurrentRoom;

// ==================== PATH DETAIL PAGE ====================
function openLearningPath(pathId) {
    const pathData = window.UnifiedLearningData?.getPathById(pathId);
    if (!pathData) {
        console.error('Path not found:', pathId);
        return;
    }

    // Store current path
    window.currentLearningPath = pathData;

    // Render the path page
    document.getElementById('content').innerHTML = renderPathDetail(pathData);
}
window.openLearningPath = openLearningPath;

function renderPathDetail(path) {
    // Check enrollment status
    const isEnrolled = typeof EnrollmentSystem !== 'undefined' ? EnrollmentSystem.isEnrolled(path.id) : false;
    const enrollmentProgress = typeof EnrollmentSystem !== 'undefined' ? EnrollmentSystem.getProgress(path.id) : 0;

    // Store last enrolled path for badge persistence
    if (isEnrolled) {
        localStorage.setItem('shadowhack_last_enrolled', path.id);
    }
    return `
        < div class="path-detail-page" >
            <style>
                .path-detail-page {
                    min-height: 100vh;
                    background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
                }
                .path-detail-container { max-width: 1200px; margin: 0 auto; padding: 0 20px; }
                
                /* Header Section */
                .path-header {
                    background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%);
                    padding: 40px 0;
                    border-bottom: 1px solid rgba(255,255,255,0.1);
                }
                .path-header-inner {
                    max-width: 1200px;
                    margin: 0 auto;
                    padding: 0 20px;
                }
                .path-label {
                    color: #64748b;
                    font-size: 12px;
                    font-weight: 700;
                    letter-spacing: 1px;
                    text-transform: uppercase;
                    margin-bottom: 12px;
                }
                .path-header-title {
                    font-size: 2.5rem;
                    font-weight: 800;
                    color: #fff;
                    margin-bottom: 15px;
                    line-height: 1.2;
                }
                .path-header-desc {
                    color: #94a3b8;
                    font-size: 16px;
                    line-height: 1.7;
                    max-width: 800px;
                    margin-bottom: 25px;
                }
                
                /* Stats Boxes */
                .path-stats-boxes {
                    display: flex;
                    gap: 20px;
                    margin-bottom: 25px;
                    flex-wrap: wrap;
                }
                .stat-box {
                    background: rgba(255,255,255,0.05);
                    border: 1px solid rgba(255,255,255,0.1);
                    border-radius: 12px;
                    padding: 16px 24px;
                    min-width: 120px;
                }
                .stat-box-label {
                    color: #64748b;
                    font-size: 12px;
                    margin-bottom: 6px;
                }
                .stat-box-value {
                    color: #fff;
                    font-size: 16px;
                    font-weight: 700;
                    display: flex;
                    align-items: center;
                    gap: 8px;
                }
                .stat-box-value i { opacity: 0.7; }
                .stat-box-value.easy { color: #22c55e; }
                .stat-box-value.intermediate { color: #f59e0b; }
                .stat-box-value.hard { color: #ef4444; }
                
                /* Enroll Button */
                .path-enroll-btn {
                    display: inline-flex;
                    align-items: center;
                    gap: 10px;
                    padding: 14px 28px;
                    background: #3b82f6;
                    border: none;
                    border-radius: 8px;
                    color: #fff;
                    font-size: 15px;
                    font-weight: 700;
                    cursor: pointer;
                    transition: all 0.3s ease;
                }
                .path-enroll-btn:hover {
                    background: #2563eb;
                    transform: translateY(-2px);
                }
                .path-enroll-btn.enrolled {
                    background: #22c55e;
                }
                
                /* Main Content - 2 Column Layout */
                .path-main-content {
                    display: grid;
                    grid-template-columns: 350px 1fr;
                    gap: 40px;
                    padding: 40px 0;
                }
                @media (max-width: 900px) {
                    .path-main-content { grid-template-columns: 1fr; }
                }
                
                /* Left Column */
                .path-left-column {}
                .path-image-box {
                    background: ${path.color};
                    border-radius: 16px;
                    height: 220px;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    margin-bottom: 25px;
                    position: relative;
                    overflow: hidden;
                }
                .path-image-box::before {
                    content: '';
                    position: absolute;
                    inset: 0;
                    background: linear-gradient(135deg, rgba(255,255,255,0.2) 0%, transparent 50%);
                }
                .path-image-box i {
                    font-size: 80px;
                    color: rgba(255,255,255,0.9);
                    z-index: 1;
                }
                
                .path-skills-box {
                    background: #fff;
                    border-radius: 16px;
                    padding: 25px;
                    margin-bottom: 25px;
                }
                .path-skills-box p {
                    color: #1e293b;
                    font-size: 14px;
                    line-height: 1.6;
                    margin-bottom: 15px;
                }
                .path-skills-list {
                    list-style: none;
                    padding: 0;
                    margin: 0;
                }
                .path-skills-list li {
                    color: #3b82f6;
                    font-size: 13px;
                    padding: 6px 0;
                    display: flex;
                    align-items: flex-start;
                    gap: 8px;
                }
                .path-skills-list li::before {
                    content: '•';
                    color: #3b82f6;
                    font-weight: bold;
                }
                
                .path-certificate-box {
                    background: linear-gradient(135deg, #1e3a5f 0%, #0f172a 100%);
                    border-radius: 16px;
                    padding: 25px;
                    position: relative;
                    overflow: hidden;
                }
                .path-certificate-box .cert-label {
                    background: #22c55e;
                    color: #000;
                    font-size: 10px;
                    font-weight: 800;
                    padding: 4px 10px;
                    border-radius: 4px;
                    display: inline-block;
                    margin-bottom: 15px;
                }
                .path-certificate-box .cert-text {
                    color: #64748b;
                    font-size: 12px;
                    margin-bottom: 5px;
                }
                .path-certificate-box .cert-title {
                    color: #22c55e;
                    font-size: 18px;
                    font-weight: 700;
                }
                
                /* Right Column */
                .path-right-column {}
                .path-intro-section {
                    background: #fff;
                    border-radius: 16px;
                    padding: 30px;
                    margin-bottom: 30px;
                }
                .path-intro-section h2 {
                    color: #1e293b;
                    font-size: 1.5rem;
                    font-weight: 700;
                    margin-bottom: 15px;
                }
                .path-intro-section p {
                    color: #475569;
                    font-size: 14px;
                    line-height: 1.8;
                    margin-bottom: 15px;
                }
                .path-intro-list {
                    list-style: disc;
                    padding-left: 20px;
                    margin: 15px 0;
                }
                .path-intro-list li {
                    color: #475569;
                    font-size: 14px;
                    padding: 4px 0;
                }
                .path-intro-footer {
                    color: #475569;
                    font-size: 14px;
                    font-style: italic;
                    margin-top: 15px;
                    padding-top: 15px;
                    border-top: 1px solid #e2e8f0;
                }
                
                /* Sections */
                .path-section {
                    background: #fff;
                    border-radius: 16px;
                    padding: 25px;
                    margin-bottom: 20px;
                }
                .path-section-header {
                    color: #64748b;
                    font-size: 12px;
                    font-weight: 700;
                    text-transform: uppercase;
                    letter-spacing: 0.5px;
                    margin-bottom: 5px;
                }
                .path-section-title {
                    color: #1e293b;
                    font-size: 1.1rem;
                    font-weight: 700;
                    margin-bottom: 20px;
                }
                
                /* Module Items */
                .module-item {
                    display: flex;
                    align-items: center;
                    gap: 15px;
                    padding: 15px;
                    border-radius: 12px;
                    margin-bottom: 10px;
                    cursor: pointer;
                    transition: all 0.3s ease;
                    border: 1px solid #e2e8f0;
                }
                .module-item:hover {
                    background: #f8fafc;
                    border-color: #3b82f6;
                }
                .module-item.locked {
                    opacity: 0.6;
                    cursor: not-allowed;
                }
                .module-item.completed {
                    border-color: #22c55e;
                    background: rgba(34, 197, 94, 0.05);
                }
                .module-icon {
                    width: 40px;
                    height: 40px;
                    border-radius: 10px;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    font-size: 18px;
                    flex-shrink: 0;
                }
                .module-icon.default { background: #e2e8f0; color: #64748b; }
                .module-icon.locked { background: #fef3c7; color: #f59e0b; }
                .module-icon.completed { background: #dcfce7; color: #22c55e; }
                .module-name {
                    color: #1e293b;
                    font-size: 14px;
                    font-weight: 600;
                    flex: 1;
                }
                .module-progress {
                    width: 36px;
                    height: 36px;
                    border-radius: 50%;
                    background: #e2e8f0;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    font-size: 10px;
                    font-weight: 700;
                    color: #64748b;
                }
                .module-progress.complete {
                    background: #dcfce7;
                    color: #22c55e;
                }
                
                /* Back Button */
                .path-back-btn {
                    display: inline-flex;
                    align-items: center;
                    gap: 10px;
                    color: #64748b;
                    font-size: 14px;
                    cursor: pointer;
                    padding: 10px 0;
                    background: none;
                    border: none;
                    margin-bottom: 20px;
                    transition: color 0.3s ease;
                }
                .path-back-btn:hover { color: #fff; }
                
                /* ============ ENROLLED VIEW STYLES ============ */
                .enrolled-header {
                    background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
                    padding: 40px;
                    border-radius: 20px;
                    margin-bottom: 30px;
                }
                .enrolled-header-top {
                    display: flex;
                    align-items: flex-start;
                    gap: 25px;
                    margin-bottom: 25px;
                }
                .enrolled-header-icon {
                    width: 70px;
                    height: 70px;
                    background: linear-gradient(135deg, #22c55e, #16a34a);
                    border-radius: 16px;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    font-size: 32px;
                    color: #fff;
                    flex-shrink: 0;
                }
                .enrolled-header-title {
                    font-size: 2rem;
                    font-weight: 800;
                    color: #fff;
                    margin-bottom: 10px;
                }
                .enrolled-header-desc {
                    color: #94a3b8;
                    font-size: 14px;
                    line-height: 1.7;
                }
                
                /* Prerequisites */
                .prerequisites-section {
                    background: rgba(255,255,255,0.03);
                    border: 1px solid rgba(255,255,255,0.1);
                    border-radius: 12px;
                    padding: 20px;
                    margin-bottom: 25px;
                }
                .prerequisites-title {
                    color: #fff;
                    font-size: 16px;
                    font-weight: 700;
                    margin-bottom: 10px;
                    display: flex;
                    align-items: center;
                    gap: 10px;
                }
                .prerequisites-title i { color: #64748b; }
                .prerequisites-subtitle {
                    color: #94a3b8;
                    font-size: 13px;
                    font-weight: 600;
                    margin-bottom: 8px;
                }
                .prerequisites-list {
                    list-style: disc;
                    padding-left: 20px;
                    margin: 0;
                }
                .prerequisites-list li {
                    color: #94a3b8;
                    font-size: 13px;
                    padding: 3px 0;
                }
                
                /* Resume Button Row */
                .resume-row {
                    display: flex;
                    align-items: center;
                    gap: 20px;
                }
                .resume-btn {
                    display: inline-flex;
                    align-items: center;
                    gap: 10px;
                    padding: 12px 24px;
                    background: #22c55e;
                    border: none;
                    border-radius: 8px;
                    color: #fff;
                    font-size: 14px;
                    font-weight: 700;
                    cursor: pointer;
                    transition: all 0.3s ease;
                }
                .resume-btn:hover { background: #16a34a; }
                /* Classic toggle styles removed */
                
                /* Enrolled 2-Column Layout */
                .enrolled-content {
                    display: grid;
                    grid-template-columns: 1fr 320px;
                    gap: 30px;
                }
                @media (max-width: 1000px) {
                    .enrolled-content { grid-template-columns: 1fr; }
                }
                
                /* Accordion Units */
                .accordion-unit {
                    background: #fff;
                    border-radius: 16px;
                    margin-bottom: 15px;
                    overflow: hidden;
                    box-shadow: 0 2px 8px rgba(0,0,0,0.05);
                }
                .accordion-header {
                    display: flex;
                    align-items: center;
                    gap: 15px;
                    padding: 20px;
                    cursor: pointer;
                    transition: background 0.3s ease;
                }
                .accordion-header:hover { background: #f8fafc; }
                .accordion-unit.active .accordion-header {
                    background: #1e3a5f;
                }
                .accordion-unit.active .accordion-header .accordion-title,
                .accordion-unit.active .accordion-header .accordion-desc { color: #fff; }
                .accordion-unit.active .accordion-header .accordion-arrow { color: #fff; transform: rotate(180deg); }
                .accordion-icon {
                    width: 50px;
                    height: 50px;
                    border-radius: 12px;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    font-size: 22px;
                    flex-shrink: 0;
                    overflow: hidden;
                }
                .accordion-icon img {
                    width: 100%;
                    height: 100%;
                    object-fit: cover;
                }
                .accordion-info { flex: 1; }
                .accordion-title {
                    color: #1e293b;
                    font-size: 15px;
                    font-weight: 700;
                    margin-bottom: 4px;
                }
                .accordion-desc {
                    color: #64748b;
                    font-size: 13px;
                    line-height: 1.5;
                }
                .accordion-arrow {
                    color: #64748b;
                    font-size: 16px;
                    transition: transform 0.3s ease;
                }
                
                /* Accordion Rooms */
                .accordion-rooms {
                    display: none;
                    padding: 0 20px 20px;
                    background: #fff;
                }
                .accordion-unit.active .accordion-rooms { display: block; }
                .accordion-room {
                    display: flex;
                    align-items: center;
                    gap: 15px;
                    padding: 15px;
                    border-radius: 10px;
                    margin-bottom: 8px;
                    cursor: pointer;
                    border: 1px solid #e2e8f0;
                    transition: all 0.3s ease;
                }
                .accordion-room:hover {
                    background: #f8fafc;
                    border-color: #3b82f6;
                }
                .accordion-room.completed {
                    background: #f0fdf4;
                    border-color: #22c55e;
                }
                .room-check {
                    width: 32px;
                    height: 32px;
                    border-radius: 50%;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    font-size: 14px;
                    flex-shrink: 0;
                }
                .room-check.pending { background: #e2e8f0; color: #64748b; }
                .room-check.done { background: #22c55e; color: #fff; }
                .accordion-room-info { flex: 1; }
                .accordion-room-title {
                    color: #1e293b;
                    font-size: 14px;
                    font-weight: 600;
                    margin-bottom: 3px;
                }
                .accordion-room-desc {
                    color: #64748b;
                    font-size: 12px;
                }
                .room-link {
                    color: #3b82f6;
                    font-size: 12px;
                }
                
                /* Right Sidebar */
                .enrolled-sidebar {}
                .sidebar-box {
                    background: #fff;
                    border-radius: 16px;
                    padding: 25px;
                    margin-bottom: 20px;
                    box-shadow: 0 2px 8px rgba(0,0,0,0.05);
                }
                
                /* Progress Status */
                .progress-status-title {
                    display: flex;
                    align-items: center;
                    gap: 10px;
                    color: #1e293b;
                    font-size: 16px;
                    font-weight: 700;
                    margin-bottom: 15px;
                }
                .progress-status-title i { color: #3b82f6; }
                .completion-date {
                    color: #64748b;
                    font-size: 13px;
                    margin-bottom: 12px;
                }
                .progress-bar-container {
                    height: 10px;
                    background: #e2e8f0;
                    border-radius: 5px;
                    overflow: hidden;
                    margin-bottom: 15px;
                }
                .progress-bar-fill {
                    height: 100%;
                    background: linear-gradient(90deg, #3b82f6, #22c55e);
                    border-radius: 5px;
                    transition: width 0.5s ease;
                }
                .edit-schedule-link {
                    color: #1e293b;
                    font-size: 13px;
                    font-weight: 600;
                    text-decoration: underline;
                    cursor: pointer;
                }
                
                /* Learning Scheduler */
                .scheduler-title {
                    display: flex;
                    align-items: center;
                    gap: 10px;
                    color: #1e293b;
                    font-size: 16px;
                    font-weight: 700;
                    margin-bottom: 12px;
                }
                .scheduler-title i { color: #64748b; }
                .scheduler-text {
                    color: #64748b;
                    font-size: 13px;
                    margin-bottom: 15px;
                }
                .hours-selector {
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    gap: 15px;
                    margin-bottom: 15px;
                }
                .hours-btn {
                    width: 30px;
                    height: 30px;
                    background: #e2e8f0;
                    border: none;
                    border-radius: 6px;
                    font-size: 16px;
                    cursor: pointer;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                }
                .hours-value {
                    width: 50px;
                    height: 40px;
                    background: #1e293b;
                    border-radius: 8px;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    color: #fff;
                    font-size: 18px;
                    font-weight: 700;
                }
                .hours-label {
                    color: #64748b;
                    font-size: 14px;
                }
                .completion-estimate {
                    text-align: center;
                    color: #64748b;
                    font-size: 13px;
                    margin-bottom: 15px;
                }
                .completion-date-badge {
                    display: inline-block;
                    background: #1e293b;
                    color: #fff;
                    padding: 5px 12px;
                    border-radius: 6px;
                    font-size: 12px;
                    font-weight: 600;
                    margin-left: 8px;
                }
                .schedule-btn {
                    width: 100%;
                    padding: 12px;
                    background: #fff;
                    border: 2px solid #1e293b;
                    border-radius: 8px;
                    color: #1e293b;
                    font-size: 14px;
                    font-weight: 700;
                    cursor: pointer;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    gap: 8px;
                    transition: all 0.3s ease;
                }
                .schedule-btn:hover {
                    background: #1e293b;
                    color: #fff;
                }
                
                /* Certificate Box */
                .cert-section-title {
                    color: #1e293b;
                    font-size: 16px;
                    font-weight: 700;
                    margin-bottom: 5px;
                }
                .view-cert-btn {
                    background: none;
                    border: 1px solid #e2e8f0;
                    border-radius: 6px;
                    padding: 6px 12px;
                    color: #64748b;
                    font-size: 12px;
                    cursor: pointer;
                    display: inline-flex;
                    align-items: center;
                    gap: 6px;
                    float: right;
                }
                .cert-info-text {
                    color: #64748b;
                    font-size: 13px;
                    line-height: 1.6;
                    margin: 15px 0;
                    clear: both;
                }
                .cert-info-text a { color: #3b82f6; text-decoration: none; }
                .path-progress-label {
                    color: #64748b;
                    font-size: 12px;
                    margin-top: 15px;
                }
                .path-progress-value {
                    color: #1e293b;
                    font-weight: 700;
                }
            </style>
            
            <!--Header Section-- >
        <div class="path-header">
            <div class="path-header-inner">
                <button class="path-back-btn" onclick="loadPage('learn')">
                    <i class="fa-solid fa-arrow-left"></i>
                    Back to Paths
                </button>

                <div class="path-label">LEARNING PATH</div>
                <h1 class="path-header-title">${path.name}</h1>
                <p class="path-header-desc">${path.description}</p>

                <!-- Stats Boxes -->
                <div class="path-stats-boxes">
                    <div class="stat-box">
                        <div class="stat-box-label">Modules</div>
                        <div class="stat-box-value">
                            <i class="fa-solid fa-layer-group"></i>
                            ${path.units?.length || 0}
                        </div>
                    </div>
                    <div class="stat-box">
                        <div class="stat-box-label">Hands-on labs</div>
                        <div class="stat-box-value">
                            <i class="fa-solid fa-flask"></i>
                            ${path.totalRooms || 0}
                        </div>
                    </div>
                    <div class="stat-box">
                        <div class="stat-box-label">Difficulty level</div>
                        <div class="stat-box-value ${path.difficulty || 'easy'}">
                            <i class="fa-solid fa-signal"></i>
                            ${(path.difficulty || 'Easy').charAt(0).toUpperCase() + (path.difficulty || 'easy').slice(1)}
                        </div>
                    </div>
                </div>

                <!-- Enroll Button -->
                ${isEnrolled ? `
                        <button class="path-enroll-btn enrolled" onclick="startPath('${path.id}')">
                            <i class="fa-solid fa-play"></i>
                            ${enrollmentProgress > 0 ? 'Resume Learning' : 'Start Learning'}
                        </button>
                    ` : `
                        <button class="path-enroll-btn" onclick="handleEnrollPath('${path.id}')">
                            Enroll in path <i class="fa-solid fa-chevron-right"></i>
                        </button>
                    `}
            </div>
        </div>
            
            ${isEnrolled ? `
            <!-- ============ ENROLLED VIEW ============ -->
            <div class="path-detail-container" style="padding-top: 30px;">
                <!-- Enrolled Header -->
                <div class="enrolled-header">
                    <div class="enrolled-header-top">
                        <div class="enrolled-header-icon" style="background: ${path.color};">
                            <i class="fa-solid ${path.icon}"></i>
                        </div>
                        <div>
                            <h1 class="enrolled-header-title">${path.name}</h1>
                            <p class="enrolled-header-desc">${path.description}</p>
                        </div>
                    </div>
                    
                    <!-- Prerequisites -->
                    <div class="prerequisites-section">
                        <div class="prerequisites-title">
                            <i class="fa-solid fa-clipboard-list"></i>
                            Prerequisites
                        </div>
                        <div class="prerequisites-subtitle">No Prior Knowledge</div>
                        <ul class="prerequisites-list">
                            <li>You need no prerequisite to start this pathway! Just enthusiasm and excitement to learn!</li>
                        </ul>
                    </div>
                    
                    <!-- Resume Button Row -->
                    <div class="resume-row">
                        <button class="resume-btn" onclick="startPath('${path.id}')">
                            <i class="fa-solid fa-play"></i>
                            Resume Learning
                        </button>
                        <!-- Classic view toggled removed -->
                    </div>
                </div>
                
                <!-- Enrolled Content - 2 Columns -->
                <div class="enrolled-content">
                    <!-- Left Column - Accordion Units -->
                    <div class="enrolled-units">
                        ${path.units?.map((unit, unitIndex) => `
                            <div class="accordion-unit ${unitIndex === 0 ? 'active' : ''}" id="accordion-${unit.id}">
                                <div class="accordion-header" onclick="toggleAccordion('${unit.id}')">
                                    <div class="accordion-icon" style="background: ${path.color}20; color: ${path.color};">
                                        <i class="fa-solid ${unit.icon || 'fa-book'}"></i>
                                    </div>
                                    <div class="accordion-info">
                                        <div class="accordion-title">${unit.name}</div>
                                        <div class="accordion-desc">${unit.description || ''}</div>
                                    </div>
                                    <i class="fa-solid fa-chevron-down accordion-arrow"></i>
                                </div>
                                <div class="accordion-rooms">
                                    ${(unit.rooms && unit.rooms.length > 0) ? unit.rooms.map(room => {
        const isComplete = isRoomCompleted(path.id, room.id);
        return `
                                        <div class="accordion-room ${isComplete ? 'completed' : ''}" onclick="openRoom('${room.id}')">
                                            <div class="room-check ${isComplete ? 'done' : 'pending'}">
                                                <i class="fa-solid ${isComplete ? 'fa-check' : 'fa-circle'}"></i>
                                            </div>
                                            <div class="accordion-room-info">
                                                <div class="accordion-room-title">
                                                    ${room.title}
                                                    ${isComplete ? '<i class="fa-solid fa-link room-link" style="margin-left: 8px;"></i>' : ''}
                                                </div>
                                                <div class="accordion-room-desc">${room.description || ''}</div>
                                            </div>
                                        </div>
                                        `;
    }).join('') : '<p style="color: #94a3b8; font-size: 13px; padding: 10px;">Rooms coming soon...</p>'}
                                </div>
                            </div>
                        `).join('') || '<p style="color: #94a3b8;">No units available yet.</p>'}
                    </div>
                    
                    <!-- Right Sidebar -->
                    <div class="enrolled-sidebar">
                        <!-- Progress Status -->
                        <div class="sidebar-box">
                            <div class="progress-status-title">
                                <i class="fa-solid fa-clock"></i>
                                ${(() => {
                const progress = getPathProgress(path.id);
                const totalRooms = path.units?.reduce((acc, u) => acc + (u.rooms?.length || 0), 0) || 0;
                const percent = totalRooms > 0 ? Math.round((progress.completedRooms.length / totalRooms) * 100) : 0;
                return percent < 50 ? "You're making progress!" : "You're doing great!";
            })()}
                            </div>
                            <div class="completion-date">
                                Estimated completion: ${(() => {
                const d = new Date();
                d.setMonth(d.getMonth() + 2);
                return d.toLocaleDateString('en-US', { day: 'numeric', month: 'long', year: 'numeric' });
            })()}
                            </div>
                            <div class="progress-bar-container">
                                <div class="progress-bar-fill" style="width: ${(() => {
                const progress = getPathProgress(path.id);
                const totalRooms = path.units?.reduce((acc, u) => acc + (u.rooms?.length || 0), 0) || 1;
                return Math.round((progress.completedRooms.length / totalRooms) * 100);
            })()}%;"></div>
                            </div>
                            <a class="edit-schedule-link">Edit schedule</a>
                        </div>
                        
                        <!-- Certificate -->
                        <div class="sidebar-box">
                            <div style="display: flex; justify-content: space-between; align-items: center;">
                                <div class="cert-section-title">Certificate</div>
                                <button class="view-cert-btn">
                                    <i class="fa-solid fa-eye"></i>
                                    View certificate
                                </button>
                            </div>
                            <p class="cert-info-text">
                                In order to get your certificate you should complete the course. 
                                <a href="#">Certificates</a> allow you to prove your education.
                            </p>
                            <div class="progress-bar-container">
                                <div class="progress-bar-fill" style="width: ${(() => {
                const progress = getPathProgress(path.id);
                const totalRooms = path.units?.reduce((acc, u) => acc + (u.rooms?.length || 0), 0) || 1;
                return Math.round((progress.completedRooms.length / totalRooms) * 100);
            })()}%;"></div>
                            </div>
                            <div class="path-progress-label">
                                Path Progress <span class="path-progress-value">${(() => {
                const progress = getPathProgress(path.id);
                const totalRooms = path.units?.reduce((acc, u) => acc + (u.rooms?.length || 0), 0) || 1;
                return Math.round((progress.completedRooms.length / totalRooms) * 100);
            })()}%</span>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            ` : `
            <!-- ============ UNENROLLED VIEW ============ -->
            <!-- Main Content - 2 Columns -->
            <div class="path-detail-container">
                <div class="path-main-content">
                    <!-- Left Column -->
                    <div class="path-left-column">
                        <!-- Path Image -->
                        <div class="path-image-box">
                            <i class="fa-solid ${path.icon}"></i>
                        </div>
                        
                        <!-- Skills Box -->
                        <div class="path-skills-box">
                            <p>Learn how to perform security assessments of ${path.name?.toLowerCase().includes('web') ? 'web applications' : 'systems and networks'}.</p>
                            <ul class="path-skills-list">
                                ${path.units?.slice(0, 4).map(unit => `<li>${unit.name}</li>`).join('') || '<li>Coming soon...</li>'}
                            </ul>
                        </div>
                        
                        <!-- Certificate Preview -->
                        <div class="path-certificate-box">
                            <div class="cert-label">CERTIFICATE OF COMPLETION</div>
                            <div class="cert-text">this is to acknowledge that</div>
                            <div class="cert-text">has <span style="color: #22c55e;">successfully</span> completed the</div>
                            <div class="cert-title">Learning Path</div>
                        </div>
                    </div>
                    
                    <!-- Right Column -->
                    <div class="path-right-column">
                        <!-- Introduction Section -->
                        <div class="path-intro-section">
                            <h2>Introduction</h2>
                            <p>${path.description}</p>
                            <p>This path covers key topics that you need to understand, such as:</p>
                            <ul class="path-intro-list">
                                ${path.units?.slice(0, 5).map(unit => `<li>${unit.name}</li>`).join('') || '<li>Course modules coming soon</li>'}
                            </ul>
                            <p class="path-intro-footer">Completing this learning path will allow you to learn and become a great ${path.career?.title || 'security professional'}.</p>
                        </div>
                        
                        <!-- Sections (Units) -->
                        ${path.units?.map((unit, unitIndex) => `
                            <div class="path-section">
                                <div class="path-section-header">SECTION ${unitIndex + 1}</div>
                                <div class="path-section-title">${unit.name}</div>
                                
                                ${(unit.rooms && unit.rooms.length > 0) ? unit.rooms.map(room => {
                const isComplete = isRoomCompleted(path.id, room.id);
                const isLocked = !isEnrolled;
                const iconClass = isLocked ? 'locked' : (isComplete ? 'completed' : 'default');
                return `
                                    <div class="module-item ${isLocked ? 'locked' : ''} ${isComplete ? 'completed' : ''}" 
                                         onclick="${isLocked ? `EnrollmentSystem.showEnrollmentPopup('${path.id}', '${path.name}')` : `openRoom('${room.id}')`}">
                                        <div class="module-icon ${iconClass}">
                                            <i class="fa-solid ${isLocked ? 'fa-lock' : (isComplete ? 'fa-check' : 'fa-book')}"></i>
                                        </div>
                                        <div class="module-name">${room.title}</div>
                                    </div>
                                    `;
            }).join('') : '<p style="color: #94a3b8; font-size: 13px; font-style: italic;">Modules coming soon...</p>'}
                            </div>
                        `).join('') || '<div class="path-section"><p style="color: #94a3b8;">Content coming soon...</p></div>'}
                    </div>
                </div>
            </div>
            `}
        </div >
        `;
}

// Export renderPathDetail globally so it can be accessed from anywhere
window.renderPathDetail = renderPathDetail;

function togglePathUnit(unitId) {
    const unitCard = document.getElementById('unit-' + unitId);
    if (unitCard) {
        unitCard.classList.toggle('open');
    }
}

// Toggle accordion in enrolled view
function toggleAccordion(unitId) {
    const accordion = document.getElementById('accordion-' + unitId);
    if (accordion) {
        // Close all other accordions
        document.querySelectorAll('.accordion-unit.active').forEach(el => {
            if (el.id !== 'accordion-' + unitId) {
                el.classList.remove('active');
            }
        });
        // Toggle clicked accordion
        accordion.classList.toggle('active');
    }
}

// Make toggleAccordion globally available
window.toggleAccordion = toggleAccordion;

// ==================== ROOM PAGE ====================
function openRoom(roomId) {
    const roomData = window.UnifiedLearningData?.getRoomById(roomId);
    if (!roomData) {
        console.error('Room not found:', roomId);
        return;
    }

    window.currentRoom = roomData;
    document.getElementById('content').innerHTML = renderRoomPage(roomData);
}

function renderRoomPage(data) {
    const { room, unit, path } = data;

    return `
        < div class="room-page" >
            <style>
                .room-page {
                    min-height: 100vh;
                    background: linear-gradient(135deg, #0f0c29 0%, #302b63 50%, #24243e 100%);
                    display: flex;
                }
                .room-sidebar {
                    width: 350px;
                    background: rgba(0,0,0,0.3);
                    border-right: 1px solid rgba(255,255,255,0.1);
                    padding: 25px;
                    overflow-y: auto;
                    max-height: 100vh;
                }
                .room-main {
                    flex: 1;
                    padding: 30px;
                    overflow-y: auto;
                    max-height: 100vh;
                }
                
                .room-back-btn {
                    display: flex;
                    align-items: center;
                    gap: 10px;
                    color: rgba(255,255,255,0.6);
                    font-size: 14px;
                    cursor: pointer;
                    margin-bottom: 25px;
                    border: none;
                    background: none;
                    padding: 0;
                }
                .room-back-btn:hover { color: #fff; }
                
                .room-header {
                    margin-bottom: 30px;
                }
                .room-title {
                    font-size: 1.8rem;
                    font-weight: 700;
                    color: #fff;
                    margin-bottom: 10px;
                }
                .room-path {
                    color: ${path.color};
                    font-size: 14px;
                    margin-bottom: 15px;
                }
                
                .task-list { margin-top: 30px; }
                .task-item {
                    background: rgba(255,255,255,0.03);
                    border: 1px solid rgba(255,255,255,0.08);
                    border-radius: 12px;
                    padding: 15px;
                    margin-bottom: 10px;
                    cursor: pointer;
                    transition: all 0.3s ease;
                }
                .task-item:hover, .task-item.active {
                    background: rgba(255,255,255,0.06);
                    border-color: ${path.color}40;
                }
                .task-item.active {
                    border-color: ${path.color};
                }
                .task-number {
                    display: inline-flex;
                    width: 28px; height: 28px;
                    background: ${path.color}30;
                    color: ${path.color};
                    border-radius: 50%;
                    align-items: center;
                    justify-content: center;
                    font-size: 13px;
                    font-weight: 700;
                    margin-right: 12px;
                }
                .task-title { color: #fff; font-size: 15px; }
                .task-status {
                    float: right;
                    color: rgba(255,255,255,0.4);
                    font-size: 14px;
                }
                .task-status.completed { color: #22c55e; }
                
                .task-content {
                    background: rgba(255,255,255,0.02);
                    border: 1px solid rgba(255,255,255,0.08);
                    border-radius: 16px;
                    padding: 30px;
                    margin-bottom: 25px;
                }
                .task-content h1, .task-content h2, .task-content h3 {
                    color: #fff;
                    margin-bottom: 15px;
                }
                .task-content p, .task-content li {
                    color: rgba(255,255,255,0.7);
                    line-height: 1.8;
                }
                .task-content code {
                    background: rgba(0,0,0,0.3);
                    padding: 2px 8px;
                    border-radius: 4px;
                    color: #22c55e;
                    font-family: 'JetBrains Mono', monospace;
                }
                .task-content pre {
                    background: rgba(0,0,0,0.4);
                    padding: 20px;
                    border-radius: 12px;
                    overflow-x: auto;
                    margin: 15px 0;
                }
                .task-content pre code {
                    background: none;
                    padding: 0;
                    color: #fff;
                }
                .task-content table {
                    width: 100%;
                    border-collapse: collapse;
                    margin: 15px 0;
                }
                .task-content th, .task-content td {
                    padding: 12px;
                    border: 1px solid rgba(255,255,255,0.1);
                    text-align: left;
                    color: rgba(255,255,255,0.8);
                }
                .task-content th {
                    background: rgba(255,255,255,0.05);
                    color: #fff;
                }
                
                .question-box {
                    background: ${path.color}15;
                    border: 1px solid ${path.color}40;
                    border-radius: 14px;
                    padding: 25px;
                    margin-top: 25px;
                }
                .question-label {
                    color: ${path.color};
                    font-size: 13px;
                    font-weight: 600;
                    margin-bottom: 10px;
                    text-transform: uppercase;
                    letter-spacing: 1px;
                }
                .question-text {
                    color: #fff;
                    font-size: 17px;
                    font-weight: 600;
                    margin-bottom: 20px;
                }
                .answer-input {
                    display: flex;
                    gap: 10px;
                }
                .answer-input input {
                    flex: 1;
                    padding: 14px 18px;
                    background: rgba(0,0,0,0.3);
                    border: 1px solid rgba(255,255,255,0.1);
                    border-radius: 10px;
                    color: #fff;
                    font-size: 15px;
                    font-family: 'JetBrains Mono', monospace;
                }
                .answer-input input:focus {
                    outline: none;
                    border-color: ${path.color};
                }
                .answer-input button {
                    padding: 14px 25px;
                    background: ${path.color};
                    border: none;
                    border-radius: 10px;
                    color: #fff;
                    font-weight: 700;
                    cursor: pointer;
                    transition: all 0.3s ease;
                }
                .answer-input button:hover {
                    transform: scale(1.02);
                }
                
                .hint-btn {
                    background: rgba(255,255,255,0.05);
                    border: 1px solid rgba(255,255,255,0.1);
                    color: rgba(255,255,255,0.6);
                    padding: 10px 18px;
                    border-radius: 8px;
                    cursor: pointer;
                    font-size: 13px;
                    margin-top: 15px;
                    display: inline-flex;
                    align-items: center;
                    gap: 8px;
                }
                .hint-btn:hover {
                    background: rgba(255,255,255,0.1);
                    color: #fff;
                }
                
                @media (max-width: 900px) {
                    .room-page { flex-direction: column; }
                    .room-sidebar { width: 100%; max-height: none; border-right: none; border-bottom: 1px solid rgba(255,255,255,0.1); }
                    .room-main { max-height: none; }
                }
            </style>
            
            <div class="room-sidebar">
                <button class="room-back-btn" onclick="openLearningPath('${path.id}')">
                    <i class="fa-solid fa-arrow-left"></i>
                    Back to ${path.name}
                </button>
                
                <div class="room-header">
                    <div class="room-path">${path.name} / ${unit.name}</div>
                    <h1 class="room-title">${room.title}</h1>
                    ${window.PlatformTaxonomy?.getDifficultyBadge(room.difficulty) || ''}
                </div>
                
                <div class="task-list">
                    <h4 style="color: rgba(255,255,255,0.5); font-size: 12px; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 15px;">Tasks</h4>
                    ${room.tasks.map((task, i) => {
        const taskDone = isTaskCompleted(room.id, i);
        return `
                        <div class="task-item ${i === 0 ? 'active' : ''} ${taskDone ? 'completed' : ''}" 
                             onclick="selectTask(${i})" 
                             id="task-item-${i}"
                             style="${taskDone ? 'border-color: rgba(34, 197, 94, 0.5);' : ''}">
                            <span class="task-number" style="${taskDone ? 'background: #22c55e;' : ''}">${i + 1}</span>
                            <span class="task-title" style="${taskDone ? 'color: #22c55e;' : ''}">${task.title}</span>
                            <span class="task-status ${taskDone ? 'completed' : ''}" id="task-status-${i}">
                                <i class="fa-${taskDone ? 'solid' : 'regular'} fa-${taskDone ? 'check-circle' : 'circle'}" style="${taskDone ? 'color: #22c55e;' : ''}"></i>
                            </span>
                        </div>
                    `}).join('')}
                </div>
                
                <div style="margin-top: 30px; padding: 20px; background: rgba(255,255,255,0.03); border-radius: 12px;">
                    <div style="display: flex; justify-content: space-between; color: rgba(255,255,255,0.5); font-size: 13px; margin-bottom: 10px;">
                        <span>Room Progress</span>
                        <span id="room-progress">${getCompletedTaskCount(room.id)}/${room.tasks.length}</span>
                    </div>
                    <div style="height: 8px; background: rgba(255,255,255,0.1); border-radius: 4px; overflow: hidden;">
                        <div id="room-progress-bar" style="width: ${(getCompletedTaskCount(room.id) / room.tasks.length) * 100}%; height: 100%; background: ${path.color}; transition: width 0.3s ease;"></div>
                    </div>
                </div>
                
                <!-- Path Navigation -->
                <div style="margin-top: 20px; padding: 15px; background: rgba(255,255,255,0.03); border-radius: 12px;" id="path-nav-container">
                    <div style="color: rgba(255,255,255,0.5); font-size: 11px; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 12px;">
                        <i class="fa-solid fa-route"></i> Path Navigation
                    </div>
                    <div style="display: flex; gap: 10px;">
                        <button id="prev-module-btn" style="flex: 1; padding: 10px; background: rgba(255,255,255,0.05); border: 1px solid rgba(255,255,255,0.1); border-radius: 8px; color: rgba(255,255,255,0.6); cursor: pointer; font-size: 12px; display: flex; align-items: center; justify-content: center; gap: 6px;" onclick="goToPrevRoom()" ${(() => { const navInfo = getRoomNavigationInfo(path.id, room.id); return navInfo?.isFirst ? 'disabled style="opacity: 0.3; cursor: not-allowed;"' : ''; })()}>
                            <i class="fa-solid fa-chevron-left"></i> Prev
                        </button>
                        <button id="next-module-btn" style="flex: 1; padding: 10px; background: linear-gradient(135deg, ${path.color}44, ${path.color}22); border: 1px solid ${path.color}44; border-radius: 8px; color: #fff; cursor: pointer; font-size: 12px; display: flex; align-items: center; justify-content: center; gap: 6px;" onclick="goToNextRoom()">
                            Next <i class="fa-solid fa-chevron-right"></i>
                        </button>
                    </div>
                    <div style="text-align: center; margin-top: 12px; color: rgba(255,255,255,0.4); font-size: 11px;" id="path-position-indicator">
                        ${(() => { const navInfo = getRoomNavigationInfo(path.id, room.id); return navInfo ? `Module ${navInfo.currentPosition} of ${navInfo.totalRooms}` : ''; })()}
                    </div>
                </div>
                
                <!-- Complete Room Button -->
                <button id="complete-room-btn" onclick="completeCurrentRoom()" style="
                    width: 100%;
                    margin-top: 20px;
                    padding: 14px;
                    background: linear-gradient(135deg, #22c55e, #16a34a);
                    border: none;
                    border-radius: 12px;
                    color: #fff;
                    font-weight: 600;
                    font-size: 14px;
                    cursor: pointer;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    gap: 10px;
                    transition: all 0.3s ease;
                ">
                    <i class="fa-solid fa-check-circle"></i> Complete & Continue
                </button>
            </div>
            
            <div class="room-main" id="room-main-content">
                ${renderLearnTaskContent(room.tasks[0], 0, path.color, room)}
            </div>
        </div >
        `;
}

function renderLearnTaskContent(task, taskIndex, color, room) {
    // Check if this task is already completed
    const taskCompleted = isTaskCompleted(room.id, taskIndex);

    // Convert markdown to HTML (simple conversion)
    let html = task.content
        .replace(/^### (.*$)/gim, '<h3>$1</h3>')
        .replace(/^## (.*$)/gim, '<h2>$1</h2>')
        .replace(/^# (.*$)/gim, '<h1>$1</h1>')
        .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
        .replace(/\*(.*?)\*/g, '<em>$1</em>')
        .replace(/`([^`]+)`/g, '<code>$1</code>')
        .replace(/```(\w*)\n([\s\S]*?)```/g, '<pre><code>$2</code></pre>')
        .replace(/^\| (.*) \|$/gim, (match) => {
            const cells = match.slice(1, -1).split('|').map(c => c.trim());
            return '<tr>' + cells.map(c => `<td>${c}</td>`).join('') + '</tr>';
        })
        .replace(/\n/g, '<br>');

    return `
        <style>
            @keyframes shake {
                0%, 100% { transform: translateX(0); }
                25% { transform: translateX(-5px); }
                75% { transform: translateX(5px); }
            }
            @keyframes pulse {
                0%, 100% { opacity: 1; }
                50% { opacity: 0.6; }
            }
            .task-completed-badge {
                display: inline-flex;
                align-items: center;
                gap: 8px;
                background: linear-gradient(135deg, rgba(34, 197, 94, 0.2), rgba(34, 197, 94, 0.1));
                border: 1px solid rgba(34, 197, 94, 0.4);
                color: #22c55e;
                padding: 8px 16px;
                border-radius: 10px;
                font-weight: 600;
                margin-bottom: 15px;
            }
        </style>
        
        <div class="task-content">
            ${taskCompleted ? `
                <div class="task-completed-badge">
                    <i class="fa-solid fa-check-circle"></i> Task Completed!
                </div>
            ` : ''}
            ${html}
        </div>
        
        <div class="question-box" style="${taskCompleted ? 'opacity: 0.8;' : ''}">
            <div class="question-label">
                <i class="fa-solid fa-${taskCompleted ? 'check-circle' : 'question-circle'}" style="${taskCompleted ? 'color: #22c55e;' : ''}"></i> 
                ${taskCompleted ? 'Completed' : 'Question'}
            </div>
            <div class="question-text">${task.question}</div>
            <div class="answer-input">
                <input type="text" id="answer-input" 
                    placeholder="${taskCompleted ? 'Already answered correctly!' : 'Enter your answer...'}" 
                    onkeypress="if(event.key==='Enter')submitAnswer(${taskIndex})"
                    ${taskCompleted ? 'disabled value="✓ Correct answer submitted" style="background: rgba(34, 197, 94, 0.2); border-color: #22c55e; color: #22c55e;"' : ''}>
                <button onclick="submitAnswer(${taskIndex})" ${taskCompleted ? 'disabled style="opacity: 0.5; cursor: not-allowed;"' : ''}>
                    <i class="fa-solid fa-${taskCompleted ? 'check' : 'check'}"></i> ${taskCompleted ? 'Done' : 'Submit'}
                </button>
            </div>
            ${!taskCompleted && task.hints && task.hints.length > 0 ? `
                <button class="hint-btn" onclick="showHint(${taskIndex}, 0)">
                    <i class="fa-solid fa-lightbulb"></i>
                    Get Hint (-${task.hints[0].cost} pts)
                </button>
                <div id="hint-display-${taskIndex}" style="margin-top: 15px;"></div>
            ` : ''}
        </div>
    `;
}

function selectTask(taskIndex) {
    const roomData = window.currentRoom;
    if (!roomData) return;

    const { room, path } = roomData;

    // Update active task
    document.querySelectorAll('.task-item').forEach((item, i) => {
        item.classList.toggle('active', i === taskIndex);
    });

    // Render task content
    document.getElementById('room-main-content').innerHTML = renderLearnTaskContent(
        room.tasks[taskIndex],
        taskIndex,
        path.color,
        room
    );
}

function submitAnswer(taskIndex) {
    const roomData = window.currentRoom;
    if (!roomData) return;

    const { room, path } = roomData;
    const task = room.tasks[taskIndex];
    const input = document.getElementById('answer-input');
    const answer = input.value.trim();

    // Check if already completed
    if (isTaskCompleted(room.id, taskIndex)) {
        showNotification('Already completed!', 'info');
        return;
    }

    if (answer.toLowerCase() === task.answer.toLowerCase()) {
        // Correct answer - save to localStorage
        markTaskComplete(room.id, taskIndex);

        // Update UI
        document.getElementById(`task-status-${taskIndex}`).innerHTML = '<i class="fa-solid fa-check-circle" style="color: #22c55e;"></i>';
        document.getElementById(`task-status-${taskIndex}`).classList.add('completed');
        document.getElementById(`task-item-${taskIndex}`).style.borderColor = 'rgba(34, 197, 94, 0.5)';

        // Update progress
        const completedCount = getCompletedTaskCount(room.id);
        document.getElementById('room-progress').textContent = `${completedCount}/${room.tasks.length}`;
        document.getElementById('room-progress-bar').style.width = `${(completedCount / room.tasks.length) * 100}%`;

        // Disable input
        input.disabled = true;
        input.value = '✓ ' + answer;
        input.style.background = 'rgba(34, 197, 94, 0.2)';
        input.style.borderColor = '#22c55e';

        // Show success message
        const xpEarned = task.points || 25;
        showNotification('✅ Correct! +' + xpEarned + ' XP', 'success');

        // Add XP to league (async, don't await)
        if (typeof LeaguesAPI !== 'undefined' && AuthState.isLoggedIn()) {
            LeaguesAPI.addXP(xpEarned).then(result => {
                if (result.success) {
                    console.log('League XP updated:', result.weekly_xp);
                }
            }).catch(err => console.log('League XP update failed:', err));
        }

        // Check if all tasks completed
        if (areAllRoomTasksCompleted(room.id, room.tasks.length)) {
            // Enable the complete button with animation
            const completeBtn = document.getElementById('complete-room-btn');
            if (completeBtn) {
                completeBtn.style.animation = 'pulse-glow 1s ease-in-out infinite';
                completeBtn.innerHTML = '<i class="fa-solid fa-trophy"></i> All Tasks Done! Continue';
            }
            showNotification('🎉 All tasks completed! Click "Continue" to proceed', 'success');
        } else {
            // Move to next task if available
            if (taskIndex < room.tasks.length - 1) {
                setTimeout(() => selectTask(taskIndex + 1), 1200);
            }
        }
    } else {
        // Wrong answer
        input.style.borderColor = '#ef4444';
        input.style.animation = 'shake 0.5s ease-in-out';
        setTimeout(() => {
            input.style.borderColor = 'rgba(255,255,255,0.1)';
            input.style.animation = '';
        }, 1500);
        showNotification('❌ Wrong answer, try again!', 'error');
    }
}

function showHint(taskIndex, hintIndex) {
    const roomData = window.currentRoom;
    if (!roomData) return;

    const task = roomData.room.tasks[taskIndex];
    if (!task.hints || !task.hints[hintIndex]) return;

    const hint = task.hints[hintIndex];
    document.getElementById(`hint-display-${taskIndex}`).innerHTML = `
        <div style="background: rgba(245, 158, 11, 0.1); border: 1px solid rgba(245, 158, 11, 0.3); border-radius: 10px; padding: 15px; color: #f59e0b;">
            <i class="fa-solid fa-lightbulb"></i> <strong>Hint:</strong> ${hint.text}
        </div>
    `;
}

// Make functions globally available
window.pageLearn = pageLearn;
window.openLearningPath = openLearningPath;
window.openRoom = openRoom;
window.togglePathUnit = togglePathUnit;
window.selectTask = selectTask;
window.submitAnswer = submitAnswer;
window.showHint = showHint;

// ==================== MODULE DETAIL PAGE ====================
function openModule(moduleId) {
    const mod = window.UnifiedLearningData?.modules?.find(m => m.id === moduleId);
    if (!mod) {
        console.error('Module not found:', moduleId);
        return;
    }
    document.getElementById('content').innerHTML = renderModulePage(mod);
}

function renderModulePage(mod) {
    // Use module's own rooms array
    const moduleRooms = mod.rooms || [];
    const skills = mod.skills || [];

    // Calculate progress
    const totalRooms = moduleRooms.length;
    const completedRooms = moduleRooms.filter(room => isModuleRoomCompleted(mod.id, room.id)).length;
    const progressPercent = totalRooms > 0 ? (completedRooms / totalRooms) * 100 : 0;

    return `
        <div class="module-detail-page">
            <style>
                .module-detail-page {
                    min-height: 100vh;
                    background: linear-gradient(135deg, #0f0c29 0%, #302b63 50%, #24243e 100%);
                    padding: 40px 20px;
                }
                .module-container { max-width: 1000px; margin: 0 auto; }
                .module-back-btn {
                    display: inline-flex; align-items: center; gap: 10px;
                    color: rgba(255,255,255,0.7); font-size: 15px; cursor: pointer;
                    padding: 10px 20px; background: rgba(255,255,255,0.05);
                    border-radius: 10px; border: none; margin-bottom: 30px;
                    transition: all 0.3s ease;
                }
                .module-back-btn:hover { background: rgba(255,255,255,0.1); color: #fff; }
                .module-hero {
                    background: linear-gradient(135deg, ${mod.color}20, rgba(0,0,0,0.3));
                    border: 2px solid ${mod.color}40;
                    border-radius: 24px; padding: 50px; text-align: center; margin-bottom: 40px;
                }
                .module-hero-icon {
                    width: 100px; height: 100px; background: ${mod.color};
                    border-radius: 24px; display: flex; align-items: center; justify-content: center;
                    font-size: 48px; color: #fff; margin: 0 auto 25px;
                    box-shadow: 0 20px 40px ${mod.color}40;
                }
                .module-hero-title { font-size: 2.5rem; font-weight: 800; color: #fff; margin-bottom: 15px; font-family: 'Orbitron', sans-serif; }
                .module-hero-desc { color: rgba(255,255,255,0.7); font-size: 1.1rem; max-width: 600px; margin: 0 auto 25px; }
                
                .module-progress-section {
                    background: rgba(0,0,0,0.2);
                    border-radius: 16px;
                    padding: 20px;
                    margin-top: 25px;
                }
                .module-progress-header { display: flex; justify-content: space-between; margin-bottom: 10px; }
                .module-progress-label { color: rgba(255,255,255,0.6); font-size: 14px; }
                .module-progress-value { color: ${mod.color}; font-weight: 700; }
                .module-progress-bar { height: 10px; background: rgba(255,255,255,0.1); border-radius: 5px; overflow: hidden; }
                .module-progress-fill { height: 100%; background: ${mod.color}; border-radius: 5px; transition: width 0.5s ease; }
                
                .module-skills-section { margin-bottom: 40px; }
                .section-title { font-size: 1.4rem; color: #fff; margin-bottom: 20px; display: flex; align-items: center; gap: 12px; }
                .section-title i { color: ${mod.color}; }
                .skills-grid { display: flex; flex-wrap: wrap; gap: 12px; }
                .skill-badge {
                    background: ${mod.color}20; border: 1px solid ${mod.color}60;
                    padding: 12px 20px; border-radius: 30px; color: ${mod.color};
                    font-weight: 600; font-size: 14px;
                }
                .rooms-section { margin-bottom: 40px; }
                .room-card {
                    background: rgba(255,255,255,0.03); border: 2px solid rgba(255,255,255,0.1);
                    border-radius: 16px; padding: 25px; margin-bottom: 15px;
                    display: flex; align-items: center; gap: 20px;
                    cursor: pointer; transition: all 0.3s ease;
                }
                .room-card:hover { border-color: ${mod.color}; transform: translateX(5px); }
                .room-card.completed { border-color: #22c55e60; background: rgba(34, 197, 94, 0.05); }
                .room-card-icon {
                    width: 55px; height: 55px; background: ${mod.color}20;
                    border-radius: 14px; display: flex; align-items: center; justify-content: center;
                    font-size: 22px; color: ${mod.color};
                }
                .room-card.completed .room-card-icon { background: #22c55e; color: #fff; }
                .room-card-info { flex: 1; }
                .room-card-title { color: #fff; font-weight: 600; font-size: 16px; margin-bottom: 6px; }
                .room-card-desc { color: rgba(255,255,255,0.5); font-size: 13px; margin-bottom: 8px; }
                .room-card-meta { display: flex; gap: 15px; }
                .room-card-meta span { color: rgba(255,255,255,0.4); font-size: 12px; display: flex; align-items: center; gap: 5px; }
                .room-card-meta i { color: ${mod.color}; }
                .room-card-status { padding: 8px 15px; border-radius: 8px; font-size: 12px; font-weight: 600; }
                .room-card-status.completed { background: rgba(34, 197, 94, 0.2); color: #22c55e; }
                .room-card-status.available { background: ${mod.color}20; color: ${mod.color}; }
                .start-module-btn {
                    width: 100%; padding: 18px; background: linear-gradient(135deg, ${mod.color}, ${mod.color}cc);
                    border: none; border-radius: 14px; color: #fff; font-weight: 700;
                    font-size: 16px; cursor: pointer; display: flex; align-items: center;
                    justify-content: center; gap: 12px; transition: all 0.3s ease;
                }
                .start-module-btn:hover { transform: scale(1.02); box-shadow: 0 10px 30px ${mod.color}40; }
            </style>
            
            <div class="module-container">
                <button class="module-back-btn" onclick="loadPage('learn'); setTimeout(() => switchLearnTab('modules'), 100);">
                    <i class="fa-solid fa-arrow-left"></i> Back to Modules
                </button>
                
                <div class="module-hero">
                    <div class="module-hero-icon"><i class="${mod.icon.includes('fab') ? mod.icon : 'fa-solid ' + mod.icon}"></i></div>
                    <h1 class="module-hero-title">${mod.title}</h1>
                    <p class="module-hero-desc">${mod.description}</p>
                    <div style="display: flex; justify-content: center; gap: 30px; color: rgba(255,255,255,0.6);">
                        <span><i class="fa-solid fa-clock" style="color: ${mod.color}; margin-right: 8px;"></i>${mod.estimatedHours}h</span>
                        <span><i class="fa-solid fa-signal" style="color: ${mod.color}; margin-right: 8px;"></i>${mod.difficulty}</span>
                        <span><i class="fa-solid fa-door-open" style="color: ${mod.color}; margin-right: 8px;"></i>${moduleRooms.length} Rooms</span>
                    </div>
                    
                    <div class="module-progress-section">
                        <div class="module-progress-header">
                            <span class="module-progress-label"><i class="fa-solid fa-chart-line" style="margin-right: 6px;"></i>Your Progress</span>
                            <span class="module-progress-value">${completedRooms}/${totalRooms} Rooms</span>
                        </div>
                        <div class="module-progress-bar">
                            <div class="module-progress-fill" style="width: ${progressPercent}%;"></div>
                        </div>
                    </div>
                </div>
                
                <div class="module-skills-section">
                    <div class="mr-skills">
                        <div class="mr-skills-title">Skills in this module</div>
                        <div class="mr-skills-list">
                            ${skills.map(s => `<span class="mr-skill-badge">${s}</span>`).join('')}
                        </div>
                    </div>
                </div>
                
                <div class="rooms-section">
                    <h2 class="section-title"><i class="fa-solid fa-door-open"></i> Module Rooms</h2>
                    ${moduleRooms.map((room, index) => {
        const isComplete = isModuleRoomCompleted(mod.id, room.id);
        return `
                        <div class="room-card ${isComplete ? 'completed' : ''}" onclick="openModuleRoom('${mod.id}', '${room.id}')">
                            <div class="room-card-icon">
                                <i class="fa-solid ${isComplete ? 'fa-check' : 'fa-door-open'}"></i>
                            </div>
                            <div class="room-card-info">
                                <div class="room-card-title">${index + 1}. ${room.title}</div>
                                <div class="room-card-desc">${room.description}</div>
                                <div class="room-card-meta">
                                    <span><i class="fa-solid fa-clock"></i> ${room.estimatedTime}</span>
                                    <span><i class="fa-solid fa-star"></i> ${room.points} pts</span>
                                    <span><i class="fa-solid fa-list-check"></i> ${room.tasks?.length || 0} Tasks</span>
                                    ${room.hasLab ? '<span><i class="fa-solid fa-flask"></i> Has Lab</span>' : ''}
                                </div>
                            </div>
                            <div class="room-card-status ${isComplete ? 'completed' : 'available'}">
                                <i class="fa-solid fa-${isComplete ? 'check-circle' : 'play-circle'}"></i>
                                ${isComplete ? 'Completed' : 'Start'}
                            </div>
                        </div>
                    `}).join('')}
                </div>
                
                <button class="start-module-btn" onclick="startModuleSequence('${mod.id}')">
                    <i class="fa-solid fa-play"></i> ${completedRooms > 0 ? 'Continue Learning' : 'Start Module'}
                </button>
            </div>
        </div>
    `;
}

// ==================== WALKTHROUGH DETAIL PAGE ====================
function openWalkthrough(walkthroughId) {
    const wt = window.UnifiedLearningData?.walkthroughs?.find(w => w.id === walkthroughId);
    if (!wt) {
        console.error('Walkthrough not found:', walkthroughId);
        return;
    }
    document.getElementById('content').innerHTML = renderWalkthroughPage(wt);
}

function renderWalkthroughPage(wt) {
    return `
        <div class="walkthrough-detail-page">
            <style>
                .walkthrough-detail-page {
                    min-height: 100vh;
                    background: linear-gradient(135deg, #0f0c29 0%, #302b63 50%, #24243e 100%);
                    padding: 40px 20px;
                }
                .wt-container { max-width: 900px; margin: 0 auto; }
                .wt-back-btn {
                    display: inline-flex; align-items: center; gap: 10px;
                    color: rgba(255,255,255,0.7); font-size: 15px; cursor: pointer;
                    padding: 10px 20px; background: rgba(255,255,255,0.05);
                    border-radius: 10px; border: none; margin-bottom: 30px;
                }
                .wt-back-btn:hover { background: rgba(255,255,255,0.1); color: #fff; }
                .wt-hero {
                    background: linear-gradient(135deg, rgba(59, 130, 246, 0.15), rgba(0,0,0,0.3));
                    border: 2px solid rgba(59, 130, 246, 0.3);
                    border-radius: 24px; padding: 40px; margin-bottom: 40px;
                }
                .wt-hero-header { display: flex; align-items: center; gap: 25px; margin-bottom: 25px; }
                .wt-hero-icon {
                    width: 80px; height: 80px; background: rgba(59, 130, 246, 0.2);
                    border-radius: 20px; display: flex; align-items: center; justify-content: center;
                    font-size: 36px; color: #3b82f6;
                }
                .wt-hero-title { font-size: 2rem; font-weight: 800; color: #fff; margin-bottom: 10px; }
                .wt-hero-desc { color: rgba(255,255,255,0.6); font-size: 15px; }
                .wt-meta { display: flex; flex-wrap: wrap; gap: 20px; margin-top: 20px; }
                .wt-meta-item { color: rgba(255,255,255,0.6); font-size: 14px; display: flex; align-items: center; gap: 8px; }
                .wt-meta-item i { color: #3b82f6; }
                .wt-steps { margin-bottom: 40px; }
                .wt-step {
                    background: rgba(255,255,255,0.03); border: 1px solid rgba(255,255,255,0.1);
                    border-radius: 16px; padding: 25px; margin-bottom: 15px;
                    display: flex; align-items: flex-start; gap: 20px;
                }
                .step-number {
                    width: 40px; height: 40px; background: #3b82f6;
                    border-radius: 50%; display: flex; align-items: center; justify-content: center;
                    font-weight: 700; color: #fff; flex-shrink: 0;
                }
                .step-content { flex: 1; }
                .step-title { color: #fff; font-weight: 600; margin-bottom: 8px; }
                .step-desc { color: rgba(255,255,255,0.5); font-size: 14px; }
                .wt-flags { margin-bottom: 40px; }
                .flag-input-group {
                    background: rgba(0,0,0,0.3); border-radius: 14px; padding: 20px; margin-bottom: 15px;
                }
                .flag-label { color: rgba(255,255,255,0.6); font-size: 13px; margin-bottom: 10px; }
                .flag-input {
                    width: 100%; padding: 15px; background: rgba(255,255,255,0.05);
                    border: 1px solid rgba(255,255,255,0.1); border-radius: 10px;
                    color: #fff; font-family: 'Fira Code', monospace; font-size: 14px;
                }
                .flag-input::placeholder { color: rgba(255,255,255,0.3); }
                .submit-flag-btn {
                    margin-top: 15px; padding: 12px 25px; background: #3b82f6;
                    border: none; border-radius: 10px; color: #fff; font-weight: 600;
                    cursor: pointer;
                }
                .submit-flag-btn:hover { background: #2563eb; }
                .wt-start-btn {
                    width: 100%; padding: 18px; background: linear-gradient(135deg, #22c55e, #16a34a);
                    border: none; border-radius: 14px; color: #fff; font-weight: 700;
                    font-size: 16px; cursor: pointer; display: flex; align-items: center;
                    justify-content: center; gap: 12px;
                }
                .wt-start-btn:hover { box-shadow: 0 10px 30px rgba(34, 197, 94, 0.3); }
            </style>
            
            <div class="wt-container">
                <button class="wt-back-btn" onclick="loadPage('learn'); setTimeout(() => switchLearnTab('walkthroughs'), 100);">
                    <i class="fa-solid fa-arrow-left"></i> Back to Walkthroughs
                </button>
                
                <div class="wt-hero">
                    <div class="wt-hero-header">
                        <div class="wt-hero-icon">
                            <i class="${wt.os === 'windows' ? 'fab fa-windows' : 'fab fa-linux'}"></i>
                        </div>
                        <div>
                            <h1 class="wt-hero-title">${wt.title}</h1>
                            <p class="wt-hero-desc">${wt.description}</p>
                        </div>
                    </div>
                    <div class="wt-meta">
                        <div class="wt-meta-item"><i class="fa-solid fa-signal"></i> ${wt.difficulty}</div>
                        <div class="wt-meta-item"><i class="fa-solid fa-clock"></i> ${wt.estimatedTime}</div>
                        <div class="wt-meta-item"><i class="fa-solid fa-star"></i> ${wt.points} points</div>
                        <div class="wt-meta-item"><i class="fa-solid fa-user"></i> ${wt.author}</div>
                        <div class="wt-meta-item"><i class="fa-solid fa-check"></i> ${wt.solves} solves</div>
                    </div>
                </div>
                
                <div class="wt-steps">
                    <h2 style="color: #fff; margin-bottom: 20px;"><i class="fa-solid fa-list-check" style="color: #3b82f6; margin-right: 10px;"></i>Walkthrough Steps</h2>
                    ${wt.steps.map((step, i) => `
                        <div class="wt-step">
                            <div class="step-number">${i + 1}</div>
                            <div class="step-content">
                                <div class="step-title">${step}</div>
                                <div class="step-desc">Complete this step to progress</div>
                            </div>
                        </div>
                    `).join('')}
                </div>
                
                <div class="wt-flags">
                    <h2 style="color: #fff; margin-bottom: 20px;"><i class="fa-solid fa-flag" style="color: #22c55e; margin-right: 10px;"></i>Submit Flags</h2>
                    ${wt.flags.map((flag, i) => `
                        <div class="flag-input-group">
                            <div class="flag-label">Flag ${i + 1}</div>
                            <input type="text" class="flag-input" id="wt-flag-${i}" placeholder="FLAG{...}">
                            <button class="submit-flag-btn" onclick="submitWtFlag('${wt.id}', ${i}, '${flag}')">Submit</button>
                        </div>
                    `).join('')}
                </div>
                
                <button class="wt-start-btn" onclick="startMachine('walkthrough', '${wt.id}')">
                    <i class="fa-solid fa-play"></i> Start Machine
                </button>
            </div>
        </div>
    `;
}

function submitWtFlag(wtId, flagIndex, correctFlag) {
    const input = document.getElementById('wt-flag-' + flagIndex);
    const answer = input.value.trim();

    if (answer === correctFlag) {
        input.style.borderColor = '#22c55e';
        input.disabled = true;
        if (typeof showToast === 'function') {
            showToast('Correct flag! +50 XP', 'success');
        }
    } else {
        input.style.borderColor = '#ef4444';
        setTimeout(() => { input.style.borderColor = 'rgba(255,255,255,0.1)'; }, 1500);
        if (typeof showToast === 'function') {
            showToast('Incorrect flag, try again!', 'error');
        }
    }
}

// ==================== NETWORK DETAIL PAGE ====================
function openNetwork(networkId) {
    const net = window.UnifiedLearningData?.networks?.find(n => n.id === networkId);
    if (!net) {
        console.error('Network not found:', networkId);
        return;
    }
    document.getElementById('content').innerHTML = renderNetworkPage(net);
}

function renderNetworkPage(net) {
    return `
        <div class="network-detail-page">
            <style>
                .network-detail-page {
                    min-height: 100vh;
                    background: linear-gradient(135deg, #0f0c29 0%, #1a1a2e 50%, #16213e 100%);
                    padding: 40px 20px;
                }
                .net-container { max-width: 1100px; margin: 0 auto; }
                .net-back-btn {
                    display: inline-flex; align-items: center; gap: 10px;
                    color: rgba(255,255,255,0.7); font-size: 15px; cursor: pointer;
                    padding: 10px 20px; background: rgba(255,255,255,0.05);
                    border-radius: 10px; border: none; margin-bottom: 30px;
                }
                .net-back-btn:hover { background: rgba(255,255,255,0.1); color: #fff; }
                .net-hero {
                    background: linear-gradient(135deg, rgba(245, 158, 11, 0.15), rgba(0,0,0,0.4));
                    border: 2px solid rgba(245, 158, 11, 0.3);
                    border-radius: 24px; padding: 40px; margin-bottom: 40px;
                }
                .net-hero-header { display: flex; align-items: center; gap: 25px; margin-bottom: 25px; }
                .net-hero-icon {
                    width: 90px; height: 90px; background: linear-gradient(135deg, #f59e0b, #d97706);
                    border-radius: 20px; display: flex; align-items: center; justify-content: center;
                    font-size: 40px; color: #000;
                }
                .net-hero-title { font-size: 2.2rem; font-weight: 800; color: #fff; margin-bottom: 10px; font-family: 'Orbitron', sans-serif; }
                .net-hero-desc { color: rgba(255,255,255,0.6); font-size: 15px; }
                .net-stats { display: flex; gap: 30px; margin-top: 20px; }
                .net-stat { text-align: center; }
                .net-stat-value { font-size: 1.5rem; font-weight: 700; color: #f59e0b; }
                .net-stat-label { font-size: 12px; color: rgba(255,255,255,0.5); text-transform: uppercase; }
                .net-topology { margin-bottom: 40px; }
                .topology-card {
                    background: rgba(0,0,0,0.4); border: 1px solid rgba(245, 158, 11, 0.2);
                    border-radius: 16px; padding: 30px;
                }
                .machine-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 20px; margin-top: 20px; }
                .machine-card {
                    background: rgba(255,255,255,0.03); border: 1px solid rgba(255,255,255,0.1);
                    border-radius: 14px; padding: 20px; transition: all 0.3s ease;
                }
                .machine-card:hover { border-color: #f59e0b; transform: translateY(-3px); }
                .machine-header { display: flex; align-items: center; gap: 15px; margin-bottom: 12px; }
                .machine-os {
                    width: 45px; height: 45px; background: rgba(245, 158, 11, 0.2);
                    border-radius: 10px; display: flex; align-items: center; justify-content: center;
                    font-size: 20px; color: #f59e0b;
                }
                .machine-name { color: #fff; font-weight: 600; }
                .machine-role { color: rgba(255,255,255,0.5); font-size: 12px; }
                .machine-ip { font-family: 'Fira Code', monospace; color: #f59e0b; font-size: 13px; margin-top: 10px; }
                .machine-flag-input {
                    width: 100%; margin-top: 12px; padding: 10px; background: rgba(0,0,0,0.3);
                    border: 1px solid rgba(255,255,255,0.1); border-radius: 8px;
                    color: #fff; font-family: 'Fira Code', monospace; font-size: 12px;
                }
                .machine-flag-input::placeholder { color: rgba(255,255,255,0.3); }
                .net-skills { display: flex; flex-wrap: wrap; gap: 10px; margin-bottom: 40px; }
                .net-skill-badge {
                    background: rgba(245, 158, 11, 0.15); border: 1px solid rgba(245, 158, 11, 0.4);
                    padding: 10px 18px; border-radius: 25px; color: #f59e0b; font-weight: 600; font-size: 13px;
                }
                .net-vpn-btn {
                    width: 100%; padding: 18px; background: linear-gradient(135deg, #f59e0b, #d97706);
                    border: none; border-radius: 14px; color: #000; font-weight: 700;
                    font-size: 16px; cursor: pointer; display: flex; align-items: center;
                    justify-content: center; gap: 12px;
                }
                .net-vpn-btn:hover { box-shadow: 0 10px 30px rgba(245, 158, 11, 0.3); }
            </style>
            
            <div class="net-container">
                <button class="net-back-btn" onclick="loadPage('learn'); setTimeout(() => switchLearnTab('networks'), 100);">
                    <i class="fa-solid fa-arrow-left"></i> Back to Networks
                </button>
                
                <div class="net-hero">
                    <div class="net-hero-header">
                        <div class="net-hero-icon"><i class="fa-solid ${net.icon}"></i></div>
                        <div>
                            <h1 class="net-hero-title">${net.title}</h1>
                            <p class="net-hero-desc">${net.description}</p>
                        </div>
                    </div>
                    <div class="net-stats">
                        <div class="net-stat"><div class="net-stat-value">${net.machinesCount}</div><div class="net-stat-label">Machines</div></div>
                        <div class="net-stat"><div class="net-stat-value">${net.points}</div><div class="net-stat-label">Points</div></div>
                        <div class="net-stat"><div class="net-stat-value">${net.estimatedHours}h</div><div class="net-stat-label">Duration</div></div>
                        <div class="net-stat"><div class="net-stat-value">${net.solves}</div><div class="net-stat-label">Solves</div></div>
                    </div>
                </div>
                
                <h2 style="color: #fff; margin-bottom: 15px;"><i class="fa-solid fa-bolt" style="color: #f59e0b; margin-right: 10px;"></i>Required Skills</h2>
                <div class="net-skills">
                    ${net.skills.map(s => `<span class="net-skill-badge">${s}</span>`).join('')}
                </div>
                
                <div class="net-topology">
                    <h2 style="color: #fff; margin-bottom: 15px;"><i class="fa-solid fa-diagram-project" style="color: #f59e0b; margin-right: 10px;"></i>Network Topology</h2>
                    <div class="topology-card">
                        <div style="text-align: center; color: rgba(255,255,255,0.5); margin-bottom: 15px;">
                            <i class="fa-solid fa-sitemap" style="font-size: 30px; color: #f59e0b;"></i>
                            <p style="margin-top: 10px;">${net.topology === 'mesh' ? 'Mesh Network' : net.topology === 'linear' ? 'Linear Chain' : 'Star Topology'}</p>
                        </div>
                        <div class="machine-grid">
                            ${net.machines.map((m, i) => `
                                <div class="machine-card">
                                    <div class="machine-header">
                                        <div class="machine-os"><i class="${m.os === 'windows' ? 'fab fa-windows' : 'fab fa-linux'}"></i></div>
                                        <div>
                                            <div class="machine-name">${m.name}</div>
                                            <div class="machine-role">${m.role}</div>
                                        </div>
                                    </div>
                                    <div class="machine-ip"><i class="fa-solid fa-network-wired"></i> ${m.ip}</div>
                                    <input type="text" class="machine-flag-input" placeholder="Submit flag for ${m.name}...">
                                </div>
                            `).join('')}
                        </div>
                    </div>
                </div>
                
                <button class="net-vpn-btn" onclick="startMachine('network', '${net.id}')">
                    <i class="fa-solid fa-plug"></i> Connect via VPN & Start Lab
                </button>
            </div>
        </div>
    `;
}

// Export all new functions
window.openModule = openModule;
window.openWalkthrough = openWalkthrough;
window.submitWtFlag = submitWtFlag;
window.openNetwork = openNetwork;

// ==================== MODULE PROGRESS TRACKING ====================
// Check if a module room is completed
function isModuleRoomCompleted(moduleId, roomId) {
    const progress = getModuleProgress(moduleId);
    return progress.completedRooms.includes(roomId);
}

function getModuleProgress(moduleId) {
    const saved = localStorage.getItem('moduleProgress_' + moduleId);
    if (saved) return JSON.parse(saved);
    return {
        moduleId: moduleId,
        completedRooms: [],
        currentRoomIndex: 0,
        startedAt: Date.now()
    };
}

function saveModuleProgress(progress) {
    progress.lastAccessedAt = Date.now();
    localStorage.setItem('moduleProgress_' + progress.moduleId, JSON.stringify(progress));
}

function markModuleRoomComplete(moduleId, roomId) {
    const progress = getModuleProgress(moduleId);
    if (!progress.completedRooms.includes(roomId)) {
        progress.completedRooms.push(roomId);
        saveModuleProgress(progress);
    }
}

// Start module sequence
function startModuleSequence(moduleId) {
    const mod = window.UnifiedLearningData?.modules?.find(m => m.id === moduleId);
    if (!mod || !mod.rooms || mod.rooms.length === 0) {
        showNotification('Module content not available', 'error');
        return;
    }

    // Find first incomplete room
    for (const room of mod.rooms) {
        if (!isModuleRoomCompleted(moduleId, room.id)) {
            openModuleRoom(moduleId, room.id);
            return;
        }
    }

    // All rooms completed
    showModuleCompletion(moduleId);
}

// Open a specific module room
function openModuleRoom(moduleId, roomId) {
    const mod = window.UnifiedLearningData?.modules?.find(m => m.id === moduleId);
    if (!mod) return;

    const room = mod.rooms?.find(r => r.id === roomId);
    if (!room) return;

    // Store current module context
    window.currentModuleContext = {
        moduleId: moduleId,
        module: mod,
        room: room,
        roomIndex: mod.rooms.findIndex(r => r.id === roomId)
    };

    document.getElementById('content').innerHTML = renderModuleRoomPage(mod, room);
}

// Render module room page
function renderModuleRoomPage(mod, room) {
    const rooms = mod.rooms || [];
    const roomIndex = rooms.findIndex(r => r.id === room.id);
    const totalRooms = rooms.length;
    const tasks = room.tasks || [];
    const totalTasks = tasks.length;

    // Get task progress
    const completedTasks = tasks.filter((_, i) => isModuleTaskCompleted(mod.id, room.id, i)).length;
    const progressPercent = totalTasks > 0 ? (completedTasks / totalTasks) * 100 : 0;

    return `
        <div class="module-room-page">
            <style>
                .module-room-page {
                    min-height: 100vh;
                    background: linear-gradient(135deg, #0a0a1a, #1a1a2e);
                    display: flex;
                }
                .mr-sidebar {
                    width: 320px;
                    background: rgba(0,0,0,0.3);
                    border-right: 1px solid rgba(255,255,255,0.1);
                    padding: 20px;
                    overflow-y: auto;
                    flex-shrink: 0;
                }
                .mr-back-btn {
                    display: flex; align-items: center; gap: 8px;
                    color: rgba(255,255,255,0.6); font-size: 14px;
                    cursor: pointer; margin-bottom: 20px;
                    padding: 10px; background: rgba(255,255,255,0.05);
                    border-radius: 8px; border: none;
                }
                .mr-back-btn:hover { color: #fff; background: rgba(255,255,255,0.1); }
                .mr-module-info {
                    background: ${mod.color}15;
                    border: 1px solid ${mod.color}40;
                    border-radius: 12px;
                    padding: 15px;
                    margin-bottom: 20px;
                }
                .mr-module-icon {
                    width: 45px; height: 45px;
                    background: ${mod.color};
                    border-radius: 10px;
                    display: flex; align-items: center; justify-content: center;
                    font-size: 20px; color: #fff;
                    margin-bottom: 10px;
                }
                .mr-module-title { color: #fff; font-weight: 700; font-size: 14px; margin-bottom: 5px; }
                .mr-room-title { color: ${mod.color}; font-size: 12px; }
                
                .mr-progress-section {
                    background: rgba(0,0,0,0.2);
                    border-radius: 10px;
                    padding: 15px;
                    margin-bottom: 20px;
                }
                .mr-progress-header { display: flex; justify-content: space-between; margin-bottom: 8px; }
                .mr-progress-label { color: rgba(255,255,255,0.5); font-size: 12px; }
                .mr-progress-value { color: ${mod.color}; font-weight: 600; font-size: 12px; }
                .mr-progress-bar { height: 8px; background: rgba(255,255,255,0.1); border-radius: 4px; }
                .mr-progress-fill { height: 100%; background: ${mod.color}; border-radius: 4px; }
                
                .mr-task-list { display: flex; flex-direction: column; gap: 8px; }
                .mr-task-item {
                    display: flex; align-items: center; gap: 10px;
                    padding: 12px;
                    background: rgba(255,255,255,0.03);
                    border: 1px solid rgba(255,255,255,0.1);
                    border-radius: 8px;
                    cursor: pointer;
                    transition: all 0.2s ease;
                }
                .mr-task-item:hover { background: rgba(255,255,255,0.06); }
                .mr-task-item.active { border-color: ${mod.color}; background: ${mod.color}10; }
                .mr-task-item.completed { border-color: #22c55e40; }
                .mr-task-num {
                    width: 26px; height: 26px;
                    background: rgba(255,255,255,0.1);
                    border-radius: 50%;
                    display: flex; align-items: center; justify-content: center;
                    font-size: 12px; font-weight: 600; color: rgba(255,255,255,0.6);
                }
                .mr-task-item.completed .mr-task-num { background: #22c55e; color: #fff; }
                .mr-task-item.active .mr-task-num { background: ${mod.color}; color: #fff; }
                .mr-task-title { flex: 1; color: rgba(255,255,255,0.7); font-size: 13px; }
                .mr-task-item.completed .mr-task-title { color: #22c55e; }
                
                .mr-content {
                    flex: 1;
                    padding: 40px;
                    overflow-y: auto;
                }
                .mr-content-inner { max-width: 800px; margin: 0 auto; }
                .mr-room-header { margin-bottom: 30px; }
                .mr-room-name { font-size: 2rem; font-weight: 700; color: #fff; margin-bottom: 10px; }
                .mr-room-meta { display: flex; gap: 20px; color: rgba(255,255,255,0.5); font-size: 14px; }
                .mr-room-meta i { color: ${mod.color}; margin-right: 6px; }
                
                .mr-task-content {
                    background: rgba(255,255,255,0.03);
                    border: 1px solid rgba(255,255,255,0.1);
                    border-radius: 16px;
                    padding: 30px;
                    margin-bottom: 30px;
                }
                .mr-task-heading { font-size: 1.3rem; color: #fff; font-weight: 700; margin-bottom: 20px; }
                .mr-task-body { color: rgba(255,255,255,0.8); line-height: 1.8; }
                .mr-task-body h1, .mr-task-body h2 { color: #fff; margin: 20px 0 15px; }
                .mr-task-body pre { background: #0a0a0a; padding: 15px; border-radius: 8px; overflow-x: auto; }
                .mr-task-body code { font-family: 'JetBrains Mono', monospace; font-size: 14px; }
                .mr-task-body ul, .mr-task-body ol { margin-left: 20px; }
                .mr-task-body table { width: 100%; border-collapse: collapse; margin: 15px 0; }
                .mr-task-body th, .mr-task-body td { padding: 10px; border: 1px solid rgba(255,255,255,0.1); text-align: left; }
                .mr-task-body th { background: rgba(255,255,255,0.05); }
                
                .mr-question-box {
                    background: ${mod.color}10;
                    border: 2px solid ${mod.color}40;
                    border-radius: 12px;
                    padding: 20px;
                    margin-top: 25px;
                }
                .mr-question-label { color: ${mod.color}; font-weight: 600; font-size: 13px; margin-bottom: 10px; }
                .mr-question-text { color: #fff; font-size: 16px; font-weight: 600; margin-bottom: 15px; }
                .mr-answer-row { display: flex; gap: 10px; }
                .mr-answer-input {
                    flex: 1;
                    background: rgba(0,0,0,0.3);
                    border: 1px solid rgba(255,255,255,0.2);
                    padding: 12px 15px;
                    border-radius: 8px;
                    color: #fff;
                    font-size: 14px;
                }
                .mr-submit-btn {
                    background: ${mod.color};
                    border: none;
                    padding: 12px 25px;
                    border-radius: 8px;
                    color: #fff;
                    font-weight: 600;
                    cursor: pointer;
                }
                .mr-submit-btn:hover { opacity: 0.9; }
                .mr-submit-btn:disabled { opacity: 0.5; cursor: not-allowed; }
                
                .mr-nav-buttons {
                    display: flex;
                    gap: 15px;
                    justify-content: space-between;
                }
                .mr-nav-btn {
                    padding: 14px 25px;
                    border-radius: 10px;
                    font-weight: 600;
                    cursor: pointer;
                    display: flex;
                    align-items: center;
                    gap: 8px;
                    transition: all 0.2s ease;
                }
                .mr-nav-btn.prev { background: rgba(255,255,255,0.1); border: 1px solid rgba(255,255,255,0.2); color: #fff; }
                .mr-nav-btn.next { background: ${mod.color}; border: none; color: #fff; }
                .mr-nav-btn:hover { transform: translateY(-2px); }
            </style>
            
            <div class="mr-sidebar">
                <button class="mr-back-btn" onclick="openModule('${mod.id}')">
                    <i class="fa-solid fa-arrow-left"></i> Back to ${mod.title}
                </button>
                
                <div class="mr-module-info">
                    <div class="mr-module-icon"><i class="${mod.icon.includes('fab') ? mod.icon : 'fa-solid ' + mod.icon}"></i></div>
                    <div class="mr-module-title">${mod.title}</div>
                    <div class="mr-room-title">Room ${roomIndex + 1} of ${totalRooms}</div>
                </div>
                
                <div class="mr-progress-section">
                    <div class="mr-progress-header">
                        <span class="mr-progress-label">Room Progress</span>
                        <span class="mr-progress-value">${completedTasks}/${totalTasks}</span>
                    </div>
                    <div class="mr-progress-bar">
                        <div class="mr-progress-fill" style="width: ${progressPercent}%;"></div>
                    </div>
                </div>
                
                <div class="mr-task-list">
                    ${tasks.map((task, i) => {
        const isComplete = isModuleTaskCompleted(mod.id, room.id, i);
        return `
                        <div class="mr-task-item ${i === 0 ? 'active' : ''} ${isComplete ? 'completed' : ''}" 
                             onclick="showModuleTask('${mod.id}', '${room.id}', ${i})" id="mr-task-${i}">
                            <div class="mr-task-num">${isComplete ? '<i class="fa-solid fa-check"></i>' : (i + 1)}</div>
                            <div class="mr-task-title">${task.title}</div>
                        </div>
                    `}).join('')}
                </div>
            </div>
            
            <div class="mr-content">
                <div class="mr-content-inner">
                    <div class="mr-room-header">
                        <div style="display:flex; justify-content:space-between; align-items:center;">
                            <h1 class="mr-room-name">${room.title}</h1>
                            <button class="mr-submit-btn" style="background: #22c55e;" onclick="startMachine('room', '${room.id}')">
                                <i class="fa-solid fa-power-off"></i> Start Lab
                            </button>
                        </div>
                        <div class="mr-room-meta">
                            <span><i class="fa-solid fa-clock"></i>${room.estimatedTime}</span>
                            <span><i class="fa-solid fa-star"></i>${room.points} pts</span>
                            <span><i class="fa-solid fa-list-check"></i>${totalTasks} Tasks</span>
                        </div>
                    </div>
                    
                    <div id="mr-task-container">
                        ${renderModuleTaskContent(mod, room, 0)}
                    </div>
                    
                    <div class="mr-nav-buttons">
                        ${roomIndex > 0 ? `
                            <button class="mr-nav-btn prev" onclick="openModuleRoom('${mod.id}', '${mod.rooms[roomIndex - 1].id}')">
                                <i class="fa-solid fa-arrow-left"></i> Previous Room
                            </button>
                        ` : '<div></div>'}
                        
                        ${roomIndex < totalRooms - 1 ? `
                            <button class="mr-nav-btn next" onclick="continueToNextModuleRoom('${mod.id}', '${room.id}')">
                                Continue <i class="fa-solid fa-arrow-right"></i>
                            </button>
                        ` : `
                            <button class="mr-nav-btn next" onclick="finishModule('${mod.id}', '${room.id}')">
                                Finish Module <i class="fa-solid fa-trophy"></i>
                            </button>
                        `}
                    </div>
                </div>
            </div>
        </div>
    `;
}

// Render task content
function renderModuleTaskContent(mod, room, taskIndex) {
    const task = room.tasks[taskIndex];
    if (!task) return '<p>Task not found</p>';

    const isComplete = isModuleTaskCompleted(mod.id, room.id, taskIndex);

    // Simple markdown rendering
    let content = task.content
        .replace(/```(\w*)\n([\s\S]*?)```/g, '<pre><code>$2</code></pre>')
        .replace(/`([^`]+)`/g, '<code>$1</code>')
        .replace(/## (.*)/g, '<h2>$1</h2>')
        .replace(/# (.*)/g, '<h1>$1</h1>')
        .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
        .replace(/\n- (.*)/g, '<li>$1</li>')
        .replace(/\n\n/g, '</p><p>')
        .replace(/\|(.*)\|/g, (match) => {
            const cells = match.split('|').filter(c => c.trim());
            return '<tr>' + cells.map(c => `<td>${c.trim()}</td>`).join('') + '</tr>';
        });

    return `
        <div class="mr-task-content">
            <h2 class="mr-task-heading">Task ${taskIndex + 1}: ${task.title}</h2>
            <div class="mr-task-body">
                <p>${content}</p>
            </div>
            
            <div class="mr-question-box">
                <div class="mr-question-label"><i class="fa-solid fa-question-circle" style="margin-right: 6px;"></i>Question</div>
                <div class="mr-question-text">${task.question}</div>
                <div class="mr-answer-row">
                    <input type="text" class="mr-answer-input" id="mr-answer-${taskIndex}" 
                           placeholder="Enter your answer..." ${isComplete ? 'disabled value="✓ Correct!"' : ''}>
                    <button class="mr-submit-btn" onclick="submitModuleAnswer('${mod.id}', '${room.id}', ${taskIndex})" ${isComplete ? 'disabled' : ''}>
                        ${isComplete ? '<i class="fa-solid fa-check"></i> Done' : 'Submit'}
                    </button>
                </div>
            </div>
        </div>
    `;
}

function showModuleTask(moduleId, roomId, taskIndex) {
    const mod = window.UnifiedLearningData?.modules?.find(m => m.id === moduleId);
    if (!mod) return;
    const room = mod.rooms?.find(r => r.id === roomId);
    if (!room) return;

    // Update sidebar active state
    document.querySelectorAll('.mr-task-item').forEach(el => el.classList.remove('active'));
    document.getElementById('mr-task-' + taskIndex)?.classList.add('active');

    // Update content
    document.getElementById('mr-task-container').innerHTML = renderModuleTaskContent(mod, room, taskIndex);
}

// Module task completion tracking
function isModuleTaskCompleted(moduleId, roomId, taskIndex) {
    const key = `moduleTask_${moduleId}_${roomId}`;
    const saved = localStorage.getItem(key);
    if (saved) {
        const data = JSON.parse(saved);
        return data.completedTasks?.includes(taskIndex);
    }
    return false;
}

function markModuleTaskComplete(moduleId, roomId, taskIndex) {
    const key = `moduleTask_${moduleId}_${roomId}`;
    let data = { completedTasks: [] };
    const saved = localStorage.getItem(key);
    if (saved) data = JSON.parse(saved);

    if (!data.completedTasks.includes(taskIndex)) {
        data.completedTasks.push(taskIndex);
        localStorage.setItem(key, JSON.stringify(data));
    }
}

function submitModuleAnswer(moduleId, roomId, taskIndex) {
    const mod = window.UnifiedLearningData?.modules?.find(m => m.id === moduleId);
    if (!mod) return;
    const room = mod.rooms?.find(r => r.id === roomId);
    if (!room) return;
    const task = room.tasks[taskIndex];
    if (!task) return;

    const input = document.getElementById('mr-answer-' + taskIndex);
    const userAnswer = input.value.trim().toLowerCase();
    const correctAnswer = task.answer.toLowerCase();

    if (userAnswer === correctAnswer) {
        markModuleTaskComplete(moduleId, roomId, taskIndex);
        const moduleXP = 10;
        showNotification('Correct! +' + moduleXP + ' XP', 'success');

        // Add XP to league (async, don't await)
        if (typeof LeaguesAPI !== 'undefined' && AuthState.isLoggedIn()) {
            LeaguesAPI.addXP(moduleXP).then(result => {
                if (result.success) {
                    console.log('League XP updated:', result.weekly_xp);
                }
            }).catch(err => console.log('League XP update failed:', err));
        }

        // Update UI
        input.disabled = true;
        input.value = '✓ Correct!';
        input.nextElementSibling.disabled = true;
        input.nextElementSibling.innerHTML = '<i class="fa-solid fa-check"></i> Done';

        // Update sidebar
        const taskItem = document.getElementById('mr-task-' + taskIndex);
        if (taskItem) {
            taskItem.classList.add('completed');
            taskItem.querySelector('.mr-task-num').innerHTML = '<i class="fa-solid fa-check"></i>';
        }

        // Update progress bar
        const tasks = room.tasks || [];
        const completedCount = tasks.filter((_, i) => isModuleTaskCompleted(moduleId, roomId, i)).length;
        const progressFill = document.querySelector('.mr-progress-fill');
        const progressValue = document.querySelector('.mr-progress-value');
        if (progressFill) progressFill.style.width = ((completedCount / tasks.length) * 100) + '%';
        if (progressValue) progressValue.textContent = `${completedCount}/${tasks.length}`;

        // Move to next task if available
        if (taskIndex < tasks.length - 1) {
            setTimeout(() => showModuleTask(moduleId, roomId, taskIndex + 1), 1000);
        }
    } else {
        showNotification('Incorrect, try again!', 'error');
        input.style.borderColor = '#ef4444';
        setTimeout(() => input.style.borderColor = 'rgba(255,255,255,0.2)', 1000);
    }
}

function completeAndNextModuleRoom(moduleId, roomId) {
    markModuleRoomComplete(moduleId, roomId);
    const mod = window.UnifiedLearningData?.modules?.find(m => m.id === moduleId);
    if (!mod) return;

    const roomIndex = mod.rooms.findIndex(r => r.id === roomId);
    if (roomIndex >= 0 && roomIndex < mod.rooms.length - 1) {
        showNotification('Room completed! Moving to next room...', 'success');
        setTimeout(() => openModuleRoom(moduleId, mod.rooms[roomIndex + 1].id), 500);
    }
}

// Continue to next room (checks if all tasks completed first)
function continueToNextModuleRoom(moduleId, roomId) {
    const mod = window.UnifiedLearningData?.modules?.find(m => m.id === moduleId);
    if (!mod) return;
    const room = mod.rooms?.find(r => r.id === roomId);
    if (!room) return;

    const totalTasks = room.tasks?.length || 0;
    const completedCount = (room.tasks || []).filter((_, i) => isModuleTaskCompleted(moduleId, roomId, i)).length;

    if (completedCount < totalTasks) {
        showNotification(`Please complete all ${totalTasks} tasks first! (${completedCount}/${totalTasks} done)`, 'warning');
        return;
    }

    // All tasks completed, mark room as complete and go to next
    markModuleRoomComplete(moduleId, roomId);

    const roomIndex = mod.rooms.findIndex(r => r.id === roomId);
    if (roomIndex >= 0 && roomIndex < mod.rooms.length - 1) {
        showNotification('Room completed! Moving to next room...', 'success');
        setTimeout(() => openModuleRoom(moduleId, mod.rooms[roomIndex + 1].id), 500);
    }
}

// Finish module (checks if all tasks completed first)
function finishModule(moduleId, roomId) {
    const mod = window.UnifiedLearningData?.modules?.find(m => m.id === moduleId);
    if (!mod) return;
    const room = mod.rooms?.find(r => r.id === roomId);
    if (!room) return;

    const totalTasks = room.tasks?.length || 0;
    const completedCount = (room.tasks || []).filter((_, i) => isModuleTaskCompleted(moduleId, roomId, i)).length;

    if (completedCount < totalTasks) {
        showNotification(`Please complete all ${totalTasks} tasks first! (${completedCount}/${totalTasks} done)`, 'warning');
        return;
    }

    // All tasks completed, mark room and module as complete
    markModuleRoomComplete(moduleId, roomId);
    showModuleCompletion(moduleId);
}

function completeModuleRoom(moduleId, roomId) {
    markModuleRoomComplete(moduleId, roomId);
    showModuleCompletion(moduleId);
}

function showModuleCompletion(moduleId) {
    const mod = window.UnifiedLearningData?.modules?.find(m => m.id === moduleId);
    if (!mod) return;

    const totalRooms = mod.rooms?.length || 0;
    const totalPoints = mod.rooms?.reduce((sum, r) => sum + (r.points || 0), 0) || 0;

    document.getElementById('content').innerHTML = `
        <div style="min-height: 100vh; background: linear-gradient(135deg, #0f0c29, #302b63); display: flex; align-items: center; justify-content: center; padding: 40px;">
            <div style="background: rgba(255,255,255,0.05); border: 2px solid ${mod.color}60; border-radius: 32px; padding: 60px; text-align: center; max-width: 500px;">
                <div style="font-size: 80px; margin-bottom: 20px;">🎉</div>
                <h1 style="font-size: 2rem; color: #fff; margin-bottom: 15px;">Module Complete!</h1>
                <p style="color: rgba(255,255,255,0.7); margin-bottom: 30px;">You've mastered ${mod.title}</p>
                
                <div style="display: flex; justify-content: center; gap: 40px; margin-bottom: 30px;">
                    <div style="text-align: center;">
                        <div style="font-size: 2rem; color: ${mod.color}; font-weight: 800;">${totalRooms}</div>
                        <div style="color: rgba(255,255,255,0.5); font-size: 13px;">Rooms</div>
                    </div>
                    <div style="text-align: center;">
                        <div style="font-size: 2rem; color: ${mod.color}; font-weight: 800;">${totalPoints}</div>
                        <div style="color: rgba(255,255,255,0.5); font-size: 13px;">Points</div>
                    </div>
                </div>
                
                <div style="width: 120px; height: 120px; background: ${mod.color}; border-radius: 50%; display: flex; align-items: center; justify-content: center; margin: 0 auto 30px; box-shadow: 0 15px 40px ${mod.color}50;">
                    <i class="${mod.icon.includes('fab') ? mod.icon : 'fa-solid ' + mod.icon}" style="font-size: 50px; color: #fff;"></i>
                </div>
                
                <button style="padding: 14px 30px; background: ${mod.color}; border: none; border-radius: 10px; color: #fff; font-weight: 600; cursor: pointer; margin-right: 10px;" onclick="loadPage('learn'); setTimeout(() => switchLearnTab('modules'), 100);">
                    <i class="fa-solid fa-arrow-left" style="margin-right: 8px;"></i> Back to Modules
                </button>
            </div>
        </div>
    `;
}

// Export module functions
window.isModuleRoomCompleted = isModuleRoomCompleted;
window.getModuleProgress = getModuleProgress;
window.startModuleSequence = startModuleSequence;
window.openModuleRoom = openModuleRoom;
window.showModuleTask = showModuleTask;
window.submitModuleAnswer = submitModuleAnswer;
window.completeAndNextModuleRoom = completeAndNextModuleRoom;
window.continueToNextModuleRoom = continueToNextModuleRoom;
window.finishModule = finishModule;
window.completeModuleRoom = completeModuleRoom;

// ==================== HTB ACADEMY MODULES FUNCTIONS ====================
// Switch between All Modules and Favourite Modules tabs
function switchModulesTabInline(tabName, buttonEl) {
    // Update tab buttons
    document.querySelectorAll('.htb-tab-inline').forEach(tab => {
        tab.classList.remove('active');
    });
    if (buttonEl) buttonEl.classList.add('active');

    // Update section title
    const sectionTitle = document.querySelector('.htb-section-title-inline');
    if (sectionTitle) {
        sectionTitle.textContent = tabName === 'favourites' ? 'Favourite Modules' : 'All Modules';
    }

    // Filter cards based on tab
    const cards = document.querySelectorAll('.htb-module-card-inline');
    const favourites = JSON.parse(localStorage.getItem('favourite_modules') || '[]');

    cards.forEach(card => {
        const moduleId = card.getAttribute('onclick')?.match(/'([^']+)'/)?.[1] || '';
        if (tabName === 'favourites') {
            card.style.display = favourites.includes(moduleId) ? '' : 'none';
        } else {
            card.style.display = '';
        }
    });
}
window.switchModulesTabInline = switchModulesTabInline;

// Filter modules based on HTB style dropdowns
function filterModulesHTB() {
    const categoryFilter = document.getElementById('htb-filter-category-inline')?.value || '';
    const difficultyFilter = document.getElementById('htb-filter-difficulty-inline')?.value || '';
    const tierFilter = document.getElementById('htb-filter-tier-inline')?.value || '';
    const typeFilter = document.getElementById('htb-filter-type-inline')?.value || '';
    const stateFilter = document.getElementById('htb-filter-state-inline')?.value || '';
    const statusFilter = document.getElementById('htb-filter-status-inline')?.value || '';

    const cards = document.querySelectorAll('.htb-module-card-inline');

    cards.forEach(card => {
        const difficulty = card.dataset.difficulty || '';
        const tier = card.dataset.tier || '';
        const type = card.dataset.type || '';
        const status = card.dataset.status || '';
        const title = card.dataset.title || '';

        // Check all filters
        const matchesDifficulty = !difficultyFilter || difficulty === difficultyFilter;
        const matchesTier = !tierFilter || tier === tierFilter;
        const matchesType = !typeFilter || type === typeFilter;
        const matchesStatus = !statusFilter || status === statusFilter;
        // Category filter - check title for keywords
        const matchesCategory = !categoryFilter || title.includes(categoryFilter);

        if (matchesDifficulty && matchesTier && matchesType && matchesStatus && matchesCategory) {
            card.style.display = '';
        } else {
            card.style.display = 'none';
        }
    });
}
window.filterModulesHTB = filterModulesHTB;

// Open module - Navigate to module detail page
function openModule(moduleId) {
    const mod = window.UnifiedLearningData?.modules?.find(m => m.id === moduleId);
    if (mod) {
        document.getElementById('content').innerHTML = renderModulePage(mod);
    } else {
        showNotification('Module not found', 'error');
    }
}
window.openModule = openModule;

console.log('✓ HTB Academy Modules Functions Loaded');

/* ============================================================
   GLOBAL NAVIGATION FUNCTIONS
   ============================================================ */

// Tab Switching Logic
window.switchLearnTab = function (tabName) {
    console.log('Switching to tab:', tabName);

    // 1. Deactivate all tabs and contents
    document.querySelectorAll('.learn-tab-thm').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.learn-tab-content').forEach(c => {
        c.classList.remove('active');
        c.style.display = 'none'; // Ensure check for display property
    });

    // 2. Activate selected tab
    const tabBtn = document.getElementById('tab-' + tabName);
    if (tabBtn) tabBtn.classList.add('active');

    // 3. Activate selected content
    const content = document.getElementById('content-' + tabName);
    if (content) {
        // DYNAMIC CONTENT INJECTION FOR MODULES
        if (tabName === 'modules') {
            if (typeof pageModulesEnhanced === 'function') {
                content.innerHTML = pageModulesEnhanced();
                // Re-initialize filters or event listeners if needed
                // specific logic for modules page can go here
            } else {
                content.innerHTML = '<div style="padding:40px;text-align:center;color:#fff;">Modules System Loading...</div>';
            }
        }

        content.classList.add('active');
        content.style.display = 'block'; // Ensure visibility
    }

    // 4. Update URL hash if needed (optional but good for history)
    // location.hash = tabName;
};

// NOTE: window.openLearningPath is already defined at line ~8690 with the professional HTB style
// Do NOT redefine it here

window.openWalkthrough = function (id) {
    console.log('Opening walkthrough:', id);
    if (typeof loadPage === 'function') {
        loadPage('writeup-viewer', id);
    } else {
        if (typeof showToast === 'function') showToast('Opening Walkthrough: ' + id, 'info');
    }
};

window.openNetwork = function (id) {
    console.log('Opening network:', id);
    if (typeof showToast === 'function') showToast('Opening Network: ' + id, 'info');
};

window.openModule = function (moduleId) {
    const mod = window.UnifiedLearningData?.modules?.find(m => m.id === moduleId);
    if (mod) {
        document.getElementById('content').innerHTML = renderModulePage(mod);
        window.scrollTo(0, 0);
    } else {
        if (typeof showToast === 'function') showToast('Module info not found locally: ' + moduleId, 'info');
    }
}


/* ============================================================
   RENDERERS FOR GENERIC CONTENT
   ============================================================ */

// NOTE: renderPathDetail is defined at line ~7163 with the professional HTB style
// Do NOT redefine it here - the global export is at line ~8685

// Also implementing renderModulePage if it was missing or partial
function renderModulePage(mod) {
    return `
    <div class="module-detail-page">
        <style>
            .module-detail-page { min-height: 100vh; background: #0f172a; font-family: 'Inter', sans-serif; color: #fff; padding: 40px; }
            .mod-header { text-align: center; margin-bottom: 50px; }
            .mod-title { font-size: 2.5rem; font-weight: 800; margin-bottom: 15px; }
            .mod-desc { color: #94a3b8; max-width: 700px; margin: 0 auto; line-height: 1.6; }
            .mod-content { max-width: 900px; margin: 0 auto; background: #1e293b; border-radius: 16px; padding: 40px; border: 1px solid #334155; }
            .mod-sections { display: flex; flex-direction: column; gap: 20px; }
            .mod-section-item { padding: 20px; background: rgba(0,0,0,0.2); border-radius: 8px; border-left: 4px solid #3b82f6; display: flex; justify-content: space-between; align-items: center; cursor: pointer; transition: background 0.2s; }
            .mod-section-item:hover { background: rgba(255,255,255,0.05); }
        </style>
        
        <button class="pd-back-btn" onclick="loadPage('learn')"><i class="fas fa-arrow-left"></i> Back</button>
        
        <div class="mod-header">
            <h1 class="mod-title">${mod.title}</h1>
            <p class="mod-desc">${mod.description}</p>
        </div>

        <div class="mod-content">
            <h2 style="margin-bottom: 25px; font-size: 1.5rem;">Module Sections</h2>
            <div class="mod-sections">
                 ${mod.sections ? mod.sections.map((sec, idx) => `
                    <div class="mod-section-item" onclick="openWalkthrough('${sec.id || idx}')">
                        <div>
                            <div style="font-weight: 700; font-size: 1.1rem; margin-bottom: 5px;">${sec.title}</div>
                            <div style="font-size: 0.9rem; color: #94a3b8;">Section ${idx + 1}</div>
                        </div>
                        <i class="fas fa-chevron-right" style="color: #64748b;"></i>
                    </div>
                 `).join('') : '<p>No sections available.</p>'}
            </div>
        </div>
    </div>
    `;
}
window.renderModulePage = renderModulePage;

// ==================== PATHS SUB-TABS SWITCHING ====================
function switchPathsSubtab(type) {
    // Update active button
    const subtabs = document.querySelectorAll('.paths-subtab');
    subtabs.forEach(tab => {
        tab.classList.remove('active');
        if (tab.dataset.subtab === type) {
            tab.classList.add('active');
        }
    });

    // Filter path cards based on type
    const pathCards = document.querySelectorAll('.path-card-thm');
    pathCards.forEach(card => {
        const cardType = card.dataset.type || 'skill';
        if (type === 'all') {
            card.style.display = '';
        } else if (type === 'skill' && (cardType === 'skill' || cardType === 'training')) {
            card.style.display = '';
        } else if (type === 'job' && (cardType === 'job' || cardType === 'career' || cardType === 'role')) {
            card.style.display = '';
        } else {
            card.style.display = 'none';
        }
    });
}
window.switchPathsSubtab = switchPathsSubtab;

/* ============================================================
   MISSING INTERACTION FUNCTIONS
   ============================================================ */
console.log('Adding interaction functions...');

window.openPath = function (pathId) {
    if (typeof loadPage === 'function') {
        loadPage('lab-path-viewer', pathId);
    }
};

// Aliasing openLearningPath to openPath if it's missing, or vice versa
if (typeof window.openLearningPath === 'undefined') {
    window.openLearningPath = window.openPath;
}

window.openModule = function (moduleId) {
    // If the module ID matches a known page route, use it.
    // Otherwise, check if it's a module object in the data.
    if (typeof loadPage === 'function') {
        // Try pageModuleLearning first if it exists in app.js routing
        // app.js has: case 'module-learning': content.innerHTML = pageModuleLearning(param);
        loadPage('module-learning', moduleId);
    }
};

window.openWalkthrough = function (walkthroughId) {
    if (typeof loadPage === 'function') {
        loadPage('writeup-viewer', walkthroughId);
    }
};

window.openNetwork = function (networkId) {
    // Networks are often treated as rooms in the app
    if (typeof loadPage === 'function') {
        loadPage('room-viewer', networkId);
    }
};

console.log('Interaction functions added.');

// ==========================================
// PATCH: Fix Open Module Room to use Rich Content
// ==========================================
window.openModuleRoom = function (moduleId, roomId) {
    console.log("Opening Room Enhanced v2:", moduleId, roomId);
    const data = window.UnifiedLearningData;

    // Find module
    let mod = data.modules.find(m => m.id === moduleId);
    if (!mod && data.paths) {
        // Try to find module in paths
        for (const p of data.paths) {
            if (p.units) {
                for (const u of p.units) {
                    if (u.rooms) {
                        const found = u.rooms.find(r => r.id === moduleId);
                        if (found) { mod = found; break; }
                    }
                }
            }
            if (mod) break;
        }
    }

    if (!mod) {
        console.warn("Module object not found for ID:", moduleId);
        mod = { id: moduleId, title: 'Module', color: '#3b82f6', icon: 'fa-cube', rooms: [] };
    }

    // PRIORITY 1: Look in the global 'rooms' array (Curriculum 3.5 Rich Content)
    let room = (data.rooms || []).find(r => r.id === roomId);
    console.log("Found in global rooms?", !!room);

    // PRIORITY 2: Look in the module's own rooms list (Legacy/Fallback)
    if (!room && mod.rooms) {
        room = mod.rooms.find(r => r.id === roomId);
        console.log("Found in module rooms?", !!room);
    }

    if (!room) {
        console.error("Room not found:", roomId);
        return;
    }

    // Ensure pathName for breadcrumbs
    if (!room.pathName && mod.pathName) room.pathName = mod.pathName;

    // Render using the existing renderer
    if (typeof renderModuleRoomPage === 'function') {
        let roomIndex = 0;
        if (mod.rooms) {
            roomIndex = mod.rooms.findIndex(r => r.id === roomId);
            if (roomIndex === -1) roomIndex = 0;
        }

        const html = renderModuleRoomPage(mod, room, roomIndex);
        const contentDiv = document.getElementById('content');
        if (contentDiv) {
            contentDiv.innerHTML = html;
            window.scrollTo(0, 0);
        }
    } else {
        console.error("renderModuleRoomPage is not defined!");
    }
};

// ==========================================
// PATCH: Fix Show Module Task (Clicking sidebar)
// ==========================================
window.showModuleTask = function (moduleId, roomId, taskIndex) {
    const data = window.UnifiedLearningData;
    let mod = data.modules.find(m => m.id === moduleId);

    // Helper to find module in paths if not found directly
    if (!mod && data.paths) {
        for (const p of data.paths) {
            if (p.units) {
                for (const u of p.units) {
                    if (u.rooms) {
                        const found = u.rooms.find(r => r.id === moduleId);
                        if (found) { mod = found; break; }
                    }
                }
            }
            if (mod) break;
        }
    }

    if (!mod) { // Last resort dummy
        mod = { id: moduleId, title: 'Module', color: '#3b82f6', icon: 'fa-cube', rooms: [] };
    }

    // PRIORITY: Global Rooms (Rich Content)
    let room = (data.rooms || []).find(r => r.id === roomId);
    if (!room && mod.rooms) {
        room = mod.rooms.find(r => r.id === roomId);
    }

    if (!room) return console.error("Room not found for task display");

    // Render Content
    const container = document.getElementById('mr-task-container');
    if (container && typeof renderModuleTaskContent === 'function') {
        container.innerHTML = renderModuleTaskContent(mod, room, taskIndex);

        // Re-highlight code blocks if Prism/Highlight is used
        if (window.Prism) window.Prism.highlightAll();
    }

    // Update Sidebar Active State
    document.querySelectorAll('.mr-task-item').forEach((el, idx) => {
        if (idx === taskIndex) el.classList.add('active');
        else el.classList.remove('active');
    });
};
