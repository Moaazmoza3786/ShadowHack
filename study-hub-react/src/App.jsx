import React, { Suspense, lazy } from "react";
import {
  BrowserRouter as Router,
  Routes,
  Route,
  Navigate,
} from "react-router-dom";
import { AppProvider } from "./context/AppContext";
import { ToastProvider } from "./context/ToastContext";
import MainLayout from "./components/MainLayout";

// Lazy load all page components
const Dashboard = lazy(() => import("./pages/Dashboard"));
const Courses = lazy(() => import("./pages/Courses"));
const CourseDetail = lazy(() => import("./pages/CourseDetail"));
const CTF = lazy(() => import("./pages/CTF"));
const Labs = lazy(() => import("./pages/Labs"));
const Achievements = lazy(() => import("./pages/Achievements"));
const Settings = lazy(() => import("./pages/Settings"));
const LessonViewer = lazy(() => import("./pages/LessonViewer"));
const YouTubeHub = lazy(() => import("./pages/YouTubeHub"));
const OWASPRange = lazy(() => import("./pages/OWASPRange"));
const OWASPModule = lazy(() => import("./pages/OWASPModule"));
const CareerHub = lazy(() => import("./pages/CareerHub"));
const SecondBrain = lazy(() => import("./pages/SecondBrain"));
const LearningTracks = lazy(() => import("./pages/LearningTracks"));
const ShadowHackSpecs = lazy(() => import("./pages/ShadowHackSpecs"));

// Tools
const PayloadGenerator = lazy(() => import("./pages/tools/PayloadGenerator"));
const ReportBuilder = lazy(() => import("./pages/tools/ReportBuilder"));
const EncoderTool = lazy(() => import("./pages/tools/EncoderTool"));
const CommandReference = lazy(() => import("./pages/tools/CommandReference"));
const Cheatsheets = CommandReference;
const ToolsHub = lazy(() => import("./pages/tools/ToolsHub"));
const WebExploitation = lazy(() => import("./pages/tools/WebExploitation"));
const CampaignManager = lazy(() => import("./pages/tools/CampaignManager"));
const JSMonitorPro = lazy(() => import("./pages/tools/JSMonitorPro"));
const TargetManager = lazy(() => import("./pages/tools/TargetManager"));
const ReconLab = lazy(() => import("./pages/tools/ReconLab"));
const APISecurityLab = lazy(() => import("./pages/tools/APISecurityLab"));
const MalwareSandbox = lazy(() => import("./pages/tools/MalwareSandbox"));
const OSINTPro = lazy(() => import("./pages/tools/OSINTPro"));
const ADAttackLab = lazy(() => import("./pages/tools/ADAttackLab"));
const FindingReporter = lazy(() => import("./pages/tools/FindingReporter"));
const CveRadar = lazy(() => import("./pages/tools/CVERadar"));
const CVEMuseum = lazy(() => import("./pages/tools/CVEMuseum"));
const HashIdentifier = lazy(() => import("./pages/tools/HashIdentifier"));
const SubnetCalculator = lazy(() => import("./pages/tools/SubnetCalculator"));
const XSSPayloads = lazy(() => import("./pages/tools/XSSPayloads"));
const SQLiPayloads = lazy(() => import("./pages/tools/SQLiPayloads"));
const FileTransferHelper = lazy(
  () => import("./pages/tools/FileTransferHelper"),
);
const PrivEscPro = lazy(() => import("./pages/tools/PrivEscPro"));
const MitreAttack = lazy(() => import("./pages/tools/MitreAttack"));
const SocialEngineeringPro = lazy(
  () => import("./pages/tools/SocialEngineeringPro"),
);
const PersonaPro = lazy(() => import("./pages/tools/PersonaPro"));
const HashRefinery = lazy(() => import("./pages/tools/HashRefinery"));
const CryptoForge = lazy(() => import("./pages/tools/CryptoForge"));
const StegoAnalyst = lazy(() => import("./pages/tools/StegoAnalyst"));
const DevSecOpsLab = lazy(() => import("./pages/tools/DevSecOpsLab"));
const C2CommandCenter = lazy(() => import("./pages/tools/C2CommandCenter"));
const CloudSecurityPro = lazy(() => import("./pages/tools/CloudSecurityPro"));
const SubdomainMonitor = lazy(() => import("./pages/tools/SubdomainMonitor"));
const VisualMapper = lazy(() => import("./pages/tools/VisualMapper"));
const FuzzingCockpit = lazy(() => import("./pages/tools/FuzzingCockpit"));
const ProjectTracker = lazy(() => import("./pages/tools/ProjectTracker"));
const LandingNode = lazy(() => import("./pages/tools/LandingNode"));
const AttackChains = lazy(() => import("./pages/tools/AttackChains"));

// Features
const CyberIntel = lazy(() => import("./pages/CyberIntel"));
const CyberOpsDashboard = lazy(() => import("./pages/CyberOpsDashboard"));
const TeamsHub = lazy(() => import("./pages/TeamsHub"));
const DailyMissions = lazy(() => import("./pages/DailyMissions"));
const AnalyticsDashboard = lazy(() => import("./pages/AnalyticsDashboard"));
const SkillAssessment = lazy(() => import("./pages/SkillAssessment"));
const ActivityFeed = lazy(() => import("./pages/ActivityFeed"));
const UserProfile = lazy(() => import("./pages/UserProfile"));
const SettingsPanel = lazy(() => import("./pages/SettingsPanel"));
const Bookmarks = lazy(() => import("./pages/Bookmarks"));
const ChatInterface = lazy(() => import("./pages/ChatInterface"));
const AdminDashboard = lazy(() => import("./pages/AdminDashboard"));
const RedTeamPath = lazy(() => import("./pages/paths/RedTeamPath"));
const BlueTeamPath = lazy(() => import("./pages/paths/BlueTeamPath"));
const SOCPath = lazy(() => import("./pages/paths/SOCPath"));
const About = lazy(() => import("./pages/About"));
const Partners = lazy(() => import("./pages/Partners"));
const VerifyCertificate = lazy(() => import("./pages/VerifyCertificate"));
const Campaigns = lazy(() => import("./pages/labs/Campaigns"));
const TopicPage = lazy(() => import("./pages/topics/TopicPage"));

// CTF & Labs
const DailyCTF = lazy(() => import("./pages/ctf/DailyCTF"));
const CTFRoomDetail = lazy(() => import("./pages/ctf/CTFRoomDetail"));
const LabWorkspace = lazy(() => import("./pages/LabWorkspace"));
const FreeLabs = lazy(() => import("./pages/labs/FreeLabs"));
const ProLabs = lazy(() => import("./pages/labs/ProLabs"));

class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, error: null, errorInfo: null };
  }

  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }

  componentDidCatch(error, errorInfo) {
    console.error("Uncaught error:", error, errorInfo);
    this.setState({ errorInfo });
  }

  render() {
    if (this.state.hasError) {
      return (
        <div
          style={{
            padding: "2rem",
            color: "#ff5555",
            background: "#1a1a1a",
            height: "100vh",
            overflow: "auto",
          }}
        >
          <h1>Something went wrong.</h1>
          <details style={{ whiteSpace: "pre-wrap" }}>
            <summary>Error Details</summary>
            {this.state.error && this.state.error.toString()}
            <br />
            {this.state.errorInfo && this.state.errorInfo.componentStack}
          </details>
        </div>
      );
    }

    return this.props.children;
  }
}

function App() {
  return (
    <ErrorBoundary>
      <AppProvider>
        <ToastProvider>
          <Router>
            <Suspense
              fallback={
                <div className="h-screen w-screen bg-dark-950 flex items-center justify-center">
                  <div className="flex flex-col items-center gap-4">
                    <div className="w-12 h-12 border-4 border-primary-500/20 border-t-primary-500 rounded-full animate-spin"></div>
                    <p className="text-primary-500 font-black uppercase tracking-[0.3em] text-[10px] animate-pulse">
                      Initializing System...
                    </p>
                  </div>
                </div>
              }
            >
              <Routes>
                {/* Standalone Landing Nodes - No Layout */}
                <Route path="/l/auth" element={<LandingNode />} />

                {/* Application with MainLayout */}
                <Route path="/" element={<MainLayout />}>
                  <Route index element={<Dashboard />} />
                  <Route path="/admin" element={<AdminDashboard />} />
                  <Route path="/courses" element={<Courses />} />
                  <Route path="/courses/:courseId" element={<CourseDetail />} />
                  <Route
                    path="/courses/:courseId/lessons/:lessonId"
                    element={<LessonViewer />}
                  />
                  <Route path="/youtube-hub" element={<YouTubeHub />} />
                  <Route path="/career-hub" element={<CareerHub />} />
                  <Route path="/second-brain" element={<SecondBrain />} />
                  <Route path="/learning-tracks" element={<LearningTracks />} />
                  <Route path="/specs" element={<ShadowHackSpecs />} />

                  <Route path="/ctf" element={<CTF />} />
                  <Route path="/ctf/daily" element={<DailyCTF />} />
                  <Route path="/ctf/room/:roomId" element={<CTFRoomDetail />} />

                  <Route path="/labs" element={<Labs />} />
                  <Route path="/labs/free" element={<FreeLabs />} />
                  <Route path="/labs/pro" element={<ProLabs />} />
                  <Route path="/labs/campaigns" element={<Campaigns />} />
                  <Route
                    path="/lab-workspace/:labId"
                    element={<LabWorkspace />}
                  />

                  <Route path="/owasp-range" element={<OWASPRange />} />
                  <Route
                    path="/owasp-range/module/:moduleId"
                    element={<OWASPModule />}
                  />

                  {/* Tools Routes */}
                  <Route path="/tools" element={<ToolsHub />} />
                  <Route
                    path="/tools/payload-gen"
                    element={<PayloadGenerator />}
                  />
                  <Route
                    path="/tools/report-builder"
                    element={<ReportBuilder />}
                  />
                  <Route path="/tools/encoder" element={<EncoderTool />} />
                  <Route path="/tools/cheatsheets" element={<Cheatsheets />} />
                  <Route
                    path="/tools/web-exploitation"
                    element={<WebExploitation />}
                  />
                  <Route
                    path="/tools/campaign-manager"
                    element={<CampaignManager />}
                  />
                  <Route path="/tools/js-monitor" element={<JSMonitorPro />} />
                  <Route
                    path="/tools/target-manager"
                    element={<TargetManager />}
                  />
                  <Route path="/tools/recon-lab" element={<ReconLab />} />
                  <Route
                    path="/tools/api-security"
                    element={<APISecurityLab />}
                  />
                  <Route
                    path="/tools/malware-sandbox"
                    element={<MalwareSandbox />}
                  />
                  <Route path="/tools/osint-lab" element={<OSINTPro />} />
                  <Route
                    path="/tools/ad-attack-lab"
                    element={<ADAttackLab />}
                  />
                  <Route
                    path="/tools/finding-reporter"
                    element={<FindingReporter />}
                  />
                  <Route path="/tools/cve-radar" element={<CveRadar />} />
                  <Route path="/tools/cve-museum" element={<CVEMuseum />} />
                  <Route
                    path="/tools/hash-identifier"
                    element={<HashIdentifier />}
                  />
                  <Route
                    path="/tools/subnet-calculator"
                    element={<SubnetCalculator />}
                  />
                  <Route path="/tools/xss-payloads" element={<XSSPayloads />} />
                  <Route
                    path="/tools/sqli-payloads"
                    element={<SQLiPayloads />}
                  />
                  <Route
                    path="/tools/file-transfer"
                    element={<FileTransferHelper />}
                  />
                  <Route path="/tools/privesc-lab" element={<PrivEscPro />} />
                  <Route
                    path="/tools/command-ref"
                    element={<CommandReference />}
                  />
                  <Route path="/tools/mitre-attack" element={<MitreAttack />} />
                  <Route
                    path="/tools/social-eng"
                    element={<SocialEngineeringPro />}
                  />
                  <Route
                    path="/tools/persona-factory"
                    element={<PersonaPro />}
                  />
                  <Route
                    path="/tools/password-cracker"
                    element={<HashRefinery />}
                  />
                  <Route path="/tools/crypto-lab" element={<CryptoForge />} />
                  <Route path="/tools/stego-lab" element={<StegoAnalyst />} />
                  <Route
                    path="/tools/devsecops-lab"
                    element={<DevSecOpsLab />}
                  />
                  <Route
                    path="/tools/c2-red-ops"
                    element={<C2CommandCenter />}
                  />
                  <Route
                    path="/tools/cloud-security"
                    element={<CloudSecurityPro />}
                  />
                  <Route
                    path="/tools/subdomain-monitor"
                    element={<SubdomainMonitor />}
                  />
                  <Route
                    path="/tools/visual-mapper"
                    element={<VisualMapper />}
                  />
                  <Route
                    path="/tools/fuzzing-cockpit"
                    element={<FuzzingCockpit />}
                  />
                  <Route
                    path="/tools/project-tracker"
                    element={<ProjectTracker />}
                  />
                  <Route path="/tools/chains" element={<AttackChains />} />

                  <Route path="/achievements" element={<Achievements />} />
                  <Route path="/settings" element={<Settings />} />

                  <Route path="/cyber-intel" element={<CyberIntel />} />
                  <Route path="/cyber-ops" element={<CyberOpsDashboard />} />
                  <Route path="/teams" element={<TeamsHub />} />
                  <Route path="/missions" element={<DailyMissions />} />
                  <Route path="/analytics" element={<AnalyticsDashboard />} />
                  <Route path="/assessments" element={<SkillAssessment />} />
                  <Route path="/activity" element={<ActivityFeed />} />
                  <Route path="/profile" element={<UserProfile />} />
                  <Route path="/bookmarks" element={<Bookmarks />} />
                  <Route path="/chat" element={<ChatInterface />} />

                  <Route path="/paths/red" element={<RedTeamPath />} />
                  <Route path="/paths/blue" element={<BlueTeamPath />} />
                  <Route path="/paths/soc" element={<SOCPath />} />

                  <Route path="/about" element={<About />} />
                  <Route path="/partners" element={<Partners />} />
                  <Route path="/verify" element={<VerifyCertificate />} />

                  <Route path="/topic/:id" element={<TopicPage />} />

                  {/* Catch all redirect */}
                  <Route path="*" element={<Navigate to="/" replace />} />
                </Route>
              </Routes>
            </Suspense>
          </Router>
        </ToastProvider>
      </AppProvider>
    </ErrorBoundary>
  );
}

export default App;
