import React from 'react'
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom'
import { AppProvider } from './context/AppContext'
import { ToastProvider } from './context/ToastContext'
import MainLayout from './components/MainLayout'
import Dashboard from './pages/Dashboard';
import Courses from './pages/Courses';
import CourseDetail from './pages/CourseDetail';
import CTF from './pages/CTF';
import Labs from './pages/Labs';
import Achievements from './pages/Achievements';
import Settings from './pages/Settings';
import LessonViewer from './pages/LessonViewer';
import YouTubeHub from './pages/YouTubeHub';
import OWASPRange from './pages/OWASPRange';
import OWASPModule from './pages/OWASPModule';

import CareerHub from './pages/CareerHub';
import SecondBrain from './pages/SecondBrain';
import LegacyTracks from './pages/LegacyTracks';
import ShadowHackSpecs from './pages/ShadowHackSpecs';

import PayloadGenerator from './pages/tools/PayloadGenerator';
import ReportBuilder from './pages/tools/ReportBuilder';
import EncoderTool from './pages/tools/EncoderTool';
import DailyCTF from './pages/ctf/DailyCTF';
import CTFRoomDetail from './pages/ctf/CTFRoomDetail';
import LabWorkspace from './pages/LabWorkspace';
import FreeLabs from './pages/labs/FreeLabs';
import ProLabs from './pages/labs/ProLabs';
// import Cheatsheets from './pages/tools/CheatsheetsPro';
import ToolsHub from './pages/tools/ToolsHub';
import WebExploitation from './pages/tools/WebExploitation';
import CampaignManager from './pages/tools/CampaignManager';
import JSMonitorPro from './pages/tools/JSMonitorPro';
import TargetManager from './pages/tools/TargetManager';
import ReconLab from './pages/tools/ReconLab';
import APISecurityLab from './pages/tools/APISecurityLab';
import MalwareSandbox from './pages/tools/MalwareSandbox';
import OSINTPro from './pages/tools/OSINTPro';
import ADAttackLab from './pages/tools/ADAttackLab';
import FindingReporter from './pages/tools/FindingReporter';
import CVERadar from './pages/tools/CVERadar';
import CVEMuseum from './pages/tools/CVEMuseum';
import HashIdentifier from './pages/tools/HashIdentifier';
import SubnetCalculator from './pages/tools/SubnetCalculator';
import XSSPayloads from './pages/tools/XSSPayloads';
import SQLiPayloads from './pages/tools/SQLiPayloads';
import FileTransferHelper from './pages/tools/FileTransferHelper';
import PrivEscPro from './pages/tools/PrivEscPro';
import CommandReference from './pages/tools/CommandReference';
import MitreAttack from './pages/tools/MitreAttack';
import SocialEngineeringPro from './pages/tools/SocialEngineeringPro';
import PersonaPro from './pages/tools/PersonaPro';
import PasswordCracker from './pages/tools/PasswordCracker';
import CryptoForge from './pages/tools/CryptoForge';
import StegoAnalyst from './pages/tools/StegoAnalyst';
import DevSecOpsLab from './pages/tools/DevSecOpsLab';
import C2CommandCenter from './pages/tools/C2CommandCenter';
import CloudSecurityPro from './pages/tools/CloudSecurityPro';
import LandingNode from './pages/tools/LandingNode';
import CyberIntel from './pages/CyberIntel';
import CyberOpsDashboard from './pages/CyberOpsDashboard';
import TeamsHub from './pages/TeamsHub';
import DailyMissions from './pages/DailyMissions';
import AnalyticsDashboard from './pages/AnalyticsDashboard';
import SkillAssessment from './pages/SkillAssessment';
import RedTeamPath from './pages/paths/RedTeamPath';
import BlueTeamPath from './pages/paths/BlueTeamPath';
import SOCPath from './pages/paths/SOCPath';
import About from './pages/About';
import Partners from './pages/Partners';
import VerifyCertificate from './pages/VerifyCertificate';
import Campaigns from './pages/labs/Campaigns';
import TopicPage from './pages/topics/TopicPage';
import { TOPICS_DATA } from './data/topics';
import CyberTerminal from './components/CyberTerminal';
import AIAssistant from './components/AIAssistant';

function App() {
  return (
    <AppProvider>
      <ToastProvider>
        <Router>
          <Routes>
            {/* Standalone Landing Nodes - No Layout */}
            <Route path="/l/auth" element={<LandingNode />} />

            {/* Application with MainLayout */}
            <Route path="/*" element={
              <MainLayout>
                <Routes>
                  <Route path="/" element={<Dashboard />} />
                  <Route path="/courses" element={<Courses />} />
                  <Route path="/course/:id" element={<CourseDetail />} />
                  <Route path="/course/:courseId/lesson/:lessonId" element={<LessonViewer />} />
                  <Route path="/ctf" element={<CTF />} />
                  <Route path="/ctf/:roomId" element={<CTFRoomDetail />} />
                  <Route path="/ctf/daily" element={<DailyCTF />} />

                  <Route path="/labs" element={<Labs />} />
                  <Route path="/labs/workspace/:id" element={<LabWorkspace />} />
                  <Route path="/labs/free" element={<FreeLabs />} />
                  <Route path="/labs/pro" element={<ProLabs />} />
                  <Route path="/labs/campaigns" element={<Campaigns />} />

                  <Route path="/achievements" element={<Achievements />} />
                  <Route path="/settings" element={<Settings />} />

                  <Route path="/youtube-hub" element={<YouTubeHub />} />
                  <Route path="/owasp-range" element={<OWASPRange />} />
                  <Route path="/owasp-range/:id/:view" element={<OWASPModule />} />

                  <Route path="/career-hub" element={<CareerHub />} />
                  <Route path="/second-brain" element={<SecondBrain />} />
                  <Route path="/legacy-tracks" element={<LegacyTracks />} />
                  <Route path="/specs" element={<ShadowHackSpecs />} />

                  <Route path="/tools" element={<ToolsHub />} />
                  <Route path="/tools/payload-gen" element={<PayloadGenerator />} />
                  <Route path="/tools/report-builder" element={<ReportBuilder />} />
                  <Route path="/tools/encoder" element={<EncoderTool />} />
                  {/* <Route path="/tools/cheatsheets" element={<Cheatsheets />} /> */}
                  <Route path="/tools/web-exploitation" element={<WebExploitation />} />
                  <Route path="/tools/campaign-manager" element={<CampaignManager />} />
                  <Route path="/tools/js-monitor" element={<JSMonitorPro />} />
                  <Route path="/tools/target-manager" element={<TargetManager />} />
                  <Route path="/tools/recon-lab" element={<ReconLab />} />
                  <Route path="/tools/api-security" element={<APISecurityLab />} />
                  <Route path="/tools/malware-sandbox" element={<MalwareSandbox />} />
                  <Route path="/tools/osint-lab" element={<OSINTPro />} />
                  <Route path="/tools/ad-attack-lab" element={<ADAttackLab />} />
                  <Route path="/tools/finding-reporter" element={<FindingReporter />} />
                  <Route path="/tools/cve-radar" element={<CVERadar />} />
                  <Route path="/tools/cve-museum" element={<CVEMuseum />} />
                  <Route path="/tools/hash-identifier" element={<HashIdentifier />} />
                  <Route path="/tools/subnet-calc" element={<SubnetCalculator />} />
                  <Route path="/tools/xss-payloads" element={<XSSPayloads />} />
                  <Route path="/tools/sqli-payloads" element={<SQLiPayloads />} />
                  <Route path="/tools/file-transfer" element={<FileTransferHelper />} />
                  <Route path="/tools/privesc-lab" element={<PrivEscPro />} />
                  <Route path="/tools/command-ref" element={<CommandReference />} />
                  <Route path="/tools/mitre-attack" element={<MitreAttack />} />
                  <Route path="/tools/social-eng" element={<SocialEngineeringPro />} />
                  <Route path="/tools/persona-factory" element={<PersonaPro />} />
                  <Route path="/tools/password-cracker" element={<PasswordCracker />} />
                  <Route path="/tools/crypto-lab" element={<CryptoForge />} />
                  <Route path="/tools/stego-lab" element={<StegoAnalyst />} />
                  <Route path="/tools/devsecops-lab" element={<DevSecOpsLab />} />
                  <Route path="/tools/c2-red-ops" element={<C2CommandCenter />} />
                  <Route path="/tools/cloud-security" element={<CloudSecurityPro />} />
                  <Route path="/cyber-intel" element={<CyberIntel />} />
                  <Route path="/cyber-ops" element={<CyberOpsDashboard />} />
                  <Route path="/teams" element={<TeamsHub />} />
                  <Route path="/missions" element={<DailyMissions />} />
                  <Route path="/analytics" element={<AnalyticsDashboard />} />
                  <Route path="/assessments" element={<SkillAssessment />} />

                  <Route path="/paths/red" element={<RedTeamPath />} />
                  <Route path="/paths/blue" element={<BlueTeamPath />} />
                  <Route path="/paths/soc" element={<SOCPath />} />

                  <Route path="/about" element={<About />} />
                  <Route path="/partners" element={<Partners />} />
                  <Route path="/verify" element={<VerifyCertificate />} />

                  <Route path="/topic/:id" element={<TopicPage />} />
                </Routes>
              </MainLayout>
            } />
          </Routes>
        </Router>
      </ToastProvider>
    </AppProvider>
  );
}

export default App;
