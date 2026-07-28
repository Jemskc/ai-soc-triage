import React, { useState } from 'react';
import { BrowserRouter as Router, Routes, Route, Link, useLocation } from 'react-router-dom';
import { LayoutDashboard, Mail, ShieldAlert, Search, Clock, CheckCircle, AlertTriangle, Globe, FileText, ChevronRight, Upload, X, ExternalLink, Eye, BarChart3 } from 'lucide-react';
import axios from 'axios';

// Dashboard Component
function Dashboard() {
  const [stats] = useState({
    totalAnalyzed: 1247,
    phishingDetected: 89,
    highRisk: 23,
    safeEmails: 1158
  });

  const recentCases = [
    { id: 1, subject: 'Urgent: Account Verification Required', sender: 'security@paypa1.com', risk: 92, status: 'Phishing', date: '2024-01-15 14:23' },
    { id: 2, subject: 'Your Invoice #INV-2024-001', sender: 'billing@microsoft-support.net', risk: 87, status: 'Phishing', date: '2024-01-15 13:45' },
    { id: 3, subject: 'Password Reset Request', sender: 'noreply@g00gle.com', risk: 95, status: 'High Risk', date: '2024-01-15 12:10' },
    { id: 4, subject: 'Weekly Report', sender: 'reports@company.com', risk: 12, status: 'Safe', date: '2024-01-15 11:30' },
    { id: 5, subject: 'Meeting Invitation', sender: 'calendar@office365-security.com', risk: 78, status: 'Investigating', date: '2024-01-15 10:15' }
  ];

  return (
    <div className="p-6">
      <h1 className="text-3xl font-bold mb-6 text-splunk-accent">Phishing Threat Dashboard</h1>
      
      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
        <div className="bg-splunk-panel p-6 rounded-lg border border-gray-700">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-gray-400 text-sm">Total Analyzed</p>
              <p className="text-3xl font-bold">{stats.totalAnalyzed}</p>
            </div>
            <Mail className="w-12 h-12 text-blue-500" />
          </div>
        </div>
        
        <div className="bg-splunk-panel p-6 rounded-lg border border-gray-700">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-gray-400 text-sm">Phishing Detected</p>
              <p className="text-3xl font-bold text-splunk-danger">{stats.phishingDetected}</p>
            </div>
            <ShieldAlert className="w-12 h-12 text-red-500" />
          </div>
        </div>
        
        <div className="bg-splunk-panel p-6 rounded-lg border border-gray-700">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-gray-400 text-sm">High Risk</p>
              <p className="text-3xl font-bold text-splunk-warning">{stats.highRisk}</p>
            </div>
            <AlertTriangle className="w-12 h-12 text-orange-500" />
          </div>
        </div>
        
        <div className="bg-splunk-panel p-6 rounded-lg border border-gray-700">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-gray-400 text-sm">Safe Emails</p>
              <p className="text-3xl font-bold text-splunk-success">{stats.safeEmails}</p>
            </div>
            <CheckCircle className="w-12 h-12 text-green-500" />
          </div>
        </div>
      </div>

      {/* Recent Cases Table */}
      <div className="bg-splunk-panel rounded-lg border border-gray-700 overflow-hidden">
        <div className="p-4 border-b border-gray-700 flex items-center justify-between">
          <h2 className="text-xl font-semibold flex items-center">
            <Clock className="w-5 h-5 mr-2" />
            Recent Phishing Cases
          </h2>
          <Link to="/phishing" className="text-splunk-accent hover:underline text-sm flex items-center">
            View All <ChevronRight className="w-4 h-4 ml-1" />
          </Link>
        </div>
        <table className="w-full">
          <thead className="bg-gray-800">
            <tr>
              <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Subject</th>
              <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Sender</th>
              <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Risk Score</th>
              <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Status</th>
              <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Date</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-700">
            {recentCases.map((caseItem) => (
              <tr key={caseItem.id} className="hover:bg-gray-800 transition-colors">
                <td className="px-4 py-3 text-sm">{caseItem.subject}</td>
                <td className="px-4 py-3 text-sm text-gray-400 font-mono">{caseItem.sender}</td>
                <td className="px-4 py-3">
                  <span className={`px-2 py-1 rounded text-xs font-bold ${
                    caseItem.risk > 80 ? 'bg-red-900 text-red-300' :
                    caseItem.risk > 50 ? 'bg-orange-900 text-orange-300' :
                    'bg-green-900 text-green-300'
                  }`}>
                    {caseItem.risk}
                  </span>
                </td>
                <td className="px-4 py-3">
                  <span className={`px-2 py-1 rounded text-xs ${
                    caseItem.status === 'Phishing' ? 'bg-red-900 text-red-300' :
                    caseItem.status === 'High Risk' ? 'bg-orange-900 text-orange-300' :
                    caseItem.status === 'Investigating' ? 'bg-yellow-900 text-yellow-300' :
                    'bg-green-900 text-green-300'
                  }`}>
                    {caseItem.status}
                  </span>
                </td>
                <td className="px-4 py-3 text-sm text-gray-400">{caseItem.date}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

// Phishing Analysis Component
function PhishingAnalysis() {
  const [activeTab, setActiveTab] = useState('analyze');
  
  return (
    <div className="h-screen flex flex-col">
      <div className="bg-splunk-panel border-b border-gray-700 px-6 py-4">
        <h1 className="text-2xl font-bold text-splunk-accent flex items-center">
          <Mail className="w-6 h-6 mr-3" />
          Email Phishing Analyzer
        </h1>
      </div>
      
      <div className="flex-1 flex overflow-hidden">
        {/* Sidebar Tabs */}
        <div className="w-64 bg-splunk-panel border-r border-gray-700 p-4">
          <nav className="space-y-2">
            <button
              onClick={() => setActiveTab('analyze')}
              className={`w-full flex items-center px-4 py-3 rounded-lg transition-colors ${
                activeTab === 'analyze' ? 'bg-splunk-accent text-black' : 'text-gray-400 hover:bg-gray-800'
              }`}
            >
              <Upload className="w-5 h-5 mr-3" />
              Email Analyzer
            </button>
            <button
              onClick={() => setActiveTab('results')}
              className={`w-full flex items-center px-4 py-3 rounded-lg transition-colors ${
                activeTab === 'results' ? 'bg-splunk-accent text-black' : 'text-gray-400 hover:bg-gray-800'
              }`}
            >
              <BarChart3 className="w-5 h-5 mr-3" />
              Analysis Results
            </button>
            <button
              onClick={() => setActiveTab('history')}
              className={`w-full flex items-center px-4 py-3 rounded-lg transition-colors ${
                activeTab === 'history' ? 'bg-splunk-accent text-black' : 'text-gray-400 hover:bg-gray-800'
              }`}
            >
              <Clock className="w-5 h-5 mr-3" />
              Case History
            </button>
          </nav>
        </div>
        
        {/* Main Content */}
        <div className="flex-1 overflow-auto p-6">
          {activeTab === 'analyze' && <EmailAnalyzer />}
          {activeTab === 'results' && <AnalysisResults />}
          {activeTab === 'history' && <CaseHistory />}
        </div>
      </div>
    </div>
  );
}

// Email Analyzer Sub-component
function EmailAnalyzer() {
  const [emailText, setEmailText] = useState('');
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [analysisResult, setAnalysisResult] = useState(null);

  const handleAnalyze = async () => {
    if (!emailText.trim()) return;
    
    setIsAnalyzing(true);
    try {
      const response = await axios.post('http://localhost:8000/email-analyze', {
        email_content: emailText
      });
      setAnalysisResult(response.data);
    } catch (error) {
      console.error('Analysis failed:', error);
    } finally {
      setIsAnalyzing(false);
    }
  };

  return (
    <div className="max-w-4xl">
      <h2 className="text-xl font-semibold mb-4 flex items-center">
        <Upload className="w-5 h-5 mr-2" />
        Paste or Upload Email
      </h2>
      
      <div className="bg-splunk-panel rounded-lg border border-gray-700 p-6">
        <textarea
          value={emailText}
          onChange={(e) => setEmailText(e.target.value)}
          placeholder="Paste raw email content here (including headers)..."
          className="w-full h-64 bg-gray-900 border border-gray-700 rounded-lg p-4 font-mono text-sm focus:outline-none focus:border-splunk-accent resize-none"
        />
        
        <div className="mt-4 flex items-center justify-between">
          <div className="flex items-center space-x-4">
            <button className="flex items-center px-4 py-2 bg-gray-800 hover:bg-gray-700 rounded-lg transition-colors">
              <Upload className="w-4 h-4 mr-2" />
              Upload .eml File
            </button>
            <span className="text-gray-500 text-sm">or drag and drop</span>
          </div>
          
          <button
            onClick={handleAnalyze}
            disabled={isAnalyzing || !emailText.trim()}
            className="px-6 py-2 bg-splunk-accent hover:bg-orange-600 disabled:bg-gray-700 disabled:cursor-not-allowed text-black font-semibold rounded-lg transition-colors flex items-center"
          >
            {isAnalyzing ? (
              <>Analyzing...</>
            ) : (
              <>
                <Search className="w-4 h-4 mr-2" />
                Analyze Email
              </>
            )}
          </button>
        </div>
      </div>
      
      {analysisResult && (
        <div className="mt-6 bg-splunk-panel rounded-lg border border-gray-700 p-6">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-lg font-semibold">Analysis Complete</h3>
            <span className={`px-3 py-1 rounded-full text-sm font-bold ${
              analysisResult.risk_score > 80 ? 'bg-red-900 text-red-300' :
              analysisResult.risk_score > 50 ? 'bg-orange-900 text-orange-300' :
              'bg-green-900 text-green-300'
            }`}>
              Risk Score: {analysisResult.risk_score}/100
            </span>
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <p className="text-gray-400 text-sm">Threat Level</p>
              <p className="text-xl font-bold">{analysisResult.threat_level}</p>
            </div>
            <div>
              <p className="text-gray-400 text-sm">Recommendation</p>
              <p className="text-xl font-bold text-splunk-accent">{analysisResult.recommendation}</p>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// Analysis Results Sub-component
function AnalysisResults() {
  const [subTab, setSubTab] = useState('overview');
  
  const mockData = {
    overview: {
      riskScore: 87,
      threatLevel: 'High',
      summary: 'This email exhibits multiple phishing indicators including suspicious sender domain, mismatched reply-to address, and urgent language designed to create panic.'
    },
    headers: {
      spf: 'FAIL',
      dkim: 'FAIL',
      dmarc: 'FAIL',
      from: 'security@paypa1.com',
      replyTo: 'attacker@malicious-domain.com',
      returnPath: 'bounce@suspicious-server.net'
    },
    urls: [
      { url: 'http://paypa1.com/verify', risk: 'High', category: 'Credential Harvesting' },
      { url: 'http://bit.ly/3xYz123', risk: 'Medium', category: 'URL Shortener' }
    ],
    threatIntel: {
      virustotal: { detections: 12, total: 89, score: 'Malicious' },
      whois: { age: '3 days', registrar: 'NameCheap', country: 'PA' },
      abuseipdb: { reports: 47, confidence: 95 }
    }
  };

  return (
    <div>
      <h2 className="text-xl font-semibold mb-4 flex items-center">
        <BarChart3 className="w-5 h-5 mr-2" />
        Detailed Analysis Results
      </h2>
      
      {/* Sub-tabs */}
      <div className="flex space-x-2 mb-6 border-b border-gray-700">
        {['overview', 'headers', 'urls', 'threat-intel', 'ai-analysis'].map((tab) => (
          <button
            key={tab}
            onClick={() => setSubTab(tab)}
            className={`px-4 py-2 rounded-t-lg transition-colors ${
              subTab === tab ? 'bg-splunk-panel border-t border-l border-r border-gray-700 text-splunk-accent' : 'text-gray-400 hover:text-white'
            }`}
          >
            {tab.split('-').map(word => word.charAt(0).toUpperCase() + word.slice(1)).join(' ')}
          </button>
        ))}
      </div>
      
      {/* Content */}
      <div className="bg-splunk-panel rounded-lg border border-gray-700 p-6">
        {subTab === 'overview' && (
          <div>
            <div className="flex items-center justify-between mb-6">
              <div>
                <p className="text-gray-400">Overall Risk Score</p>
                <p className="text-5xl font-bold text-splunk-danger">{mockData.overview.riskScore}/100</p>
              </div>
              <div className="text-right">
                <p className="text-gray-400">Threat Level</p>
                <p className="text-2xl font-bold text-red-500">{mockData.overview.threatLevel}</p>
              </div>
            </div>
            <div className="bg-gray-900 rounded-lg p-4">
              <h3 className="font-semibold mb-2">AI Summary</h3>
              <p className="text-gray-300">{mockData.overview.summary}</p>
            </div>
          </div>
        )}
        
        {subTab === 'headers' && (
          <div className="space-y-4">
            <h3 className="font-semibold text-lg">Authentication Results</h3>
            <div className="grid grid-cols-3 gap-4">
              <div className="bg-gray-900 rounded-lg p-4">
                <p className="text-gray-400 text-sm">SPF</p>
                <p className={`text-xl font-bold ${mockData.headers.spf === 'FAIL' ? 'text-red-500' : 'text-green-500'}`}>
                  {mockData.headers.spf}
                </p>
              </div>
              <div className="bg-gray-900 rounded-lg p-4">
                <p className="text-gray-400 text-sm">DKIM</p>
                <p className={`text-xl font-bold ${mockData.headers.dkim === 'FAIL' ? 'text-red-500' : 'text-green-500'}`}>
                  {mockData.headers.dkim}
                </p>
              </div>
              <div className="bg-gray-900 rounded-lg p-4">
                <p className="text-gray-400 text-sm">DMARC</p>
                <p className={`text-xl font-bold ${mockData.headers.dmarc === 'FAIL' ? 'text-red-500' : 'text-green-500'}`}>
                  {mockData.headers.dmarc}
                </p>
              </div>
            </div>
            
            <h3 className="font-semibold text-lg mt-6">Header Analysis</h3>
            <div className="space-y-3">
              <div className="flex justify-between py-2 border-b border-gray-700">
                <span className="text-gray-400">From:</span>
                <span className="font-mono text-red-400">{mockData.headers.from}</span>
              </div>
              <div className="flex justify-between py-2 border-b border-gray-700">
                <span className="text-gray-400">Reply-To:</span>
                <span className="font-mono text-red-400">{mockData.headers.replyTo}</span>
              </div>
              <div className="flex justify-between py-2 border-b border-gray-700">
                <span className="text-gray-400">Return-Path:</span>
                <span className="font-mono text-orange-400">{mockData.headers.returnPath}</span>
              </div>
            </div>
          </div>
        )}
        
        {subTab === 'urls' && (
          <div>
            <h3 className="font-semibold text-lg mb-4">Extracted URLs</h3>
            <div className="space-y-3">
              {mockData.urls.map((url, idx) => (
                <div key={idx} className="bg-gray-900 rounded-lg p-4 flex items-center justify-between">
                  <div className="flex-1">
                    <p className="font-mono text-sm break-all">{url.url}</p>
                    <p className="text-gray-400 text-xs mt-1">{url.category}</p>
                  </div>
                  <span className={`px-3 py-1 rounded text-xs font-bold ${
                    url.risk === 'High' ? 'bg-red-900 text-red-300' : 'bg-orange-900 text-orange-300'
                  }`}>
                    {url.risk} Risk
                  </span>
                </div>
              ))}
            </div>
          </div>
        )}
        
        {subTab === 'threat-intel' && (
          <div className="space-y-6">
            <div className="bg-gray-900 rounded-lg p-4">
              <div className="flex items-center justify-between mb-3">
                <h3 className="font-semibold flex items-center">
                  <ExternalLink className="w-4 h-4 mr-2" />
                  VirusTotal
                </h3>
                <span className="text-red-400 font-bold">{mockData.threatIntel.virustotal.score}</span>
              </div>
              <p className="text-gray-300">{mockData.threatIntel.virustotal.detections}/{mockData.threatIntel.virustotal.total} engines detected malware</p>
            </div>
            
            <div className="bg-gray-900 rounded-lg p-4">
              <div className="flex items-center justify-between mb-3">
                <h3 className="font-semibold flex items-center">
                  <Globe className="w-4 h-4 mr-2" />
                  WHOIS Information
                </h3>
                <span className="text-orange-400 font-bold">New Domain</span>
              </div>
              <div className="grid grid-cols-3 gap-4 text-sm">
                <div>
                  <p className="text-gray-400">Age</p>
                  <p className="font-semibold">{mockData.threatIntel.whois.age}</p>
                </div>
                <div>
                  <p className="text-gray-400">Registrar</p>
                  <p className="font-semibold">{mockData.threatIntel.whois.registrar}</p>
                </div>
                <div>
                  <p className="text-gray-400">Country</p>
                  <p className="font-semibold">{mockData.threatIntel.whois.country}</p>
                </div>
              </div>
            </div>
            
            <div className="bg-gray-900 rounded-lg p-4">
              <div className="flex items-center justify-between mb-3">
                <h3 className="font-semibold">AbuseIPDB</h3>
                <span className="text-red-400 font-bold">{mockData.threatIntel.abuseipdb.confidence}% Confidence</span>
              </div>
              <p className="text-gray-300">{mockData.threatIntel.abuseipdb.reports} user reports of malicious activity</p>
            </div>
          </div>
        )}
        
        {subTab === 'ai-analysis' && (
          <div className="bg-gray-900 rounded-lg p-6">
            <h3 className="font-semibold text-lg mb-4 flex items-center">
              <Eye className="w-5 h-5 mr-2" />
              AI-Powered Analysis
            </h3>
            <div className="prose prose-invert max-w-none">
              <p className="text-gray-300 leading-relaxed">
                Based on comprehensive analysis, this email demonstrates classic phishing characteristics:
              </p>
              <ul className="list-disc list-inside space-y-2 text-gray-300 mt-4">
                <li><strong>Spoofed Sender:</strong> Domain "paypa1.com" mimics legitimate PayPal domain with character substitution</li>
                <li><strong>Authentication Failures:</strong> SPF, DKIM, and DMARC all failed validation</li>
                <li><strong>Reply-To Mismatch:</strong> Reply-to address points to unrelated malicious domain</li>
                <li><strong>Urgency Tactics:</strong> Language designed to create panic and immediate action</li>
                <li><strong>Suspicious Links:</strong> URLs lead to known credential harvesting sites</li>
                <li><strong>Recent Domain Registration:</strong> Domain registered only 3 days ago</li>
              </ul>
              <div className="mt-6 p-4 bg-red-900/30 border border-red-700 rounded-lg">
                <p className="font-bold text-red-300">Recommendation: BLOCK AND DELETE</p>
                <p className="text-sm text-red-200 mt-1">Do not click any links. Report to security team immediately.</p>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

// Case History Sub-component
function CaseHistory() {
  const cases = [
    { id: 1, subject: 'Urgent: Account Verification Required', sender: 'security@paypa1.com', risk: 92, status: 'Phishing', date: '2024-01-15 14:23' },
    { id: 2, subject: 'Your Invoice #INV-2024-001', sender: 'billing@microsoft-support.net', risk: 87, status: 'Phishing', date: '2024-01-15 13:45' },
    { id: 3, subject: 'Password Reset Request', sender: 'noreply@g00gle.com', risk: 95, status: 'High Risk', date: '2024-01-15 12:10' },
    { id: 4, subject: 'Weekly Report', sender: 'reports@company.com', risk: 12, status: 'Safe', date: '2024-01-15 11:30' },
    { id: 5, subject: 'Meeting Invitation', sender: 'calendar@office365-security.com', risk: 78, status: 'Investigating', date: '2024-01-15 10:15' }
  ];

  return (
    <div>
      <h2 className="text-xl font-semibold mb-4 flex items-center">
        <Clock className="w-5 h-5 mr-2" />
        Case History
      </h2>
      
      <div className="bg-splunk-panel rounded-lg border border-gray-700 overflow-hidden">
        <div className="p-4 border-b border-gray-700 flex items-center justify-between">
          <div className="flex items-center space-x-4">
            <input
              type="text"
              placeholder="Search cases..."
              className="bg-gray-900 border border-gray-700 rounded-lg px-4 py-2 text-sm focus:outline-none focus:border-splunk-accent"
            />
            <select className="bg-gray-900 border border-gray-700 rounded-lg px-4 py-2 text-sm focus:outline-none focus:border-splunk-accent">
              <option>All Statuses</option>
              <option>Phishing</option>
              <option>Safe</option>
              <option>Investigating</option>
            </select>
          </div>
          <button className="flex items-center px-4 py-2 bg-splunk-accent hover:bg-orange-600 text-black rounded-lg transition-colors text-sm font-semibold">
            <FileText className="w-4 h-4 mr-2" />
            Export Report
          </button>
        </div>
        
        <table className="w-full">
          <thead className="bg-gray-800">
            <tr>
              <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">ID</th>
              <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Subject</th>
              <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Sender</th>
              <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Risk</th>
              <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Status</th>
              <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Date</th>
              <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-700">
            {cases.map((caseItem) => (
              <tr key={caseItem.id} className="hover:bg-gray-800 transition-colors">
                <td className="px-4 py-3 text-sm text-gray-400">#{caseItem.id}</td>
                <td className="px-4 py-3 text-sm">{caseItem.subject}</td>
                <td className="px-4 py-3 text-sm text-gray-400 font-mono">{caseItem.sender}</td>
                <td className="px-4 py-3">
                  <span className={`px-2 py-1 rounded text-xs font-bold ${
                    caseItem.risk > 80 ? 'bg-red-900 text-red-300' :
                    caseItem.risk > 50 ? 'bg-orange-900 text-orange-300' :
                    'bg-green-900 text-green-300'
                  }`}>
                    {caseItem.risk}
                  </span>
                </td>
                <td className="px-4 py-3">
                  <span className={`px-2 py-1 rounded text-xs ${
                    caseItem.status === 'Phishing' ? 'bg-red-900 text-red-300' :
                    caseItem.status === 'High Risk' ? 'bg-orange-900 text-orange-300' :
                    caseItem.status === 'Investigating' ? 'bg-yellow-900 text-yellow-300' :
                    'bg-green-900 text-green-300'
                  }`}>
                    {caseItem.status}
                  </span>
                </td>
                <td className="px-4 py-3 text-sm text-gray-400">{caseItem.date}</td>
                <td className="px-4 py-3">
                  <button className="text-splunk-accent hover:text-orange-400 text-sm flex items-center">
                    <Eye className="w-4 h-4 mr-1" />
                    View
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

// Main App Component
function App() {
  return (
    <Router>
      <div className="min-h-screen bg-splunk-dark">
        {/* Top Navigation */}
        <nav className="bg-splunk-panel border-b border-gray-700 px-6 py-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-8">
              <h1 className="text-xl font-bold text-splunk-accent flex items-center">
                <ShieldAlert className="w-6 h-6 mr-2" />
                PhishingSOC
              </h1>
              <div className="flex space-x-1">
                <Link to="/" className="flex items-center px-4 py-2 rounded-lg hover:bg-gray-800 transition-colors">
                  <LayoutDashboard className="w-4 h-4 mr-2" />
                  Dashboard
                </Link>
                <Link to="/phishing" className="flex items-center px-4 py-2 rounded-lg hover:bg-gray-800 transition-colors">
                  <Mail className="w-4 h-4 mr-2" />
                  Phishing Analysis
                </Link>
              </div>
            </div>
            
            <div className="flex items-center space-x-4">
              <div className="relative">
                <Search className="w-4 h-4 absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400" />
                <input
                  type="text"
                  placeholder="Search logs, emails, IOCs..."
                  className="bg-gray-900 border border-gray-700 rounded-lg pl-10 pr-4 py-2 text-sm focus:outline-none focus:border-splunk-accent w-80"
                />
              </div>
              <div className="w-8 h-8 bg-splunk-accent rounded-full flex items-center justify-center text-black font-bold">
                A
              </div>
            </div>
          </div>
        </nav>
        
        {/* Main Content */}
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/phishing" element={<PhishingAnalysis />} />
        </Routes>
      </div>
    </Router>
  );
}

export default App;
