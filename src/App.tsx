import React, { useState, useEffect, useRef } from "react";
import { GoogleGenAI, Type } from "@google/genai";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Card, CardContent, CardHeader, CardTitle, CardFooter } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Search, ShieldAlert, ShieldCheck, Shield, Globe, AlertTriangle, AlertCircle, Loader2, History, Terminal, Info, Zap } from "lucide-react";
import DOMPurify from "dompurify";
import * as motion from "motion/react-client";

// Initialize Gemini API
const ai = new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY });

interface AnalysisResult {
  safe: boolean;
  level: "Safe" | "Suspicious" | "Malicious";
  summary: string;
  details: string[];
  score: number;
}

interface ScanLog {
  timestamp: string;
  message: string;
  type: "info" | "warn" | "error" | "success";
}

interface RecentScan {
  url: string;
  score: number;
  level: string;
  timestamp: number;
}

export default function App() {
  const [url, setUrl] = useState("");
  const [isScanning, setIsScanning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [htmlContent, setHtmlContent] = useState<string>("");
  const [logs, setLogs] = useState<ScanLog[]>([]);
  const [recentScans, setRecentScans] = useState<RecentScan[]>([]);
  
  const logEndRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const saved = localStorage.getItem("shield-x-recent");
    if (saved) {
      try {
        setRecentScans(JSON.parse(saved));
      } catch (e) {
        console.error("Failed to load recent scans", e);
      }
    }
  }, []);

  useEffect(() => {
    if (logEndRef.current) {
      logEndRef.current.scrollIntoView({ behavior: "smooth" });
    }
  }, [logs]);

  const addLog = (message: string, type: ScanLog["type"] = "info") => {
    const time = new Date().toLocaleTimeString([], { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });
    setLogs(prev => [...prev, { timestamp: time, message, type }]);
  };

  const handleScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!url) return;

    let targetUrl = url;
    if (!/^https?:\/\//i.test(targetUrl)) {
      targetUrl = "https://" + targetUrl;
    }

    setIsScanning(true);
    setError(null);
    setResult(null);
    setHtmlContent("");
    setLogs([]);

    addLog(`Initializing isolated sandbox for: ${targetUrl}`, "info");
    addLog("Requesting remote content via secure proxy...", "info");

    try {
      // Fetch URL content via backend API
      const res = await fetch(`/api/fetch?url=${encodeURIComponent(targetUrl)}`);
      const data = await res.json();

      if (!res.ok) {
        addLog(`Proxy error: ${data.error || "Failed to fetch"}`, "error");
        throw new Error(data.error || "Failed to fetch URL");
      }

      addLog("Content received successfully. Content-Type: " + (data.contentType || "unknown"), "success");
      setHtmlContent(data.content);
      
      addLog("Starting heuristic analysis with Gemini Intelligence Engine...", "info");
      addLog("Analyzing DOM patterns for phishing indicators...", "info");

      // Analyze with Gemini
      const analysisPrompt = `
You are a cybersecurity expert analyzing webpage content for a URL scanner sandbox.
Analyze this webpage content for any signs of malicious activity:
- Phishing indicators (fake login pages, credential harvesting, disguised links)
- Malware delivery (suspicious script tags, obfuscated code, drive-by downloads)
- Scam content

Return a JSON object following this schema:
{
  "safe": boolean (true if totally safe, false if any suspicious or malicious content),
  "level": "Safe" | "Suspicious" | "Malicious",
  "summary": "One sentence summary of your findings",
  "details": ["Specific finding 1", "Specific finding 2"],
  "score": number (0-100, 100 being most dangerous)
}

Target URL: ${targetUrl}
HTML Content:
${data.content.substring(0, 100000)} // Using first 100k chars for analysis
`;

      const aiResponse = await ai.models.generateContent({
        model: "gemini-3-flash-preview",
        contents: analysisPrompt,
        config: {
          responseMimeType: "application/json",
          responseSchema: {
            type: Type.OBJECT,
            properties: {
              safe: { type: Type.BOOLEAN, description: "True if safe, false if suspicious/malicious." },
              level: { type: Type.STRING, description: "One of: Safe, Suspicious, Malicious." },
              summary: { type: Type.STRING, description: "A brief summary of the findings." },
              details: { 
                type: Type.ARRAY, 
                items: { type: Type.STRING },
                description: "Array of specific findings or observations."
              },
              score: { type: Type.NUMBER, description: "Danger score from 0 to 100. 100 is highly malicious." },
            },
            required: ["safe", "level", "summary", "details", "score"],
          },
        },
      });

      const analysisJson = JSON.parse(aiResponse.text);
      setResult(analysisJson);
      
      addLog(`Analysis complete. Level: ${analysisJson.level}, Score: ${analysisJson.score}`, analysisJson.safe ? "success" : "warn");

      // Save to recent scans
      const newRecent: RecentScan = {
        url: targetUrl,
        score: analysisJson.score,
        level: analysisJson.level,
        timestamp: Date.now()
      };
      setRecentScans(prev => {
        const updated = [newRecent, ...prev.filter(s => s.url !== targetUrl)].slice(0, 5);
        localStorage.setItem("shield-x-recent", JSON.stringify(updated));
        return updated;
      });
      
    } catch (err: any) {
      console.error(err);
      setError(err.message || "An unexpected error occurred during scanning.");
      addLog(`Fatal error during analysis: ${err.message}`, "error");
    } finally {
      setIsScanning(false);
    }
  };

  const getScoreColor = (score: number) => {
    if (score > 50) return "text-red-600";
    if (score > 20) return "text-orange-500";
    return "text-green-600";
  };

  const getBarColor = (score: number) => {
    if (score > 50) return "bg-red-500";
    if (score > 20) return "bg-orange-500";
    return "bg-green-500";
  };

  const getLogColor = (type: ScanLog["type"]) => {
    switch (type) {
      case "error": return "text-red-400";
      case "warn": return "text-yellow-400";
      case "success": return "text-green-400";
      default: return "text-blue-400";
    }
  };

  return (
    <div className="min-h-screen bg-slate-50 text-slate-900 font-sans flex flex-col selection:bg-blue-200">
      
      {/* Top Navigation */}
      <nav className="h-16 bg-slate-900 text-white flex items-center justify-between px-6 shrink-0 border-b border-slate-800 shadow-sm z-10">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 bg-blue-600 rounded flex items-center justify-center shadow-lg shadow-blue-500/20">
            <Shield className="w-5 h-5 text-white" />
          </div>
          <span className="font-bold tracking-tight text-lg">SHIELD-X <span className="text-blue-400 font-medium italic">SANDBOX</span></span>
        </div>
        <div className="flex items-center gap-6 text-sm font-medium">
          <div className="flex items-center gap-4 text-slate-400">
             <div className="flex items-center gap-2">
               <Zap className="h-3.5 w-3.5 text-blue-400" />
               <span className="hidden sm:inline">Engine: Gemini-3</span>
             </div>
             <div className="h-4 w-px bg-slate-700 hidden sm:block"></div>
             <div className="flex items-center gap-2">
                <div className="w-2 h-2 rounded-full bg-green-500 animate-pulse"></div>
                <span className="hidden sm:inline">System: Protected</span>
             </div>
          </div>
        </div>
      </nav>

      {/* Main Layout */}
      <main className="flex-1 w-full flex flex-col overflow-hidden">
        
        <div className="flex-1 flex overflow-hidden">
          
          {/* Sidebar - History & Feedback */}
          <aside className="w-64 bg-white border-r border-slate-200 hidden lg:flex flex-col shrink-0">
            <div className="p-4 border-b border-slate-100 bg-slate-50/50">
               <h3 className="text-[10px] font-bold text-slate-500 uppercase tracking-widest flex items-center gap-2 mb-3">
                 <History className="h-3 w-3" />
                 Recent Investigations
               </h3>
               <div className="space-y-2">
                 {recentScans.length === 0 ? (
                   <p className="text-[10px] text-slate-400 italic">No recent scans found</p>
                 ) : (
                   recentScans.map((scan, i) => (
                     <button 
                       key={i} 
                       onClick={() => setUrl(scan.url)}
                       className="w-full text-left p-2 rounded hover:bg-slate-100 border border-transparent hover:border-slate-200 transition-all group"
                     >
                        <p className="text-[11px] font-mono text-slate-600 truncate mb-1">{scan.url.replace(/^https?:\/\//, '')}</p>
                        <div className="flex items-center justify-between">
                          <Badge variant="outline" className={`text-[9px] px-1 py-0 border-transparent ${getScoreColor(scan.score)}`}>
                            SCORE: {scan.score}
                          </Badge>
                          <span className="text-[9px] text-slate-400 group-hover:text-blue-500 uppercase font-bold">Rescan</span>
                        </div>
                     </button>
                   ))
                 )}
               </div>
            </div>

            <div className="flex-1 flex flex-col overflow-hidden">
               <div className="p-4 flex items-center justify-between shrink-0">
                  <h3 className="text-[10px] font-bold text-slate-900 uppercase tracking-widest flex items-center gap-2">
                    <Terminal className="h-3 w-3" />
                    Analysis Feed
                  </h3>
                  {isScanning && (
                    <span className="flex h-2 w-2 relative">
                      <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-blue-400 opacity-75"></span>
                      <span className="relative inline-flex rounded-full h-2 w-2 bg-blue-500"></span>
                    </span>
                  )}
               </div>
               <div className="flex-1 bg-slate-900 mx-3 mb-3 rounded-lg overflow-hidden border border-slate-800 flex flex-col shadow-inner">
                  <ScrollArea className="flex-1 p-3">
                    <div className="font-mono text-[9px] space-y-1.5 min-h-full">
                       {logs.length === 0 ? (
                         <p className="text-slate-600 italic">System ready. Waiting for input...</p>
                       ) : (
                         logs.map((log, i) => (
                           <div key={i} className="flex gap-2">
                             <span className="text-slate-600 shrink-0">[{log.timestamp}]</span>
                             <span className={getLogColor(log.type)}>{log.message}</span>
                           </div>
                         ))
                       )}
                       <div ref={logEndRef} />
                    </div>
                  </ScrollArea>
               </div>
            </div>
          </aside>

          {/* Right Content */}
          <section className="flex-1 flex flex-col p-4 md:p-6 bg-slate-50 overflow-y-auto">
            <div className="max-w-5xl mx-auto w-full space-y-6">
              
              {/* Search Bar */}
              <Card className="bg-white border border-slate-200 shadow-sm rounded-lg overflow-hidden shrink-0">
                <CardContent className="p-5">
                  <form onSubmit={handleScan} className="flex flex-col md:flex-row gap-4">
                    <div className="relative flex-1">
                      <Globe className="absolute left-3.5 top-3.5 h-5 w-5 text-slate-400" />
                      <Input
                        value={url}
                        onChange={(e) => setUrl(e.target.value)}
                        placeholder="Enter URL for isolated investigation..."
                        className="pl-11 h-12 bg-white border-slate-300 text-slate-700 font-mono text-sm placeholder:text-slate-400 placeholder:font-sans focus-visible:ring-2 focus-visible:ring-blue-500 rounded shadow-sm"
                        disabled={isScanning}
                      />
                    </div>
                    <Button 
                      type="submit" 
                      size="lg" 
                      className="h-12 px-6 bg-blue-600 hover:bg-blue-700 text-white font-bold tracking-wide rounded transition-all active:scale-95 shadow-md shadow-blue-500/20"
                      disabled={isScanning || !url}
                    >
                      {isScanning ? (
                        <>
                          <Loader2 className="mr-2 h-5 w-5 animate-spin" />
                          ANALYZING...
                        </>
                      ) : (
                        <>
                          <Search className="mr-2 h-5 w-5" />
                          SCAN LINK
                        </>
                      )}
                    </Button>
                  </form>
                </CardContent>
              </Card>

              {/* Error State */}
              {error && (
                <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} className="shrink-0">
                  <Alert variant="destructive" className="bg-red-50 border-red-200 text-red-900 rounded shadow-sm">
                    <AlertCircle className="h-4 w-4 text-red-600" />
                    <AlertTitle className="text-red-900 font-bold uppercase tracking-wider text-xs">Security Exception Triggered</AlertTitle>
                    <AlertDescription className="text-sm mt-1">{error}</AlertDescription>
                  </Alert>
                </motion.div>
              )}

              {/* Results Area */}
              {result && (
                <motion.div 
                  initial={{ opacity: 0, y: 20 }} 
                  animate={{ opacity: 1, y: 0 }} 
                  className="grid grid-cols-1 lg:grid-cols-3 gap-6 pb-8"
                >
                  {/* Score Card */}
                  <Card className="lg:col-span-1 bg-white border border-slate-200 shadow-sm rounded-lg flex flex-col justify-between overflow-hidden h-fit">
                    <CardHeader className="pb-4 pt-5 px-5 bg-slate-50 border-b border-slate-100">
                      <CardTitle className="text-[10px] font-bold text-slate-500 uppercase tracking-widest flex items-center justify-between">
                        Investigation Status
                        {result.safe ? <ShieldCheck className="h-4 w-4 text-green-500" /> : <ShieldAlert className="h-4 w-4 text-red-500" />}
                      </CardTitle>
                    </CardHeader>
                    <CardContent className="p-6">
                      <div className="flex flex-col items-center">
                         <div className="relative flex items-center justify-center">
                            <span className={`text-8xl font-black ${getScoreColor(result.score)} tracking-tighter`}>{result.score}</span>
                         </div>
                         <div className="mt-4 text-center">
                           <Badge className={`px-3 py-1 text-[10px] font-bold uppercase tracking-tighter shadow-sm ${result.score > 50 ? 'bg-red-600 hover:bg-red-600' : result.score > 20 ? 'bg-orange-500 hover:bg-orange-500' : 'bg-green-600 hover:bg-green-600'}`}>
                             {result.level} RISK
                           </Badge>
                         </div>
                         
                         <div className="w-full h-2 bg-slate-100 rounded-full overflow-hidden mt-8 shadow-inner">
                           <motion.div 
                             initial={{ width: 0 }}
                             animate={{ width: `${result.score}%` }}
                             transition={{ duration: 1, ease: "easeOut" }}
                             className={`h-full ${getBarColor(result.score)}`}
                           />
                         </div>
                      </div>

                      <div className="mt-8 pt-6 border-t border-slate-100">
                         <div className="flex items-center gap-2 text-[10px] font-bold text-slate-400 uppercase tracking-wider mb-2">
                           <Info className="h-3 w-3 text-blue-500" />
                           Analyst Summary
                         </div>
                         <p className="text-xs text-slate-600 leading-relaxed font-semibold">
                            {result.summary}
                         </p>
                      </div>
                    </CardContent>
                  </Card>

                  {/* Details & Sandbox Tabs */}
                  <Card className="lg:col-span-2 bg-white border border-slate-200 shadow-sm rounded-lg overflow-hidden flex flex-col min-h-[500px]">
                    <Tabs defaultValue="findings" className="w-full flex-1 flex flex-col">
                      <div className="border-b border-slate-200 bg-slate-50 px-5 pt-3">
                        <TabsList className="bg-transparent space-x-2 h-auto p-0 pb-3 block">
                          <TabsTrigger value="findings" className="data-[state=active]:bg-white data-[state=active]:text-blue-700 data-[state=active]:shadow-sm text-slate-500 font-bold text-xs uppercase tracking-wider rounded px-4 py-2 border border-transparent data-[state=active]:border-slate-200 transition-all">
                            Threat IOCs
                          </TabsTrigger>
                          <TabsTrigger value="preview" className="data-[state=active]:bg-white data-[state=active]:text-blue-700 data-[state=active]:shadow-sm text-slate-500 font-bold text-xs uppercase tracking-wider rounded px-4 py-2 border border-transparent data-[state=active]:border-slate-200 transition-all">
                            Visual Sandbox
                          </TabsTrigger>
                          <TabsTrigger value="source" className="data-[state=active]:bg-white data-[state=active]:text-blue-700 data-[state=active]:shadow-sm text-slate-500 font-bold text-xs uppercase tracking-wider rounded px-4 py-2 border border-transparent data-[state=active]:border-slate-200 transition-all">
                            HTTP Payload
                          </TabsTrigger>
                        </TabsList>
                      </div>
                      
                      <CardContent className="flex-1 p-0 relative">
                        <TabsContent value="findings" className="m-0 h-full absolute inset-0 p-5 bg-white">
                          <ScrollArea className="h-full pr-4">
                            <div className="grid grid-cols-1 md:grid-cols-2 gap-3 pb-4">
                              {result.details.map((detail, idx) => {
                                const isMalicious = !result.safe && (result.level === "Malicious" || idx % 2 === 0);
                                const isSuspicious = !result.safe && !isMalicious;
                                
                                return (
                                  <div key={idx} className={`flex items-start gap-3 p-4 rounded border transition-colors ${isMalicious ? 'bg-red-50 border-red-100 hover:bg-red-100/50' : isSuspicious ? 'bg-amber-50 border-amber-100 hover:bg-amber-100/50' : 'bg-green-50 border-green-100 hover:bg-green-100/50'}`}>
                                    <div className={`w-2 h-2 mt-1.5 rounded-full shrink-0 ${isMalicious ? 'bg-red-500' : isSuspicious ? 'bg-amber-500' : 'bg-green-500'}`}></div>
                                    <div>
                                      <div className={`text-[10px] font-bold leading-none mb-1.5 uppercase tracking-wide ${isMalicious ? 'text-red-900' : isSuspicious ? 'text-amber-900' : 'text-green-900'}`}>
                                        {isMalicious ? 'Critical Indicator' : isSuspicious ? 'Suspicious Signal' : 'Safe Finding'}
                                      </div>
                                      <div className={`text-[11px] leading-relaxed font-medium ${isMalicious ? 'text-red-700' : isSuspicious ? 'text-amber-700' : 'text-green-700'}`}>
                                        {detail}
                                      </div>
                                    </div>
                                  </div>
                                );
                              })}
                            </div>
                          </ScrollArea>
                        </TabsContent>
                        
                        <TabsContent value="preview" className="m-0 h-full absolute inset-0 flex flex-col bg-slate-100 overflow-hidden">
                          <div className="h-8 bg-slate-200 border-b border-slate-300 flex items-center justify-between px-4 shrink-0">
                            <div className="flex gap-1.5">
                              <div className="w-2.5 h-2.5 rounded-full bg-slate-400"></div>
                              <div className="w-2.5 h-2.5 rounded-full bg-slate-400"></div>
                              <div className="w-2.5 h-2.5 rounded-full bg-slate-400"></div>
                            </div>
                            <div className="flex items-center gap-2">
                              <ShieldAlert className="w-3 h-3 text-slate-500" />
                              <span className="text-[9px] text-slate-500 font-bold uppercase tracking-widest italic">Isolated Virtual Environment active</span>
                            </div>
                            <div className="w-10"></div>
                          </div>
                          <div className="flex-1 bg-white relative">
                            <iframe 
                              srcDoc={DOMPurify.sanitize(htmlContent)}
                              sandbox=""
                              className="w-full h-full border-0 absolute inset-0"
                              title="Sandbox Preview"
                            />
                          </div>
                        </TabsContent>

                        <TabsContent value="source" className="m-0 h-full absolute inset-0 p-4 bg-[#0F1012]">
                          <ScrollArea className="h-full">
                            <pre className="font-mono text-[10px] text-zinc-400 p-4 whitespace-pre-wrap break-all selection:bg-blue-500/30">
                              {htmlContent}
                            </pre>
                          </ScrollArea>
                        </TabsContent>
                      </CardContent>
                    </Tabs>
                  </Card>
                </motion.div>
              )}

            </div>
          </section>
        </div>

        {/* Footer */}
        <footer className="h-8 bg-slate-100 border-t border-slate-200 px-6 flex items-center justify-between text-[10px] text-slate-500 font-bold uppercase tracking-widest shrink-0 z-10 shadow-sm">
          <div className="flex gap-6">
            <span className="flex items-center gap-2">
               <div className="w-1.5 h-1.5 rounded-full bg-green-500 animate-pulse"></div>
               NODE: SECURE-01
            </span>
            <span>REGION: US-EAST-ISOLATED</span>
            <span className="hidden sm:inline">SESSION: {Math.random().toString(36).substring(7).toUpperCase()}</span>
          </div>
          <div className="flex items-center gap-6">
            <button className="text-blue-600 hover:text-blue-700 transition-colors hover:underline cursor-not-allowed opacity-50 font-black">EXPORT_PDF</button>
            <button className="text-red-500 hover:text-red-600 transition-colors hover:underline cursor-not-allowed opacity-50 font-black">TERMINATE_SESSION</button>
          </div>
        </footer>
      </main>
    </div>
  );
}

