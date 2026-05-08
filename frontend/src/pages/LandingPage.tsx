import React from 'react';
import { useNavigate } from 'react-router-dom';
import { ArrowRight, Binary, Cpu, Network } from 'lucide-react';

export function LandingPage() {
  const navigate = useNavigate();

  return (
    <div className="flex-grow flex flex-col items-center justify-center p-8 bg-gray-950 relative overflow-hidden">
      
      {/* Background Glow Effect */}
      <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[800px] h-[800px] bg-cyan-900/10 rounded-full blur-[120px] pointer-events-none"></div>

      <div className="max-w-4xl w-full z-10 text-center space-y-8 mt-12">
        <h1 className="text-5xl md:text-7xl font-bold tracking-tight text-white drop-shadow-lg">
          Autonomous Semantic <span className="text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 to-blue-600">Provenance.</span>
        </h1>
        
        <p className="text-xl md:text-2xl text-gray-400 leading-relaxed max-w-3xl mx-auto">
          Trace the arsonist's fingerprints. OriginTrace is the technical forensic engine that maps binary heuristics to software supply chain origins in real-time.
        </p>

        <div className="pt-8">
          <button 
            onClick={() => navigate('/app')}
            className="group relative inline-flex items-center justify-center px-8 py-4 text-base font-bold text-white transition-all duration-200 bg-cyan-600 font-mono tracking-widest uppercase rounded-md hover:bg-cyan-500 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-cyan-600 focus:ring-offset-gray-950"
          >
            Launch Platform
            <ArrowRight className="w-5 h-5 ml-3 group-hover:translate-x-1 transition-transform" />
            
            {/* Outer Glow */}
            <div className="absolute inset-0 h-full w-full rounded-md group-hover:shadow-[0_0_20px_rgba(0,229,255,0.4)] transition-shadow pointer-events-none"></div>
          </button>
        </div>
      </div>

      {/* Feature Grid */}
      <div className="max-w-6xl w-full mt-32 z-10 grid grid-cols-1 md:grid-cols-3 gap-8 pb-24">
        
        {/* Card 1 */}
        <div className="bg-gray-900/50 border border-gray-800 p-8 rounded-xl hover:border-gray-600 hover:bg-gray-900 transition-all">
          <div className="w-12 h-12 bg-gray-950 border border-gray-800 rounded-lg flex items-center justify-center mb-6">
            <Binary className="w-6 h-6 text-cyan-400" />
          </div>
          <h3 className="text-lg font-bold text-white mb-3 tracking-wide">Static Binary Analysis</h3>
          <p className="text-sm text-gray-400 leading-relaxed">
            Deep inspection of PE/ELF headers, import tables, and entropy characteristics without detonation.
          </p>
        </div>

        {/* Card 2 */}
        <div className="bg-gray-900/50 border border-gray-800 p-8 rounded-xl hover:border-gray-600 hover:bg-gray-900 transition-all">
          <div className="w-12 h-12 bg-gray-950 border border-gray-800 rounded-lg flex items-center justify-center mb-6">
            <Cpu className="w-6 h-6 text-cyan-400" />
          </div>
          <h3 className="text-lg font-bold text-white mb-3 tracking-wide">LLM Threat Reasoning</h3>
          <p className="text-sm text-gray-400 leading-relaxed">
            Automated intelligence derivation mapping extracted heuristics directly to MITRE ATT&CK tactics and techniques.
          </p>
        </div>

        {/* Card 3 */}
        <div className="bg-gray-900/50 border border-gray-800 p-8 rounded-xl hover:border-gray-600 hover:bg-gray-900 transition-all">
          <div className="w-12 h-12 bg-gray-950 border border-gray-800 rounded-lg flex items-center justify-center mb-6">
            <Network className="w-6 h-6 text-cyan-400" />
          </div>
          <h3 className="text-lg font-bold text-white mb-3 tracking-wide">Supply Chain Attribution</h3>
          <p className="text-sm text-gray-400 leading-relaxed">
            Pinpoint the exact open-source ecosystem or package responsible for malicious dropper behavior.
          </p>
        </div>

      </div>
    </div>
  );
}
