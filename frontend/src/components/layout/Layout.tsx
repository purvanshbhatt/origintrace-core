import React from 'react';
import { Outlet, Link } from 'react-router-dom';
import { ShieldAlert, Github } from 'lucide-react';

export function Layout() {
  return (
    <div className="min-h-screen bg-gray-950 text-gray-100 font-sans flex flex-col">
      {/* Sticky Glassmorphism Navbar */}
      <nav className="sticky top-0 z-50 backdrop-blur-md bg-gray-950/80 border-b border-gray-800">
        <div className="max-w-6xl mx-auto px-8 h-16 flex items-center justify-between">

          {/* Logo & Brand */}
          <Link to="/" className="flex items-center space-x-3 group">
            <ShieldAlert className="w-6 h-6 text-cyan-400 group-hover:text-cyan-300 transition-colors" />
            <div>
              <span className="text-lg font-bold tracking-widest text-white">ORIGIN</span>
              <span className="text-lg font-light tracking-widest text-cyan-400">TRACE</span>
            </div>
          </Link>

          {/* Navigation Links */}
          <div className="flex items-center space-x-8">
            <Link to="/" className="text-sm font-semibold tracking-wider text-gray-400 hover:text-white transition-colors">HOME</Link>
            <Link to="/app" className="text-sm font-semibold tracking-wider text-gray-400 hover:text-white transition-colors">PLATFORM</Link>
            <Link to="/docs" className="text-sm font-semibold tracking-wider text-gray-400 hover:text-white transition-colors">DOCUMENTATION</Link>

            {/* GitHub Button */}
            <a
              href="https://github.com/purvanshbhatt/origintrace-core"
              target="_blank"
              rel="noopener noreferrer"
              className="flex items-center justify-center w-8 h-8 rounded-full bg-gray-900 border border-gray-700 hover:border-gray-500 hover:bg-gray-800 transition-all text-gray-400 hover:text-white"
            >
              <Github className="w-4 h-4" />
            </a>
          </div>
        </div>
      </nav>

      {/* Main Content Area */}
      <main className="flex-grow flex flex-col relative">
        <Outlet />
      </main>

    </div>
  );
}
