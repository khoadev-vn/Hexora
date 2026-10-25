import { ArrowRight, Menu, X, Shield, Terminal, Zap, GitBranch, Cpu, ExternalLink } from 'lucide-react';
import { useState, useEffect } from 'react';

const BG_VIDEO = "https://d8j0ntlcm91z4.cloudfront.net/user_38xzZboKViGWJOttwIXH07lWA1P/hf_20260508_155101_f2540600-6fe9-433e-8e48-b3f4b72f0727.mp4";
const GITHUB_URL = "https://github.com/khoadev-vn/Hexora";
const LOGO_SRC = "/logo.png";
const LOGO_FALLBACK = "https://i.ibb.co/KpkVDx9w/Screenshot-6-Photoroom-Picsart-Ai-Image-Enhancer.png";

interface NavItem {
  label: string;
  href: string;
}

const NAV_ITEMS: NavItem[] = [
  { label: 'Platform', href: `${GITHUB_URL}#-features--capabilities` },
  { label: 'How it works', href: `${GITHUB_URL}#-architecture--core-pillars` },
  { label: 'AI Defense', href: `${GITHUB_URL}#-feature-4-ai-agent-dual-engine` },
  { label: 'Connections', href: `${GITHUB_URL}#-quick-start` },
  { label: 'Insights', href: `${GITHUB_URL}#-security-reports--dashboards` },
];

function HamburgerButton({ open, onClick }: { open: boolean; onClick: () => void }) {
  return (
    <button
      onClick={onClick}
      className="lg:hidden relative w-9 h-9 flex items-center justify-center rounded-full transition-all duration-300 focus:outline-none"
      style={{ backgroundColor: open ? '#1a1a1a' : 'transparent' }}
      aria-label="Toggle menu"
    >
      <span
        className="absolute transition-all duration-300 ease-[cubic-bezier(0.23,1,0.32,1)]"
        style={{ opacity: open ? 0 : 1, transform: open ? 'rotate(-90deg) scale(0.5)' : 'rotate(0deg) scale(1)' }}
      >
        <Menu size={20} color="white" strokeWidth={1.5} />
      </span>
      <span
        className="absolute transition-all duration-300 ease-[cubic-bezier(0.23,1,0.32,1)]"
        style={{ opacity: open ? 1 : 0, transform: open ? 'rotate(0deg) scale(1)' : 'rotate(90deg) scale(0.5)' }}
      >
        <X size={20} color="white" strokeWidth={1.5} />
      </span>
    </button>
  );
}

function MobileMenu({ open, onClose }: { open: boolean; onClose: () => void }) {
  return (
    <>
      <div
        className="fixed inset-0 z-30 lg:hidden transition-all duration-500"
        style={{
          backdropFilter: open ? 'blur(12px)' : 'blur(0px)',
          backgroundColor: open ? 'rgba(0,0,0,0.6)' : 'rgba(0,0,0,0)',
          pointerEvents: open ? 'auto' : 'none',
        }}
        onClick={onClose}
      />

      <div
        className="fixed top-0 left-0 right-0 z-40 lg:hidden overflow-hidden"
        style={{
          maxHeight: open ? '460px' : '0px',
          transition: 'max-height 0.5s cubic-bezier(0.23, 1, 0.32, 1)',
        }}
      >
        <div
          className="pt-20 pb-6 px-5"
          style={{ backgroundColor: 'rgba(8,8,8,0.97)', borderBottom: '1px solid rgba(255,255,255,0.08)' }}
        >
          <div className="flex flex-col gap-1">
            {NAV_ITEMS.map((item, i) => (
              <a
                key={item.label}
                href={item.href}
                target={item.href.startsWith('http') ? '_blank' : '_self'}
                rel="noopener noreferrer"
                onClick={onClose}
                className="text-white/70 hover:text-white text-base py-3 px-3 rounded-xl hover:bg-white/5 transition-all duration-200 flex items-center justify-between group"
                style={{
                  fontFamily: 'Inter, sans-serif',
                  transitionDelay: open ? `${i * 50 + 80}ms` : '0ms',
                  opacity: open ? 1 : 0,
                  transform: open ? 'translateY(0)' : 'translateY(-8px)',
                  transition: `opacity 0.4s cubic-bezier(0.23,1,0.32,1) ${i * 50 + 80}ms, transform 0.4s cubic-bezier(0.23,1,0.32,1) ${i * 50 + 80}ms, color 0.2s, background 0.2s`,
                }}
              >
                {item.label}
                <ArrowRight size={14} className="opacity-0 group-hover:opacity-40 -translate-x-1 group-hover:translate-x-0 transition-all duration-200" />
              </a>
            ))}
          </div>

          <div
            className="mt-5 pt-5"
            style={{
              borderTop: '1px solid rgba(255,255,255,0.07)',
              transitionDelay: open ? '360ms' : '0ms',
              opacity: open ? 1 : 0,
              transform: open ? 'translateY(0)' : 'translateY(-8px)',
              transition: `opacity 0.4s cubic-bezier(0.23,1,0.32,1) 360ms, transform 0.4s cubic-bezier(0.23,1,0.32,1) 360ms`,
            }}
          >
            <a
              href={GITHUB_URL}
              target="_blank"
              rel="noopener noreferrer"
              className="w-full py-3 rounded-full text-black text-sm font-medium transition-all duration-300 hover:opacity-80 flex items-center justify-center gap-2 group"
              style={{ fontFamily: 'Inter, sans-serif', backgroundColor: '#ffffff' }}
            >
              <span>Explore on GitHub</span>
              <ArrowRight size={14} className="group-hover:translate-x-0.5 transition-transform duration-200" />
            </a>
          </div>
        </div>
      </div>
    </>
  );
}

function Navbar() {
  const [open, setOpen] = useState(false);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === 'Escape' && setOpen(false);
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, []);

  return (
    <>
      <nav className="absolute top-0 left-0 right-0 z-50 flex items-center justify-between px-5 py-4 lg:px-10 lg:py-6">
        <a 
          href={GITHUB_URL}
          target="_blank"
          rel="noopener noreferrer"
          className="flex items-center gap-3 group focus:outline-none"
        >
          <img
            src={LOGO_SRC}
            onError={(e) => {
              (e.currentTarget as HTMLImageElement).src = LOGO_FALLBACK;
            }}
            alt="Hexora Logo"
            className="h-8 w-8 rounded-lg object-contain border border-white/10 group-hover:border-cyan-400/50 transition-all duration-300 shadow-sm"
          />
          <span 
            className="text-white text-xl font-semibold tracking-tight group-hover:text-cyan-400 transition-colors" 
            style={{ fontFamily: 'Inter, sans-serif' }}
          >
            Hexora
          </span>
        </a>

        <div className="hidden lg:flex items-center gap-1 rounded-full px-2 py-1.5" style={{ backgroundColor: '#0C0C0C' }}>
          {NAV_ITEMS.map((item) => (
            <a
              key={item.label}
              href={item.href}
              target={item.href.startsWith('http') ? '_blank' : '_self'}
              rel="noopener noreferrer"
              className="text-white/80 hover:text-white text-sm px-4 py-1.5 rounded-full hover:bg-white/10 transition-all duration-200"
              style={{ fontFamily: 'Inter, sans-serif' }}
            >
              {item.label}
            </a>
          ))}
        </div>

        <div className="flex items-center gap-2">
          <HamburgerButton open={open} onClick={() => setOpen((v) => !v)} />
          <a
            href={GITHUB_URL}
            target="_blank"
            rel="noopener noreferrer"
            className="hidden lg:flex items-center gap-2 text-sm font-medium px-5 py-2 rounded-full text-black transition-all duration-300 hover:opacity-80 group"
            style={{ fontFamily: 'Inter, sans-serif', backgroundColor: '#ffffff' }}
          >
            <span>Star on GitHub</span>
            <ArrowRight size={14} className="group-hover:translate-x-0.5 transition-transform duration-200" />
          </a>
        </div>
      </nav>
      <MobileMenu open={open} onClose={() => setOpen(false)} />
    </>
  );
}

export default function App() {
  return (
    <div className="relative w-full h-screen overflow-hidden bg-black select-none" style={{ fontFamily: 'Inter, sans-serif' }}>
      {/* Background Video */}
      <video
        className="absolute inset-0 z-0 w-full h-full object-cover filter brightness-[0.75] contrast-[1.05]"
        src={BG_VIDEO}
        autoPlay
        loop
        muted
        playsInline
      />

      {/* Subtle overlay gradients for contrast */}
      <div className="absolute inset-0 z-10 pointer-events-none bg-gradient-to-b from-black/60 via-transparent to-black/80" />

      {/* Navigation */}
      <Navbar />

      {/* Hero Content */}
      <div className="relative z-20 flex flex-col items-center justify-center text-center h-full pt-[40px] px-5 sm:px-8">
        {/* Subtle pill badge */}
        <div className="mb-6 inline-flex items-center gap-2 px-3.5 py-1.5 rounded-full border border-white/10 bg-black/40 backdrop-blur-md">
          <span className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse" />
          <span className="text-white/70 text-xs font-mono tracking-wider uppercase">
            Universal Security Engine v1.0
          </span>
        </div>

        <h1
          className="text-white font-normal leading-[1.12] tracking-tight max-w-3xl"
          style={{
            fontFamily: 'Inter, sans-serif',
            fontSize: 'clamp(1.75rem, 5vw, 2.75rem)',
          }}
        >
          Where precision finds its edge
          <br className="hidden sm:block" />
          {' '}and vision rewrites what comes next
        </h1>

        <p
          className="mt-5 md:mt-6 text-white/60 text-sm md:text-base leading-relaxed max-w-xs sm:max-w-sm md:max-w-md"
          style={{ fontFamily: "'Courier New', Courier, monospace", letterSpacing: '0.01em' }}
        >
          a seamless bridge - where raw ambition
          <br className="hidden sm:block" />
          {' '}and machine clarity converge as one
        </p>

        {/* CTA Button linked directly to GitHub */}
        <div className="mt-7 md:mt-8 flex flex-col sm:flex-row items-center gap-3">
          <a
            href={GITHUB_URL}
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center gap-2.5 px-6 py-2.5 rounded-full text-black text-sm font-medium transition-all duration-300 hover:opacity-90 hover:scale-[1.02] active:scale-[0.98] group shadow-lg shadow-white/10"
            style={{ fontFamily: 'Inter, sans-serif', backgroundColor: '#ffffff' }}
          >
            <span>Explore on GitHub</span>
            <ArrowRight size={15} className="group-hover:translate-x-0.5 transition-transform duration-200" />
          </a>

          {/* Terminal Command Snippet */}
          <div className="flex items-center gap-2 px-4 py-2 rounded-full border border-white/15 bg-white/5 backdrop-blur-md text-white/80 font-mono text-xs hover:border-cyan-400/50 transition-colors">
            <span className="text-cyan-400">$</span>
            <code>npx hexora .</code>
          </div>
        </div>

        {/* Quick Footer indicator */}
        <div className="absolute bottom-6 left-0 right-0 flex justify-center items-center gap-6 text-white/40 text-xs font-mono">
          <span>Deterministic SAST</span>
          <span>•</span>
          <span>Dual-Agent Verification</span>
          <span>•</span>
          <span>Dynamic PoC</span>
        </div>
      </div>
    </div>
  );
}
