import type { Metadata } from "next";
import Link from "next/link";
import "./globals.css";

export const metadata: Metadata = {
  title: "prompt-armor // dashboard",
  description: "Real-time analytics for prompt injection detection",
};

function Sidebar() {
  const links = [
    { href: "/", label: "overview" },
    { href: "/feed", label: "live-feed" },
    { href: "/timeline", label: "timeline" },
  ];

  return (
    <aside className="w-52 border-r border-[#1f521f] flex flex-col" style={{ background: '#0a0a0a' }}>
      <div className="p-4 border-b border-[#1f521f]">
        <div className="text-xs font-bold tracking-widest glow" style={{ color: '#33ff00' }}>
          PROMPT ARMOR
        </div>
        <div className="text-[10px] mt-1" style={{ color: '#1f521f' }}>
          v0.2.0 // dashboard
        </div>
      </div>

      <nav className="flex-1 p-3 space-y-1">
        {links.map((link) => (
          <Link
            key={link.href}
            href={link.href}
            className="block px-2 py-1.5 text-xs hover:bg-[#1f521f]/30 transition-colors"
            style={{ color: '#33ff00' }}
          >
            <span style={{ color: '#1f521f' }}>$ </span>
            {link.label}
          </Link>
        ))}
      </nav>

      <div className="p-3 border-t border-[#1f521f] text-[10px]" style={{ color: '#1f521f' }}>
        <div>[DB] analytics.db</div>
      </div>
    </aside>
  );
}

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className="dark">
      <head>
        <link
          href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;500;700&display=swap"
          rel="stylesheet"
        />
      </head>
      <body style={{ fontFamily: "'JetBrains Mono', monospace", background: '#0a0a0a', color: '#33ff00' }}>
        <div className="flex h-screen">
          <Sidebar />
          <main className="flex-1 overflow-auto p-6">
            {children}
          </main>
        </div>
      </body>
    </html>
  );
}
