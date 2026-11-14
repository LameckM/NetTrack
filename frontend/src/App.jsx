import { useMemo, useState } from "react";
import {
  Activity, ArrowDown, ArrowDownToLine, ArrowUp, ArrowUpFromLine,
  Bell, ChevronDown, CircleHelp, Command, Cpu, Gauge, Globe2,
  LayoutDashboard, LockKeyhole, MoreHorizontal, Network, Search,
  Settings2, ShieldCheck, SlidersHorizontal, Wifi, Zap
} from "lucide-react";
import {
  Area, AreaChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis
} from "recharts";

const traffic = [
  { time: "00:00", down: 1.2, up: 0.3 }, { time: "02:00", down: 0.8, up: 0.2 },
  { time: "04:00", down: 1.5, up: 0.4 }, { time: "06:00", down: 2.1, up: 0.6 },
  { time: "08:00", down: 4.8, up: 1.2 }, { time: "10:00", down: 3.6, up: 0.9 },
  { time: "12:00", down: 7.9, up: 1.8 }, { time: "14:00", down: 5.3, up: 1.1 },
  { time: "16:00", down: 8.6, up: 2.3 }, { time: "18:00", down: 6.4, up: 1.6 },
  { time: "20:00", down: 4.2, up: 1.0 }, { time: "22:00", down: 2.8, up: 0.7 }
];

const applications = [
  { name: "Google Chrome", process: "chrome.exe", category: "Browser", down: "203.71 MB", up: "2.45 MB", total: "206.16 MB", color: "blue", initials: "C" },
  { name: "Visual Studio Code", process: "Code.exe", category: "Development", down: "780.56 KB", up: "324.19 KB", total: "1.08 MB", color: "violet", initials: "V" },
  { name: "Windows Services", process: "svchost.exe", category: "System", down: "141.09 KB", up: "11.03 KB", total: "152.12 KB", color: "teal", initials: "W" },
  { name: "Microsoft Office", process: "OfficeClickToRun.exe", category: "Productivity", down: "5.13 KB", up: "899 B", total: "6.00 KB", color: "orange", initials: "M" }
];

const nav = [
  { label: "OVERVIEW", icon: LayoutDashboard },
  { label: "APPLICATIONS", icon: Command },
  { label: "USAGE HISTORY", icon: Activity }
];

function Metric({ label, value, unit, change, icon: Icon, tone, direction }) {
  return <article className="metric-card">
    <div className="metric-top"><span>{label}</span><span className={`metric-icon ${tone}`}><Icon size={18}/></span></div>
    <div className="metric-value">{value}<small>{unit}</small></div>
    <div className="metric-foot"><span className="trend"><ArrowUp size={13}/>{change}</span><span>vs. previous hour</span></div>
    <div className={`metric-glow ${tone}`}/>
  </article>;
}

function TrafficPanel() {
  const [range, setRange] = useState("Today");
  return <section className="surface traffic-panel">
    <div className="section-head">
      <div><div className="eyebrow">BANDWIDTH ANALYTICS</div><h2>Network activity</h2><p>Real-time view of your connection usage</p></div>
      <div className="chart-actions"><div className="legend"><span><i className="dot download"/>Download</span><span><i className="dot upload"/>Upload</span></div><button className="select-button">{range}<ChevronDown size={14}/></button></div>
    </div>
    <div className="chart-wrap"><ResponsiveContainer width="100%" height="100%">
      <AreaChart data={traffic} margin={{ top: 12, right: 8, left: -18, bottom: 0 }}>
        <defs>
          <linearGradient id="downloadFill" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#8b7cff" stopOpacity={0.3}/><stop offset="100%" stopColor="#8b7cff" stopOpacity={0}/></linearGradient>
          <linearGradient id="uploadFill" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#35c6bb" stopOpacity={0.18}/><stop offset="100%" stopColor="#35c6bb" stopOpacity={0}/></linearGradient>
        </defs>
        <CartesianGrid stroke="#202b3d" strokeDasharray="3 5" vertical={false}/>
        <XAxis dataKey="time" axisLine={false} tickLine={false} tick={{ fill: "#77869d", fontSize: 11 }} dy={12}/>
        <YAxis axisLine={false} tickLine={false} tick={{ fill: "#77869d", fontSize: 11 }} tickFormatter={v=>v+" MB"} />
        <Tooltip contentStyle={{ background: "#151f30", border: "1px solid #2a3850", borderRadius: 12, color: "#f3f5fc" }} />
        <Area type="monotone" dataKey="down" name="Download" stroke="#9688ff" strokeWidth={2.5} fill="url(#downloadFill)" />
        <Area type="monotone" dataKey="up" name="Upload" stroke="#35c6bb" strokeWidth={2} fill="url(#uploadFill)" />
      </AreaChart>
    </ResponsiveContainer></div>
    <div className="chart-summary"><div><span className="summary-label">TOTAL DOWNLOADED</span><strong>1.42 GB</strong></div><div><span className="summary-label">TOTAL UPLOADED</span><strong>186.4 MB</strong></div><div><span className="summary-label">PEAK DOWNLOAD</span><strong>8.6 Mbps</strong></div></div>
  </section>;
}

function AppTable({ compact = false }) {
  const rows = compact ? applications.slice(0, 4) : applications;
  return <div className="app-list">
    {rows.map((app) => <div className="app-row" key={app.process}>
      <div className={`app-avatar ${app.color}`}>{app.initials}</div>
      <div className="app-name"><strong>{app.name}</strong><span>{app.process}</span></div>
      {!compact && <span className="app-category">{app.category}</span>}
      <div className="app-usage"><strong>{app.total}</strong><span>{app.down} ↓</span></div>
      <div className="usage-track"><i style={{ width: app.process === "chrome.exe" ? "92%" : app.process === "Code.exe" ? "35%" : "12%" }}/></div>
      <button className="icon-button" aria-label={`More about ${app.name}`}><MoreHorizontal size={18}/></button>
    </div>)}
  </div>;
}

export default function App() {
  const [active, setActive] = useState("OVERVIEW");
  const [search, setSearch] = useState("");
  const [range, setRange] = useState("Today");
  const pageTitle = active === "OVERVIEW" ? "Good afternoon" : active === "APPLICATIONS" ? "Application usage" : "Usage history";
  const filtered = useMemo(() => applications.filter(a => (a.name+a.process).toLowerCase().includes(search.toLowerCase())), [search]);
  return <div className="app-shell">
    <aside className="sidebar">
      <div className="brand"><div className="brand-mark"><Activity size={21}/></div><div><strong>nettrack</strong><span>NETWORK INTELLIGENCE</span></div></div>
      <div className="device-card"><div className="device-icon"><Wifi size={17}/></div><div><strong>My PC</strong><span>Windows device</span></div><span className="online-dot"/></div>
      <div className="nav-caption">WORKSPACE</div>
      <nav>{nav.map(({label,icon:Icon})=><button key={label} onClick={()=>setActive(label)} className={active===label?"nav-item active":"nav-item"}><Icon size={17}/><span>{label.charAt(0)+label.slice(1).toLowerCase()}</span>{active===label&&<i/>}</button>)}</nav>
      <div className="nav-caption tools-caption">PREFERENCES</div>
      <button className="nav-item"><Settings2 size={17}/><span>Settings</span></button>
      <div className="sidebar-bottom"><div className="privacy-card"><div className="privacy-icon"><LockKeyhole size={16}/></div><strong>Your data stays yours.</strong><p>Network insights are stored locally on this device.</p><span><ShieldCheck size={13}/> LOCAL-FIRST PRIVACY</span></div><div className="sidebar-footer"><span>NETTRACK DESKTOP</span><span>v0.1.0</span></div></div>
    </aside>

    <main className="main-area">
      <header className="topbar"><div className="breadcrumb">NetTrack <span>/</span> {active.charAt(0)+active.slice(1).toLowerCase()}</div><div className="top-actions"><label className="search-box"><Search size={15}/><input placeholder="Search applications..." value={search} onChange={e=>setSearch(e.target.value)}/><kbd>⌘ K</kbd></label><button className="top-icon"><Bell size={17}/><i/></button><div className="profile"><div className="profile-avatar">N</div><span>My device</span><ChevronDown size={14}/></div></div></header>
      <div className="page-content">
        <div className="welcome-row"><div><div className="eyebrow">SATURDAY, NOVEMBER 14, 2026</div><h1>{pageTitle}<span className="wave">✦</span></h1><p>{active==="OVERVIEW"?"Here's what's happening with your network today.":active==="APPLICATIONS"?"Understand which apps are using your bandwidth.":"Explore your network usage patterns over time."}</p></div><div className="preview-pill"><Activity size={14}/> UI PREVIEW · SAMPLE VALUES</div></div>

        {active==="OVERVIEW"&&<>
          <div className="metrics-grid">
            <Metric label="Download speed" value="0.01" unit="Mbps" change="12.8%" icon={ArrowDownToLine} tone="purple"/>
            <Metric label="Upload speed" value="0.01" unit="Mbps" change="4.2%" icon={ArrowUpFromLine} tone="teal"/>
            <Metric label="Session usage" value="16.46" unit="KB" change="8.4%" icon={Gauge} tone="blue"/>
            <Metric label="Lifetime usage" value="11.70" unit="MB" change="2.1%" icon={Globe2} tone="orange"/>
          </div>
          <TrafficPanel/>
          <div className="bottom-grid">
            <section className="surface connection-panel"><div className="section-head"><div><div className="eyebrow">NETWORK STATUS</div><h2>Your connection</h2></div><button className="text-button">View details <ArrowDown size={13}/></button></div><div className="connection-info"><div className="connection-symbol"><Wifi size={22}/></div><div><strong>Ethernet 2</strong><span>Primary network adapter</span></div><span className="status-badge">ACTIVE</span></div><div className="connection-stats"><div><span>DOWNLOAD</span><strong>0.001 Mbps</strong></div><div><span>UPLOAD</span><strong>0.001 Mbps</strong></div><div><span>ADAPTERS</span><strong>9 detected</strong></div></div></section>
            <section className="surface top-apps-panel"><div className="section-head"><div><div className="eyebrow">DATA CONSUMPTION</div><h2>Top applications</h2></div><button className="text-button" onClick={()=>setActive("APPLICATIONS")}>See all <ArrowDown size={13}/></button></div><AppTable compact/></section>
          </div>
        </>}
        {active==="APPLICATIONS"&&<section className="surface full-panel"><div className="section-head"><div><div className="eyebrow">PROCESS INTELLIGENCE</div><h2>Application breakdown</h2><p>Data usage by running application</p></div><button className="select-button"><SlidersHorizontal size={14}/> Filter</button></div><AppTable/></section>}
        {active==="USAGE HISTORY"&&<><TrafficPanel/><div className="history-cards"><div className="surface history-stat"><span>THIS WEEK</span><strong>4.82 GB</strong><small>Total network traffic</small></div><div className="surface history-stat"><span>DAILY AVERAGE</span><strong>688 MB</strong><small>Across active days</small></div><div className="surface history-stat"><span>BUSIEST DAY</span><strong>Friday</strong><small>1.24 GB transferred</small></div></div></>}
        <footer className="page-footer"><span><LockKeyhole size={13}/> Your network data is stored locally.</span><span>NETTRACK · NETWORK INTELLIGENCE</span></footer>
      </div>
    </main>
  </div>;
}
