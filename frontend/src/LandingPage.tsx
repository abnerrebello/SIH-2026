import {
  ArrowRight,
  Binary,
  BrainCircuit,
  ChevronRight,
  CircleCheck,
  GitBranch,
  LockKeyhole,
  Radar,
  Sparkles,
  Activity,
  Cpu,
  Database,
  Globe2,
  ScanLine,
  Terminal,
  Zap,
} from "lucide-react";
import { Link } from "react-router-dom";
import { useEffect, useRef } from "react";

const capabilities = [
  {
    icon: Radar,
    index: "01",
    label: "ATTACK SURFACE",
    title: "See what is exposed.",
    text: "Map assets, vulnerabilities and external exposure into one continuously evolving security view.",
    accent: "cyan",
  },
  {
    icon: GitBranch,
    index: "02",
    label: "ATTACK PATHS",
    title: "See how attackers move.",
    text: "Trace realistic paths through your environment and identify the systems that matter most.",
    accent: "violet",
  },
  {
    icon: BrainCircuit,
    index: "03",
    label: "RISK INTELLIGENCE",
    title: "Turn telemetry into decisions.",
    text: "Correlate technical signals with business criticality to surface the risks worth acting on.",
    accent: "blue",
  },
  {
    icon: Sparkles,
    index: "04",
    label: "INVESTMENT ENGINE",
    title: "Spend security budget intelligently.",
    text: "Compare remediation strategies and find the highest-impact actions within real constraints.",
    accent: "amber",
  },
];

const telemetry = [
  "07 ATTACK PATHS CORRELATED",
  "03 ACTIVE EXPOSURES",
  "14 HIGH-VALUE ASSETS",
  "01 SECURITY GRAPH ONLINE",
];

const nodes = [
  { id: "gateway", label: "EDGE", type: "GATEWAY", x: 13, y: 30, tone: "cyan" },
  { id: "web", label: "WEB-01", type: "PUBLIC", x: 34, y: 19, tone: "cyan" },
  { id: "app", label: "APP-02", type: "INTERNAL", x: 51, y: 43, tone: "violet" },
  { id: "identity", label: "ID-01", type: "IDENTITY", x: 71, y: 22, tone: "blue" },
  { id: "finance", label: "FIN-02", type: "CRITICAL", x: 76, y: 57, tone: "red" },
  { id: "db", label: "DB-01", type: "DATA", x: 48, y: 73, tone: "amber" },
  { id: "vault", label: "VAULT", type: "CORE", x: 85, y: 80, tone: "violet" },
];

const links = [
  [13, 30, 34, 19],
  [34, 19, 51, 43],
  [51, 43, 71, 22],
  [51, 43, 76, 57],
  [51, 43, 48, 73],
  [71, 22, 76, 57],
  [76, 57, 85, 80],
  [48, 73, 85, 80],
];

const css = `
.singularity-landing {
  --bg: #08060e;
  --bg-deep: #05040a;
  --surface: rgba(10, 15, 23, .72);
  --surface-strong: rgba(12, 18, 28, .9);
  --line: rgba(154, 177, 207, .12);
  --line-strong: rgba(154, 177, 207, .22);
  --text: #f4f8fc;
  --muted: #9aa8b9;
  --subtle: #66758a;
  --cyan: #c34dff;
  --blue: #8f72ff;
  --violet: #d05cff;
  --amber: #c59bff;
  --red: #ff70c8;
  position: relative;
  min-height: 100dvh;
  width: 100%;
  overflow: hidden;
  color: var(--text);
  background:
    radial-gradient(circle at 78% 18%, rgba(173, 74, 255, .10), transparent 30%),
    radial-gradient(circle at 12% 34%, rgba(195, 77, 255, .06), transparent 28%),
    linear-gradient(180deg, #08060e 0%, #090611 52%, #030509 100%);
  font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
}

.singularity-landing,
.singularity-landing * { box-sizing: border-box; }

.singularity-landing a { color: inherit; text-decoration: none; }

.singularity-landing::before {
  content: "";
  position: fixed;
  inset: 0;
  z-index: 0;
  pointer-events: none;
  background-image:
    linear-gradient(rgba(196, 167, 220, .025) 1px, transparent 1px),
    linear-gradient(90deg, rgba(196, 167, 220, .025) 1px, transparent 1px);
  background-size: 72px 72px;
  mask-image: linear-gradient(to bottom, rgba(0,0,0,.9), transparent 88%);
}

.singularity-landing::after {
  content: "";
  position: fixed;
  inset: 0;
  z-index: 40;
  pointer-events: none;
  opacity: .06;
  background-image: repeating-linear-gradient(180deg, rgba(255,255,255,.16) 0, rgba(255,255,255,.16) 1px, transparent 1px, transparent 5px);
  mix-blend-mode: soft-light;
}

.sl-ambient {
  position: absolute;
  inset: 0;
  overflow: hidden;
  pointer-events: none;
  z-index: 1;
}

.sl-orb {
  position: absolute;
  width: 420px;
  height: 420px;
  border: 1px solid rgba(195, 77, 255, .06);
  border-radius: 50%;
  transform: translate3d(calc(var(--mx, 0px) * .12), calc(var(--my, 0px) * .12), 0);
  animation: sl-orbit 20s linear infinite;
}

.sl-orb-a { top: 2%; left: 58%; }
.sl-orb-b { top: 11%; left: 56%; width: 600px; height: 600px; opacity: .55; animation-duration: 34s; animation-direction: reverse; }
.sl-orb-c { top: 30%; left: -260px; width: 520px; height: 520px; opacity: .32; animation-duration: 28s; }

@keyframes sl-orbit { to { transform: rotate(360deg) translate3d(calc(var(--mx, 0px) * .12), calc(var(--my, 0px) * .12), 0); } }

.sl-scan {
  position: absolute;
  left: 0;
  right: 0;
  top: 0;
  height: 1px;
  background: linear-gradient(90deg, transparent, rgba(66,217,255,.22), transparent);
  box-shadow: 0 0 24px rgba(66,217,255,.12);
  animation: sl-scan 9s linear infinite;
}

@keyframes sl-scan { 0% { transform: translateY(0); opacity: 0; } 12% { opacity: 1; } 88% { opacity: 1; } 100% { transform: translateY(100vh); opacity: 0; } }

.sl-nav,
.sl-main,
.sl-footer { position: relative; z-index: 5; }

.sl-nav {
  width: min(1680px, calc(100% - 56px));
  margin: 0 auto;
  padding: 24px 0;
  display: flex;
  align-items: center;
  justify-content: space-between;
  border-bottom: 1px solid rgba(154,177,207,.08);
}

.sl-brand {
  display: inline-flex;
  align-items: center;
  gap: 12px;
}

.sl-brand-mark {
  position: relative;
  display: grid;
  place-items: center;
  width: 42px;
  height: 42px;
  border: 1px solid rgba(66,217,255,.34);
  background: linear-gradient(145deg, rgba(14,35,47,.96), rgba(5,11,17,.96));
  box-shadow: inset 0 0 22px rgba(66,217,255,.08), 0 0 26px rgba(66,217,255,.06);
  overflow: hidden;
}
.sl-brand-mark::before {
  content: "";
  position: absolute;
  inset: 6px;
  border: 1px solid rgba(66,217,255,.14);
  transform: rotate(45deg);
}
.sl-brand-mark::after {
  content: "";
  position: absolute;
  left: 6px;
  right: 6px;
  bottom: 7px;
  height: 1px;
  background: linear-gradient(90deg, transparent, var(--cyan), transparent);
  opacity: .65;
}
.sl-brand-mark span {
  position: relative;
  z-index: 2;
  color: #dff8ff;
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-size: 16px;
  font-weight: 800;
  letter-spacing: -.12em;
  transform: translateX(-1px);
}
.sl-brand-mark i {
  position: absolute;
  z-index: 2;
  right: 7px;
  top: 7px;
  width: 4px;
  height: 4px;
  border-radius: 50%;
  background: var(--cyan);
  box-shadow: 0 0 10px rgba(66,217,255,.8);
}

.sl-brand-copy { display: flex; flex-direction: column; gap: 2px; }
.sl-brand-copy strong { font-size: 16px; letter-spacing: -.02em; }
.sl-brand-copy small { color: var(--subtle); font-size: 10px; letter-spacing: .14em; text-transform: uppercase; }

.sl-nav-meta {
  display: flex;
  align-items: center;
  gap: 20px;
}

.sl-system-state {
  display: flex;
  align-items: center;
  gap: 8px;
  color: #a8b5c5;
  font-size: 11px;
  letter-spacing: .12em;
  text-transform: uppercase;
}

.sl-live-dot,
.sl-mini-dot {
  width: 7px;
  height: 7px;
  border-radius: 50%;
  background: var(--cyan);
  box-shadow: 0 0 0 4px rgba(66,217,255,.08), 0 0 14px rgba(66,217,255,.5);
  animation: sl-pulse 2.4s ease-in-out infinite;
}

@keyframes sl-pulse { 50% { opacity: .55; transform: scale(.82); } }

.sl-nav-actions { display: flex; align-items: center; gap: 10px; }
.sl-nav-login { color: #aab7c6; font-size: 14px; padding: 11px 12px; }
.sl-nav-cta { display: inline-flex; align-items: center; gap: 9px; padding: 11px 15px; border: 1px solid rgba(66,217,255,.28); background: rgba(10,22,31,.76); font-size: 13px; font-weight: 600; transition: transform .2s ease, border-color .2s ease, background .2s ease; }
.sl-nav-cta:hover { transform: translateY(-1px); border-color: rgba(66,217,255,.55); background: rgba(12,29,40,.92); }

.sl-hero {
  width: min(1680px, calc(100% - 56px));
  margin: 0 auto;
  min-height: clamp(610px, calc(100svh - 92px), 820px);
  padding: clamp(44px, 5vh, 76px) 0 clamp(44px, 5vh, 72px);
  display: grid;
  grid-template-columns: minmax(0, .92fr) minmax(480px, 1.08fr);
  gap: 56px;
  align-items: center;
}

.sl-hero-copy { max-width: 670px; }

.sl-kicker {
  display: inline-flex;
  align-items: center;
  gap: 9px;
  color: #8d9daf;
  font-size: 12px;
  font-weight: 700;
  letter-spacing: .16em;
  text-transform: uppercase;
}

.sl-kicker::before {
  content: "";
  width: 26px;
  height: 1px;
  background: linear-gradient(90deg, transparent, var(--cyan));
}

.sl-hero h1 {
  margin: 22px 0 24px;
  max-width: 760px;
  font-size: clamp(52px, 5.8vw, 88px);
  line-height: .94;
  letter-spacing: -.06em;
  font-weight: 720;
}

.sl-hero h1 span {
  background: linear-gradient(105deg, #f6fbff 0%, #a6dff5 45%, #75d7ff 100%);
  -webkit-background-clip: text;
  background-clip: text;
  color: transparent;
}

.sl-hero-lede {
  max-width: 610px;
  margin: 0;
  color: #9aa8b8;
  font-size: 18px;
  line-height: 1.72;
}

.sl-actions { display: flex; flex-wrap: wrap; gap: 12px; margin-top: 32px; }

.sl-primary,
.sl-secondary {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: 10px;
  min-height: 48px;
  padding: 0 18px;
  border: 1px solid transparent;
  font-size: 14px;
  font-weight: 700;
  transition: transform .2s ease, border-color .2s ease, background .2s ease, box-shadow .2s ease;
}

.sl-primary { background: linear-gradient(180deg, #79e3ff 0%, #42c8ef 100%); color: #041017; box-shadow: 0 12px 34px rgba(66,217,255,.16); }
.sl-primary:hover { transform: translateY(-2px); box-shadow: 0 16px 42px rgba(66,217,255,.22); }
.sl-secondary { border-color: rgba(154,177,207,.16); background: rgba(8,13,20,.55); color: #d3dde8; }
.sl-secondary:hover { transform: translateY(-2px); border-color: rgba(154,177,207,.32); background: rgba(12,18,27,.82); }

.sl-trust { display: flex; flex-wrap: wrap; gap: 16px 24px; margin-top: 26px; color: #8c9bad; font-size: 12px; }
.sl-trust div { display: inline-flex; align-items: center; gap: 7px; }
.sl-trust svg { color: #61d7b4; }

.sl-hero-side { min-width: 0; }

.sl-console {
  position: relative;
  min-height: clamp(500px, 66svh, 620px);
  border: 1px solid rgba(130,156,187,.18);
  background:
    linear-gradient(180deg, rgba(9,16,25,.90), rgba(4,8,13,.96)),
    radial-gradient(circle at 50% 42%, rgba(66,217,255,.08), transparent 34%);
  box-shadow: 0 28px 80px rgba(0,0,0,.42), inset 0 0 90px rgba(84,124,164,.05);
  overflow: hidden;
  transform: translate3d(calc(var(--mx, 0px) * -.012), calc(var(--my, 0px) * -.012), 0);
  transition: transform .18s ease-out;
}

.sl-console::before {
  content: "";
  position: absolute;
  inset: 0;
  background-image:
    linear-gradient(rgba(110,146,179,.035) 1px, transparent 1px),
    linear-gradient(90deg, rgba(110,146,179,.035) 1px, transparent 1px);
  background-size: 42px 42px;
  mask-image: radial-gradient(circle at center, black 20%, transparent 88%);
}

.sl-console-bar {
  position: relative;
  z-index: 2;
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  padding: 18px 18px 14px;
  border-bottom: 1px solid rgba(154,177,207,.10);
}

.sl-console-label { display: flex; flex-direction: column; gap: 5px; }
.sl-console-label span { color: #66778b; font-size: 11px; letter-spacing: .17em; text-transform: uppercase; }
.sl-console-label strong { font-size: 14px; letter-spacing: -.01em; }

.sl-console-state { display: inline-flex; align-items: center; gap: 7px; color: #78dcc2; font-size: 11px; font-weight: 700; letter-spacing: .14em; }
.sl-console-state span { width: 6px; height: 6px; border-radius: 50%; background: #58d9ae; box-shadow: 0 0 12px #58d9ae; }

.sl-field { position: relative; min-height: 392px; }
.sl-field svg { position: absolute; inset: 0; width: 100%; height: 100%; overflow: visible; }
.sl-link { stroke: rgba(119,150,183,.18); stroke-width: .22; fill: none; }
.sl-link.hot { stroke: rgba(255,93,110,.48); stroke-dasharray: 1.6 1.8; animation: sl-dash 4s linear infinite; }
@keyframes sl-dash { to { stroke-dashoffset: -24; } }

.sl-field-core {
  position: absolute;
  left: 50%; top: 48%;
  transform: translate(-50%, -50%);
  width: 178px;
  height: 178px;
  border-radius: 50%;
}
.sl-core-ring { position: absolute; inset: 0; border-radius: 50%; border: 1px solid rgba(66,217,255,.16); animation: sl-core-rotate 18s linear infinite; }
.sl-core-ring.r2 { inset: 13px; border-color: rgba(166,137,255,.14); animation-duration: 26s; animation-direction: reverse; }
.sl-core-ring.r3 { inset: 34px; border-color: rgba(66,217,255,.22); animation-duration: 11s; }
.sl-core-ring::before { content: ""; position: absolute; top: -3px; left: 50%; width: 6px; height: 6px; border-radius: 50%; background: var(--cyan); box-shadow: 0 0 16px rgba(66,217,255,.8); }
@keyframes sl-core-rotate { to { transform: rotate(360deg); } }

.sl-risk {
  position: absolute;
  inset: 0;
  display: grid;
  place-items: center;
  text-align: center;
  transform: translateZ(0);
}
.sl-risk span { display: block; color: #7e8ea1; font-size: 10px; letter-spacing: .22em; }
.sl-risk strong { display: block; margin-top: 2px; font-size: 42px; line-height: 1; letter-spacing: -.06em; }
.sl-risk small { display: block; margin-top: 7px; color: #efb55e; font-size: 10px; font-weight: 800; letter-spacing: .16em; }

.sl-node {
  position: absolute;
  transform: translate(-50%, -50%);
  display: flex;
  align-items: center;
  gap: 7px;
  color: #b7c3d0;
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-size: 10px;
  white-space: nowrap;
}
.sl-node > i { display: block; width: 7px; height: 7px; border-radius: 50%; background: var(--cyan); box-shadow: 0 0 12px rgba(66,217,255,.7); animation: sl-pulse 2.2s ease-in-out infinite; }
.sl-node.violet > i { background: var(--violet); box-shadow: 0 0 12px rgba(166,137,255,.7); }
.sl-node.blue > i { background: var(--blue); box-shadow: 0 0 12px rgba(111,143,255,.7); }
.sl-node.red > i { background: var(--red); box-shadow: 0 0 12px rgba(255,93,110,.9); }
.sl-node.amber > i { background: var(--amber); box-shadow: 0 0 12px rgba(240,179,93,.7); }

.sl-signal {
  position: absolute;
  display: inline-flex;
  align-items: center;
  gap: 7px;
  min-height: 30px;
  padding: 0 9px;
  border: 1px solid rgba(154,177,207,.13);
  background: rgba(6,11,17,.82);
  color: #8ea0b3;
  font-size: 9px;
  letter-spacing: .1em;
  box-shadow: 0 14px 26px rgba(0,0,0,.25);
  animation: sl-float 5s ease-in-out infinite;
}
.sl-signal svg { position: static; width: 13px; height: 13px; color: var(--cyan); }
.sl-signal-a { left: 8%; top: 15%; }
.sl-signal-b { right: 8%; top: 70%; animation-delay: -2s; }
@keyframes sl-float { 50% { transform: translateY(-5px); } }

.sl-packet {
  position: absolute;
  width: 5px;
  height: 5px;
  border-radius: 50%;
  background: #91eaff;
  box-shadow: 0 0 14px rgba(66,217,255,.9);
  animation: sl-packet 5.2s linear infinite;
}
.sl-packet.p1 { left: 20%; top: 25%; --dx: 29vw; --dy: 20vh; }
.sl-packet.p2 { left: 37%; top: 22%; --dx: 19vw; --dy: 21vh; animation-delay: -2s; }
.sl-packet.p3 { left: 55%; top: 48%; --dx: 19vw; --dy: 12vh; animation-delay: -3.1s; background: #ff7180; box-shadow: 0 0 14px rgba(255,93,110,.88); }
@keyframes sl-packet { 0% { transform: translate(0,0); opacity: 0; } 10% { opacity: 1; } 48% { opacity: 1; } 60% { transform: translate(var(--dx), var(--dy)); opacity: 0; } 100% { transform: translate(var(--dx), var(--dy)); opacity: 0; } }

.sl-console-footer { position: absolute; left: 0; right: 0; bottom: 0; z-index: 2; display: grid; grid-template-columns: repeat(4, 1fr); border-top: 1px solid rgba(154,177,207,.10); background: rgba(4,8,13,.78); backdrop-filter: blur(10px); }
.sl-console-stat { min-width: 0; padding: 14px 16px; border-right: 1px solid rgba(154,177,207,.08); }
.sl-console-stat:last-child { border-right: 0; }
.sl-console-stat span { display: block; color: #68778a; font-size: 9px; letter-spacing: .13em; }
.sl-console-stat strong { display: block; margin-top: 4px; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 17px; }
.sl-console-stat strong.hot { color: #ff7a88; }

.sl-side-tag { position: absolute; z-index: 3; display: flex; align-items: center; gap: 8px; border: 1px solid rgba(154,177,207,.11); background: rgba(7,11,17,.78); padding: 9px 11px; color: #8d9cad; font-size: 10px; box-shadow: 0 16px 30px rgba(0,0,0,.25); }
.sl-side-tag.left { left: -28px; bottom: 78px; }
.sl-side-tag.right { right: -20px; top: 86px; }
.sl-side-tag .dot { width: 6px; height: 6px; border-radius: 50%; background: var(--cyan); box-shadow: 0 0 10px rgba(66,217,255,.75); }

.sl-telemetry {
  width: min(1680px, calc(100% - 56px));
  margin: 0 auto;
  display: grid;
  grid-template-columns: 155px repeat(4, 1fr);
  border-top: 1px solid rgba(154,177,207,.10);
  border-bottom: 1px solid rgba(154,177,207,.10);
}
.sl-telemetry-label,
.sl-telemetry-item { padding: 13px 14px; }
.sl-telemetry-label { color: #596a7d; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 11px; letter-spacing: .12em; }
.sl-telemetry-item { position: relative; border-left: 1px solid rgba(154,177,207,.07); color: #8091a4; font-size: 11px; letter-spacing: .08em; white-space: nowrap; overflow: hidden; }
.sl-telemetry-item::after { content: ""; position: absolute; left: 0; bottom: -1px; width: 34px; height: 1px; background: var(--cyan); opacity: .55; }

.sl-section { width: min(1440px, calc(100% - 64px)); margin: 0 auto; padding: 118px 0; }
.sl-section-head { display: grid; grid-template-columns: minmax(0, 1fr) minmax(320px, 480px); gap: 60px; align-items: end; }
.sl-section-head h2 { margin: 18px 0 0; font-size: clamp(38px, 4.5vw, 64px); line-height: .98; letter-spacing: -.05em; }
.sl-section-head p { margin: 0; color: #8998a9; font-size: 16px; line-height: 1.75; }

.sl-capability-grid { margin-top: 58px; display: grid; grid-template-columns: repeat(4, 1fr); border-top: 1px solid rgba(154,177,207,.12); border-bottom: 1px solid rgba(154,177,207,.12); }
.sl-capability { position: relative; min-height: 330px; padding: 26px 24px 30px; border-right: 1px solid rgba(154,177,207,.08); transition: transform .25s ease, background .25s ease; overflow: hidden; }
.sl-capability:last-child { border-right: 0; }
.sl-capability:hover { transform: translateY(-5px); background: linear-gradient(180deg, rgba(16,26,38,.52), rgba(6,11,17,.38)); }
.sl-capability::after { content: ""; position: absolute; top: 0; left: 24px; right: 24px; height: 1px; background: linear-gradient(90deg, rgba(66,217,255,.5), transparent); opacity: .24; }
.sl-capability-index { position: absolute; right: 20px; top: 23px; color: #3b495a; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 10px; }
.sl-capability-icon { width: 42px; height: 42px; display: grid; place-items: center; border: 1px solid rgba(154,177,207,.12); background: rgba(10,16,24,.72); color: var(--cyan); }
.sl-capability.violet .sl-capability-icon { color: var(--violet); }
.sl-capability.blue .sl-capability-icon { color: var(--blue); }
.sl-capability.amber .sl-capability-icon { color: var(--amber); }
.sl-capability-label { display: block; margin-top: 30px; color: #66768a; font-size: 10px; font-weight: 700; letter-spacing: .15em; }
.sl-capability h3 { margin: 11px 0 14px; max-width: 260px; font-size: 24px; line-height: 1.12; letter-spacing: -.03em; }
.sl-capability p { margin: 0; color: #7f8e9f; font-size: 14px; line-height: 1.68; }

.sl-middle { display: grid; grid-template-columns: minmax(0, 1.05fr) minmax(320px, .7fr); gap: 20px; margin-top: 20px; }
.sl-module { min-height: 300px; position: relative; border: 1px solid rgba(154,177,207,.10); background: rgba(7,12,19,.66); overflow: hidden; }
.sl-module-main { padding: 28px; }
.sl-module::before { content: ""; position: absolute; inset: 0; background: linear-gradient(135deg, rgba(66,217,255,.05), transparent 32%, transparent 70%, rgba(166,137,255,.04)); pointer-events: none; }
.sl-module-title { display: flex; align-items: flex-start; justify-content: space-between; gap: 18px; }
.sl-module-title span { display: block; color: #63748a; font-size: 9px; letter-spacing: .16em; }
.sl-module-title strong { display: block; margin-top: 7px; font-size: 20px; letter-spacing: -.025em; }
.sl-module-code { color: #4c5b6d; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 10px; }

.sl-bars { display: grid; gap: 12px; margin-top: 28px; }
.sl-bar-row { display: grid; grid-template-columns: 120px 1fr 48px; gap: 12px; align-items: center; }
.sl-bar-label { color: #8797a9; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 10px; }
.sl-bar-track { position: relative; height: 6px; background: rgba(154,177,207,.08); }
.sl-bar-track span { display: block; height: 100%; background: linear-gradient(90deg, #c34dff, #8f72ff); transform-origin: left; animation: sl-grow 1.2s ease both; }
.sl-bar-row:nth-child(2) .sl-bar-track span { background: linear-gradient(90deg, #8f7aff, #be9aff); animation-delay: .08s; }
.sl-bar-row:nth-child(3) .sl-bar-track span { background: linear-gradient(90deg, #efb35f, #ffcf86); animation-delay: .16s; }
.sl-bar-row:nth-child(4) .sl-bar-track span { background: linear-gradient(90deg, #ff70c8, #ff8893); animation-delay: .24s; }
@keyframes sl-grow { from { transform: scaleX(0); } to { transform: scaleX(1); } }
.sl-bar-value { color: #c6d1dc; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 11px; text-align: right; }

.sl-module-list { display: grid; margin-top: 22px; border-top: 1px solid rgba(154,177,207,.08); }
.sl-list-item { display: grid; grid-template-columns: 34px 1fr auto; align-items: center; gap: 12px; padding: 15px 0; border-bottom: 1px solid rgba(154,177,207,.08); }
.sl-list-icon { width: 30px; height: 30px; display: grid; place-items: center; border: 1px solid rgba(154,177,207,.10); color: #75dcff; background: rgba(66,217,255,.04); }
.sl-list-copy strong { display: block; font-size: 12px; }
.sl-list-copy span { display: block; margin-top: 3px; color: #617185; font-size: 10px; }
.sl-list-score { color: #ff7b88; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 12px; }

.sl-bottom { width: min(1440px, calc(100% - 64px)); margin: 0 auto; padding: 24px 0 120px; }
.sl-bottom-panel { position: relative; min-height: 320px; display: flex; align-items: center; justify-content: space-between; gap: 40px; padding: 52px; border: 1px solid rgba(154,177,207,.12); background: linear-gradient(135deg, rgba(10,18,28,.92), rgba(5,9,15,.92)); overflow: hidden; }
.sl-bottom-panel::before { content: ""; position: absolute; inset: auto -10% -55% auto; width: 500px; height: 500px; border: 1px solid rgba(66,217,255,.08); border-radius: 50%; box-shadow: 0 0 0 60px rgba(66,217,255,.02), 0 0 0 120px rgba(66,217,255,.015); }
.sl-bottom-copy { position: relative; z-index: 2; }
.sl-bottom-copy h2 { margin: 18px 0 0; max-width: 800px; font-size: clamp(38px, 5vw, 66px); line-height: .98; letter-spacing: -.055em; }
.sl-bottom-copy p { max-width: 650px; margin: 20px 0 0; color: #8190a1; font-size: 15px; line-height: 1.7; }
.sl-bottom-action { position: relative; z-index: 2; flex: 0 0 auto; }

.sl-footer { width: min(1440px, calc(100% - 64px)); margin: 0 auto; padding: 22px 0 30px; border-top: 1px solid rgba(154,177,207,.08); display: flex; align-items: center; justify-content: space-between; gap: 20px; color: #526175; font-size: 10px; letter-spacing: .08em; text-transform: uppercase; }
.sl-footer strong { color: #8b9aac; font-size: 11px; letter-spacing: .02em; text-transform: none; }

.sl-corner-data { position: absolute; left: 18px; bottom: 18px; color: #415064; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 9px; line-height: 1.7; }

@media (max-width: 1100px) {
  .sl-hero { grid-template-columns: 1fr; }
  .sl-hero-copy { max-width: 840px; }
  .sl-hero-side { max-width: 900px; width: 100%; margin: 0 auto; }
  .sl-capability-grid { grid-template-columns: repeat(2, 1fr); }
  .sl-capability:nth-child(2) { border-right: 0; }
  .sl-capability:nth-child(n+3) { border-top: 1px solid rgba(154,177,207,.08); }
  .sl-middle { grid-template-columns: 1fr; }
}

@media (max-width: 760px) {
  .sl-nav, .sl-hero, .sl-telemetry, .sl-section, .sl-bottom, .sl-footer { width: min(100% - 32px, 1680px); }
  .sl-nav { padding: 18px 0; }
  .sl-system-state { display: none; }
  .sl-nav-login { display: none; }
  .sl-hero { padding: 56px 0 48px; min-height: auto; }
  .sl-hero h1 { font-size: clamp(46px, 13vw, 66px); }
  .sl-hero-lede { font-size: 16px; line-height: 1.65; }
  .sl-console { min-height: 500px; }
  .sl-console-footer { grid-template-columns: repeat(2, 1fr); }
  .sl-console-stat:nth-child(2) { border-right: 0; }
  .sl-console-stat:nth-child(3), .sl-console-stat:nth-child(4) { border-top: 1px solid rgba(154,177,207,.08); }
  .sl-console-stat:nth-child(4) { border-right: 0; }
  .sl-telemetry { display: grid; grid-template-columns: 1fr 1fr; }
  .sl-telemetry-label { grid-column: 1 / -1; border-bottom: 1px solid rgba(154,177,207,.07); }
  .sl-telemetry-item { min-width: 0; overflow: hidden; text-overflow: ellipsis; }
  .sl-section { padding: 84px 0; }
  .sl-section-head { grid-template-columns: 1fr; gap: 24px; }
  .sl-section-head h2 { font-size: clamp(38px, 11vw, 52px); }
  .sl-capability-grid { grid-template-columns: 1fr; }
  .sl-capability, .sl-capability:nth-child(2) { border-right: 0; border-top: 1px solid rgba(154,177,207,.08); }
  .sl-capability:first-child { border-top: 0; }
  .sl-bottom-panel { padding: 32px 26px; flex-direction: column; align-items: flex-start; }
  .sl-footer { align-items: flex-start; flex-direction: column; }
  .sl-side-tag { display: none; }
  .sl-field { min-height: 350px; }
  .sl-node { font-size: 8px; }
  .sl-signal { transform: scale(.86); transform-origin: left center; }
  .sl-signal-b { transform-origin: right center; }
}

@media (prefers-reduced-motion: reduce) {
  .singularity-landing *, .singularity-landing *::before, .singularity-landing *::after {
    animation-duration: .01ms !important;
    animation-iteration-count: 1 !important;
    transition-duration: .01ms !important;
    scroll-behavior: auto !important;
  }
}
`;

export default function LandingPage() {
  const pageRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const page = pageRef.current;
    if (!page) return;

    let frame = 0;
    let mx = 0;
    let my = 0;

    const paint = () => {
      frame = 0;
      page.style.setProperty("--mx", `${mx}px`);
      page.style.setProperty("--my", `${my}px`);
    };

    const onMove = (event: PointerEvent) => {
      const rect = page.getBoundingClientRect();
      mx = (event.clientX - rect.left - rect.width / 2) / 12;
      my = (event.clientY - rect.top - rect.height / 2) / 12;
      if (!frame) frame = requestAnimationFrame(paint);
    };

    window.addEventListener("pointermove", onMove, { passive: true });
    return () => {
      window.removeEventListener("pointermove", onMove);
      if (frame) cancelAnimationFrame(frame);
    };
  }, []);

  return (
    <div ref={pageRef} className="singularity-landing">
      <style>{css}</style>

      <div className="sl-ambient" aria-hidden="true">
        <div className="sl-orb sl-orb-a" />
        <div className="sl-orb sl-orb-b" />
        <div className="sl-orb sl-orb-c" />
        <div className="sl-scan" />
      </div>

      <header className="sl-nav">
        <Link to="/" className="sl-brand" aria-label="Singularity home">
          <span className="sl-brand-mark" aria-hidden="true"><span>S</span><i /></span>
          <span className="sl-brand-copy">
            <strong>Singularity</strong>
            <small>Cyber Risk Intelligence</small>
          </span>
        </Link>

        <div className="sl-nav-meta">
          <div className="sl-system-state">
            <span className="sl-live-dot" />
            Security environment online
          </div>
          <div className="sl-nav-actions">
            <Link to="/auth" className="sl-nav-login">Sign in</Link>
            <Link to="/auth?mode=register" className="sl-nav-cta">
              Create account
              <ArrowRight size={15} />
            </Link>
          </div>
        </div>
      </header>

      <main className="sl-main">
        <section className="sl-hero">
          <div className="sl-hero-copy">
            <div className="sl-kicker">Security intelligence / live</div>
            <h1>
              See the threat.
              <br />
              <span>Understand the risk.</span>
            </h1>
            <p className="sl-hero-lede">
              Singularity connects attack surface, vulnerabilities, network relationships and financial exposure into one decision system for modern security teams.
            </p>

            <div className="sl-actions">
              <Link to="/auth?mode=register" className="sl-primary">
                Enter Singularity
                <ArrowRight size={18} />
              </Link>
              <Link to="/auth" className="sl-secondary">
                Sign in
              </Link>
            </div>

            <div className="sl-trust">
              <div><CircleCheck size={15} /> Context-aware risk</div>
              <div><CircleCheck size={15} /> Attack-path analysis</div>
              <div><CircleCheck size={15} /> Financial decisions</div>
            </div>
          </div>

          <div className="sl-hero-side">
            <div className="sl-console" aria-label="Illustrative Singularity security field">
              <div className="sl-console-bar">
                <div className="sl-console-label">
                  <span>Live security field</span>
                  <strong>Environment posture</strong>
                </div>
                <div className="sl-console-state"><span /> SECURE CHANNEL</div>
              </div>

              <div className="sl-field">
                <svg viewBox="0 0 100 100" preserveAspectRatio="none" aria-hidden="true">
                  {links.map(([x1, y1, x2, y2], index) => (
                    <line
                      key={`${x1}-${y1}-${x2}-${y2}`}
                      className={`sl-link ${index === 5 || index === 6 ? "hot" : ""}`}
                      x1={x1}
                      y1={y1}
                      x2={x2}
                      y2={y2}
                    />
                  ))}
                </svg>

                {nodes.map((node) => (
                  <div
                    className={`sl-node ${node.tone}`}
                    key={node.id}
                    style={{ left: `${node.x}%`, top: `${node.y}%` }}
                  >
                    <i />
                    {node.label}
                  </div>
                ))}

                <div className="sl-field-core">
                  <div className="sl-core-ring" />
                  <div className="sl-core-ring r2" />
                  <div className="sl-core-ring r3" />
                  <div className="sl-risk">
                    <div>
                      <span>RISK</span>
                      <strong>68</strong>
                      <small>ELEVATED</small>
                    </div>
                  </div>
                </div>

                <div className="sl-signal sl-signal-a"><Binary size={13} /> CVE / ACTIVE</div>
                <div className="sl-signal sl-signal-b"><Zap size={13} /> PATH DETECTED</div>
                <span className="sl-packet p1" />
                <span className="sl-packet p2" />
                <span className="sl-packet p3" />
              </div>

              <div className="sl-corner-data">
                <div>SYS  /  GRAPH-01</div>
                <div>FLOW  /  0x7A4C</div>
                <div>SYNC  /  14:32:08</div>
              </div>

              <div className="sl-console-footer">
                <div className="sl-console-stat"><span>ATTACK PATHS</span><strong className="hot">07</strong></div>
                <div className="sl-console-stat"><span>CRITICAL ASSETS</span><strong>04</strong></div>
                <div className="sl-console-stat"><span>THREAT SIGNALS</span><strong>19</strong></div>
                <div className="sl-console-stat"><span>EXPOSURE</span><strong>1,362</strong></div>
              </div>
            </div>

            <div className="sl-side-tag left"><span className="dot" /> Threat signals correlated</div>
            <div className="sl-side-tag right"><span className="dot" /> Decision engine online</div>
          </div>
        </section>

        <section className="sl-telemetry" aria-label="Platform telemetry">
          <div className="sl-telemetry-label">SYSTEM TELEMETRY</div>
          {telemetry.map((item) => <div className="sl-telemetry-item" key={item}>{item}</div>)}
        </section>

        <section className="sl-section">
          <div className="sl-section-head">
            <div>
              <div className="sl-kicker">The platform</div>
              <h2>From raw security signals to clear action.</h2>
            </div>
            <p>
              Singularity turns complex security telemetry into a visual, explainable decision layer built for teams that need to know what matters now-not just what is technically vulnerable.
            </p>
          </div>

          <div className="sl-capability-grid">
            {capabilities.map((capability) => {
              const Icon = capability.icon;
              return (
                <article className={`sl-capability ${capability.accent}`} key={capability.label}>
                  <span className="sl-capability-index">{capability.index}</span>
                  <div className="sl-capability-icon"><Icon size={19} /></div>
                  <span className="sl-capability-label">{capability.label}</span>
                  <h3>{capability.title}</h3>
                  <p>{capability.text}</p>
                </article>
              );
            })}
          </div>

          <div className="sl-middle">
            <article className="sl-module sl-module-main">
              <div className="sl-module-title">
                <div>
                  <span>RISK SIGNAL COMPOSITION</span>
                  <strong>Why the system is watching these assets.</strong>
                </div>
                <span className="sl-module-code">MODEL / RISK-7</span>
              </div>

              <div className="sl-bars">
                {[
                  ["CVSS / SEVERITY", 86, "86%"],
                  ["EPSS / EXPOSURE", 73, "73%"],
                  ["EXTERNAL REACH", 61, "61%"],
                  ["PATH IMPACT", 92, "92%"],
                ].map(([label, value, display]) => (
                  <div className="sl-bar-row" key={String(label)}>
                    <span className="sl-bar-label">{label}</span>
                    <div className="sl-bar-track"><span style={{ width: `${value}%` }} /></div>
                    <span className="sl-bar-value">{display}</span>
                  </div>
                ))}
              </div>
            </article>

            <article className="sl-module sl-module-main">
              <div className="sl-module-title">
                <div>
                  <span>ACTIVE SIGNALS</span>
                  <strong>What needs attention now.</strong>
                </div>
                <Activity size={18} color="#c34dff" />
              </div>

              <div className="sl-module-list">
                <div className="sl-list-item">
                  <div className="sl-list-icon"><Globe2 size={15} /></div>
          <div className="sl-list-copy"><strong>Public edge exposure</strong><span>GATEWAY TO WEB / EXTERNAL</span></div>
                  <div className="sl-list-score">HIGH</div>
                </div>
                <div className="sl-list-item">
                  <div className="sl-list-icon"><GitBranch size={15} /></div>
                  <div className="sl-list-copy"><strong>Critical lateral path</strong><span>WEB - APP - FINANCE</span></div>
                  <div className="sl-list-score">92</div>
                </div>
                <div className="sl-list-item">
                  <div className="sl-list-icon"><Database size={15} /></div>
                  <div className="sl-list-copy"><strong>Data concentration</strong><span>DB-01 / PRIVILEGED STORE</span></div>
                  <div className="sl-list-score">87</div>
                </div>
              </div>
            </article>
          </div>
        </section>

        <section className="sl-bottom">
          <div className="sl-bottom-panel">
            <div className="sl-bottom-copy">
              <div className="sl-kicker">Enter the system</div>
              <h2>Your security environment is already telling a story.</h2>
              <p>
                Singularity gives that story structure: what is exposed, how an attacker could move, what matters most, and which actions create the greatest reduction in risk.
              </p>
            </div>
            <div className="sl-bottom-action">
              <Link to="/auth?mode=register" className="sl-primary">
                Create your secure workspace
                <ArrowRight size={18} />
              </Link>
            </div>
          </div>
        </section>
      </main>

      <footer className="sl-footer">
        <strong>Singularity</strong>
        <span>Cyber Risk Intelligence Platform</span>
        <span>Protected environment / online</span>
      </footer>
    </div>
  );
}



