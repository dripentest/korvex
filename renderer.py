import json
from pathlib import Path


def _embed_json(data: dict) -> str:
    raw = json.dumps(data, ensure_ascii=False)
    return raw.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")


def render_html(graph: dict, target: str) -> str:
    payload = {"target": target, "graph": graph}
    return _TEMPLATE.replace("__GRAPH_DATA__", _embed_json(payload))


def render_to_file(graph: dict, target: str, out_path: str) -> str:
    html = render_html(graph, target)
    Path(out_path).write_text(html, encoding="utf-8")
    return out_path


_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Recon Graph</title>
<script id="graph-data" type="application/json">__GRAPH_DATA__</script>
<style>
  :root{
    --bg:#0b0e14; --bg2:#0e131b;
    --glass:rgba(20,26,35,.72); --glass2:rgba(30,37,49,.9);
    --border:rgba(255,255,255,.08); --border2:rgba(255,255,255,.15);
    --ink:#e8eef6; --ink-dim:#9aa7b8; --muted:#6b7688;
    --edge:#46536a; --accent:#5b9dff; --accent2:#8b7bff;
    --shadow:0 10px 34px rgba(0,0,0,.55), 0 2px 8px rgba(0,0,0,.4);
    --ring:0 0 0 3px rgba(91,157,255,.18);
  }
  *{box-sizing:border-box}
  html,body{height:100%;margin:0}
  body{background:radial-gradient(1200px 800px at 78% -8%,#141d2b 0%,var(--bg) 55%);color:var(--ink);
    font:13px/1.45 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;overflow:hidden;-webkit-font-smoothing:antialiased}
  svg{width:100%;height:100%;display:block;cursor:grab;touch-action:none}
  svg.panning{cursor:grabbing}

  #bar{position:fixed;top:14px;left:14px;right:14px;display:flex;gap:10px;align-items:center;z-index:20;flex-wrap:wrap}
  .brand{display:flex;align-items:center;gap:8px;font-weight:650;font-size:13.5px;letter-spacing:.2px;padding:9px 14px;
    background:var(--glass);border:1px solid var(--border);border-radius:13px;box-shadow:var(--shadow);backdrop-filter:blur(14px) saturate(140%);-webkit-backdrop-filter:blur(14px) saturate(140%)}
  .brand .dot{width:9px;height:9px;border-radius:50%;background:linear-gradient(135deg,var(--accent),var(--accent2));box-shadow:0 0 10px rgba(91,157,255,.7)}
  .brand small{color:var(--ink-dim);font-weight:500}

  .cluster{display:flex;gap:4px;align-items:center;padding:6px;background:var(--glass);border:1px solid var(--border);
    border-radius:14px;box-shadow:var(--shadow);backdrop-filter:blur(14px) saturate(140%);-webkit-backdrop-filter:blur(14px) saturate(140%)}
  .vr{width:1px;height:22px;background:var(--border);margin:0 3px;flex:none}
  .b{appearance:none;-webkit-appearance:none;font:inherit;color:var(--ink);border:1px solid transparent;border-radius:9px;background:transparent;transition:background .15s,border-color .15s,transform .12s,box-shadow .15s,color .15s}
  button.b{padding:8px 13px;font-size:12px;font-weight:550;cursor:pointer;white-space:nowrap}
  button.b:hover{background:rgba(255,255,255,.09);color:#fff}
  button.b:active{transform:scale(.97)}
  button.b#reset:hover{background:rgba(255,255,255,.09)}
  input.b{min-width:170px;padding:8px 12px 8px 32px;font-size:12px;outline:none;
    background-image:url("data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' width='16' height='16' viewBox='0 0 24 24' fill='none' stroke='%237b8698' stroke-width='2' stroke-linecap='round'><circle cx='11' cy='11' r='7'/><path d='M21 21l-4.2-4.2'/></svg>");
    background-repeat:no-repeat;background-position:10px center;background-size:14px}
  input.b::placeholder{color:var(--muted)}
  input.b:hover{background-color:rgba(255,255,255,.05)}
  input.b:focus{border-color:var(--accent);box-shadow:var(--ring);background-color:rgba(255,255,255,.05)}
  select.b{padding:8px 30px 8px 12px;font-size:12px;font-weight:500;cursor:pointer;
    background-image:url("data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' width='12' height='12' viewBox='0 0 24 24' fill='none' stroke='%239aa7b8' stroke-width='2.4' stroke-linecap='round' stroke-linejoin='round'><path d='M6 9l6 6 6-6'/></svg>");
    background-repeat:no-repeat;background-position:right 10px center;background-size:11px}
  select.b:hover{background-color:rgba(255,255,255,.07);border-color:var(--border)}
  select.b:focus{border-color:var(--accent);box-shadow:var(--ring);outline:none}
  select.b option{background:#141a24;color:var(--ink)}

  #legend{position:fixed;left:14px;bottom:14px;z-index:20;background:var(--glass);border:1px solid var(--border);
    border-radius:13px;padding:12px 13px;box-shadow:var(--shadow);font-size:11px;max-width:250px;
    backdrop-filter:blur(14px) saturate(140%);-webkit-backdrop-filter:blur(14px) saturate(140%)}
  #legend .lg{display:flex;align-items:center;gap:7px;margin:5px 0;color:var(--ink-dim)}
  #legend .sw{width:12px;height:12px;border-radius:4px;flex:none;box-shadow:inset 0 0 0 1px rgba(255,255,255,.15)}
  #legend .hint{margin-top:10px;padding-top:9px;border-top:1px solid var(--border);color:var(--muted);font-size:10px;line-height:1.55}

  .node text{font-weight:600;pointer-events:none;dominant-baseline:middle}
  .node .box{stroke-width:1.7px}
  .node.dragging{opacity:.85}
  .node.dim{opacity:.12}
  .node.hidden,.edge.hidden{display:none}
  .node .collapseglyph{display:none;font-size:11px;font-weight:800;fill:#ffcf66;paint-order:stroke;stroke:var(--bg);stroke-width:3px}
  .node.match .box{stroke:var(--accent);stroke-width:3px}
  .node .statusring{fill:none;stroke-width:3px;display:none}
  .node.st-test .statusring{display:block;stroke:#58a6ff}
  .node.st-done .statusring{display:block;stroke:#3fb950}
  .node.st-fail .statusring{display:block;stroke:#8b949e;stroke-dasharray:4 3}
  .node .statusglyph{display:none;font-size:12px;font-weight:800;paint-order:stroke;stroke:var(--bg);stroke-width:3px}
  .node.st-test .statusglyph,.node.st-done .statusglyph,.node.st-fail .statusglyph{display:block}
  .edge{fill:none;stroke:var(--edge);stroke-width:1.5px}
  .edge.dim{opacity:.05}
  .note text{fill:var(--ink);font-size:14px;font-weight:600;cursor:move;paint-order:stroke;stroke:var(--bg);stroke-width:3px;stroke-linejoin:round}

  .menu{position:fixed;z-index:60;background:var(--glass2);border:1px solid var(--border2);border-radius:12px;
    box-shadow:var(--shadow);padding:6px;min-width:190px;display:none;font-size:12.5px;
    backdrop-filter:blur(16px) saturate(150%);-webkit-backdrop-filter:blur(16px) saturate(150%);
    transform-origin:top left;animation:pop .12s ease}
  @keyframes pop{from{opacity:0;transform:scale(.96)}to{opacity:1;transform:scale(1)}}
  .menu.open{display:block}
  .menu .mi{padding:8px 11px;border-radius:8px;cursor:pointer;white-space:nowrap;transition:background .12s}
  .menu .mi:hover{background:rgba(255,255,255,.10)}
  .menu .mhead{padding:5px 11px 7px;color:var(--muted);font-size:10.5px;font-weight:600;text-transform:uppercase;letter-spacing:.6px;max-width:230px;overflow:hidden;text-overflow:ellipsis}
  .menu .sep{height:1px;background:var(--border);margin:5px 7px}

  #drawer{position:fixed;top:0;right:0;height:100%;width:400px;max-width:94vw;z-index:45;background:var(--glass);
    border-left:1px solid var(--border);box-shadow:-16px 0 48px rgba(0,0,0,.5);transform:translateX(105%);
    transition:transform .24s cubic-bezier(.22,1,.36,1);display:flex;flex-direction:column;
    backdrop-filter:blur(20px) saturate(150%);-webkit-backdrop-filter:blur(20px) saturate(150%)}
  #drawer.open{transform:none}
  #drawer .dh{position:relative;display:flex;justify-content:space-between;align-items:flex-start;gap:12px;padding:18px 18px 16px;border-bottom:1px solid var(--border)}
  #drawer .dh:before{content:"";position:absolute;top:0;left:0;right:0;height:2px;background:linear-gradient(90deg,var(--accent),var(--accent2),transparent)}
  #drawer .dt{font-weight:700;font-size:15.5px;line-height:1.35;word-break:break-word}
  #drawer .dsub{color:var(--muted);font-size:10.5px;font-weight:600;text-transform:uppercase;letter-spacing:.6px;margin-top:5px}
  #drawer .dh button{background:rgba(255,255,255,.05);border:1px solid var(--border);color:var(--ink-dim);font-size:15px;
    width:30px;height:30px;border-radius:8px;cursor:pointer;flex:none;transition:background .15s,color .15s}
  #drawer .dh button:hover{background:rgba(255,255,255,.12);color:#fff}
  #drawer .db{padding:16px 18px;overflow:auto;flex:1}
  #drawer .row{margin:0 0 14px;font-size:13px}
  #drawer .k{color:var(--ink-dim);text-transform:uppercase;font-size:10px;font-weight:600;letter-spacing:.7px}
  #drawer .v{margin-top:4px;line-height:1.55;word-break:break-word}
  #drawer .plist{margin-top:6px;padding:10px 12px;background:rgba(0,0,0,.25);border:1px solid var(--border);border-radius:9px;font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px;line-height:1.8;color:var(--ink-dim)}
  #drawer .badge{display:inline-block;padding:3px 10px;border-radius:20px;font-size:10px;font-weight:700;letter-spacing:.3px;color:#fff;box-shadow:0 2px 8px rgba(0,0,0,.3)}

  .ovl{position:fixed;inset:0;z-index:70;display:none;align-items:flex-start;justify-content:center;background:rgba(6,9,14,.5);backdrop-filter:blur(3px);-webkit-backdrop-filter:blur(3px)}
  .ovl.open{display:flex;animation:pop .14s ease}
  .nbcard{margin-top:16vh;width:420px;max-width:92vw;background:var(--glass2);border:1px solid var(--border2);border-radius:16px;box-shadow:var(--shadow);padding:16px;backdrop-filter:blur(16px) saturate(150%);-webkit-backdrop-filter:blur(16px) saturate(150%)}
  .nbh{font-weight:650;font-size:13px;margin-bottom:10px;color:var(--ink)}
  #nbinput{width:100%;background:rgba(0,0,0,.28);color:var(--ink);border:1px solid var(--border);border-radius:10px;padding:11px 12px;font:13px/1.5 inherit;outline:none;resize:vertical;min-height:70px}
  #nbinput::placeholder{color:var(--muted)}
  #nbinput:focus{border-color:var(--accent);box-shadow:var(--ring)}
  .nbf{display:flex;justify-content:flex-end;gap:8px;margin-top:12px}
  .nbf .b{border:1px solid var(--border);padding:8px 15px;font-size:12px;font-weight:550;cursor:pointer}
  .nbf .nbcancel:hover{background:rgba(255,255,255,.08)}
  .nbf .nbsave{background:linear-gradient(135deg,var(--accent),var(--accent2));border-color:transparent;color:#fff}
  .nbf .nbsave:hover{filter:brightness(1.08)}
  .nbf .nbsave:active{transform:scale(.97)}
</style>
</head>
<body>
<svg id="svg" xmlns="http://www.w3.org/2000/svg"></svg>
<div id="bar">
  <div class="brand"><span class="dot"></span>Recon Graph <small id="tgt"></small></div>
  <div class="cluster">
    <input class="b" id="search" type="text" placeholder="search…" autocomplete="off" spellcheck="false">
    <span class="vr"></span>
    <select class="b" id="fprio" title="Filter by priority">
      <option value="all">priority: all</option>
      <option value="CRITICAL">CRITICAL</option>
      <option value="HIGH">HIGH+</option>
      <option value="MEDIUM">MEDIUM+</option>
    </select>
    <select class="b" id="fstatus" title="Filter by status">
      <option value="all">status: all</option>
      <option value="test">testing</option>
      <option value="done">exploited</option>
      <option value="fail">failed</option>
      <option value="none">no status</option>
    </select>
    <span class="vr"></span>
    <button class="b" id="addnote">＋ Note</button>
    <button class="b" id="fit">Fit</button>
    <button class="b" id="lanes">Swimlanes</button>
    <button class="b" id="reset">Reset layout</button>
    <button class="b" id="hidden">Hidden (0)</button>
    <button class="b" id="report">Report</button>
    <button class="b" id="png">PNG</button>
  </div>
</div>
<div id="notebox" class="ovl"><div class="nbcard">
  <div class="nbh" id="nbtitle">New note</div>
  <textarea id="nbinput" rows="3" placeholder="Type a note…  (Enter to save, Esc to cancel)" spellcheck="false"></textarea>
  <div class="nbf"><button class="b nbcancel" id="nbcancel">Cancel</button><button class="b nbsave" id="nbsave">Save</button></div>
</div></div>
<div id="confirmbox" class="ovl"><div class="nbcard">
  <div class="nbh" id="cfmsg"></div>
  <div class="nbf"><button class="b nbcancel" id="cfno">Cancel</button><button class="b nbsave" id="cfyes">Confirm</button></div>
</div></div>
<div id="legend">
  <div class="lg"><span class="sw" style="background:#5b8def"></span> Target · <span class="sw" style="background:#7d8cff"></span> Subdomain · <span class="sw" style="background:#3a4250"></span> Port</div>
  <div class="lg"><span class="sw" style="background:#38b2c4"></span> Stack / DB</div>
  <div class="lg"><span class="sw" style="background:#d7263d"></span> CRITICAL · <span class="sw" style="background:#f46036"></span> HIGH · <span class="sw" style="background:#ffc857"></span> MED</div>
  <div class="lg"><span class="sw" style="background:#1f6d43"></span> Path · <span class="sw" style="background:#c9932b"></span> Auth-gated · <span class="sw" style="background:#232a38"></span> Other (hub)</div>
  <div class="hint">Drag background to pan, wheel to zoom, drag a node to move. Double-click for details. Right-click a node for status or to hide it; restore from "Hidden" in the toolbar. Right-click background for a note.</div>
</div>
<div id="menu" class="menu"></div>
<div id="drawer"><div class="dh"><div><div class="dt" id="drtitle"></div><div class="dsub" id="drsub"></div></div><button id="drclose">✕</button></div><div class="db" id="drbody"></div></div>
<script>
"use strict";
const SVGNS="http://www.w3.org/2000/svg";
const DATA=JSON.parse(document.getElementById("graph-data").textContent);
const TARGET=DATA.target, GRAPH=DATA.graph;
const LSKEY="fingerprint-graph:"+TARGET;
document.getElementById("tgt").textContent=TARGET;

const PRIORITY_COLORS={CRITICAL:"#d7263d",HIGH:"#f46036",MEDIUM:"#ffc857",LOW:"#2a9d8f"};
const TYPE_COLORS={target:"#5b8def",subdomain:"#7d8cff",port:"#3a4250",stack:"#38b2c4",db:"#7a49c9",waf:"#8a4a12",path:"#1f6d43",gated:"#c9932b",hub:"#232a38",vuln:"#3a4250"};
const TYPE_LABEL={target:"TARGET",subdomain:"SUBDOMAIN",port:"PORT",stack:"STACK",db:"DATABASE",waf:"WAF",path:"PATH",gated:"AUTH-GATED (30x/401/403)",hub:"HUB",vuln:"HYPOTHESIS"};

const byId={};GRAPH.nodes.forEach(n=>byId[n.id]=n);
const NBR={},OUTADJ={},INADJ={};GRAPH.nodes.forEach(n=>{NBR[n.id]=[];OUTADJ[n.id]=[];INADJ[n.id]=[];});
GRAPH.edges.forEach(e=>{if(NBR[e.from]&&NBR[e.to]){NBR[e.from].push(e.to);NBR[e.to].push(e.from);OUTADJ[e.from].push(e.to);INADJ[e.to].push(e.from);}});

let saved={pos:{},notes:[],status:{},hidden:{},collapsed:{},layout:"auto"};
try{const s=JSON.parse(localStorage.getItem(LSKEY));if(s){saved.pos=s.pos||{};saved.notes=s.notes||[];saved.status=s.status||{};saved.hidden=s.hidden||{};saved.collapsed=s.collapsed||{};saved.layout=s.layout||"auto";}}catch(e){}
let saveT=null;
function save(){clearTimeout(saveT);saveT=setTimeout(()=>{try{localStorage.setItem(LSKEY,JSON.stringify(saved));}catch(e){}},200);}

/* ---- layout: BFS depth columns + barycenter ordering (fewer crossings) ---- */
function computeLayout(){
  const outAdj={},inAdj={};
  GRAPH.nodes.forEach(n=>{outAdj[n.id]=[];inAdj[n.id]=[];});
  GRAPH.edges.forEach(e=>{if(outAdj[e.from]&&inAdj[e.to]){outAdj[e.from].push(e.to);inAdj[e.to].push(e.from);}});
  // BFS depth from target
  const depth={};const q=[];
  if(byId["target"]){depth["target"]=0;q.push("target");}
  while(q.length){const c=q.shift();outAdj[c].forEach(nx=>{if(depth[nx]===undefined){depth[nx]=depth[c]+1;q.push(nx);}});}
  GRAPH.nodes.forEach(n=>{if(depth[n.id]===undefined)depth[n.id]=0;});
  const maxD=Math.max(0,...GRAPH.nodes.map(n=>depth[n.id]));
  const cols=[];for(let d=0;d<=maxD;d++)cols[d]=[];
  GRAPH.nodes.forEach(n=>cols[depth[n.id]].push(n));
  const pos={};cols.forEach(col=>col.forEach((n,i)=>pos[n.id]=i));
  // barycenter sweeps: order each column by the mean position of its neighbours
  function sweep(dir){ // dir=+1 uses parents (in), -1 uses children (out)
    const from=dir>0?1:maxD-1, to=dir>0?maxD:0;
    for(let d=from; dir>0?d<=to:d>=to; d+=dir){
      const adj=dir>0?inAdj:outAdj;
      cols[d].forEach(n=>{const nb=adj[n.id];n._bc=nb.length?nb.reduce((s,id)=>s+pos[id],0)/nb.length:pos[n.id];});
      cols[d].sort((a,b)=>a._bc-b._bc);
      cols[d].forEach((n,i)=>pos[n.id]=i);
    }
  }
  for(let it=0;it<4;it++){sweep(1);sweep(-1);}
  const COLGAP=340,ROWGAP=72;
  cols.forEach((col,d)=>{const total=(col.length-1)*ROWGAP;
    col.forEach((n,i)=>{n.x=d*COLGAP;n.y=-total/2+i*ROWGAP;delete n._bc;});});
}
/* ---- layout: swimlanes (one horizontal lane per host) ---- */
function computeLayoutSwimlanes(){
  const depth={},q=[];
  if(byId["target"]){depth["target"]=0;q.push("target");}
  while(q.length){const c=q.shift();(OUTADJ[c]||[]).forEach(nx=>{if(depth[nx]===undefined){depth[nx]=depth[c]+1;q.push(nx);}});}
  GRAPH.nodes.forEach(n=>{if(depth[n.id]===undefined)depth[n.id]=1;});
  const lane={},q2=[];
  if(byId["target"]){lane["target"]="__root__";q2.push("target");}
  while(q2.length){const c=q2.shift();(OUTADJ[c]||[]).forEach(nx=>{if(lane[nx]!==undefined)return;
    lane[nx]=(byId[nx]&&byId[nx].type==="subdomain")?nx:lane[c];q2.push(nx);});}
  GRAPH.nodes.forEach(n=>{if(lane[n.id]===undefined)lane[n.id]="__root__";});
  const laneKeys=["__root__"];
  GRAPH.nodes.filter(n=>n.type==="subdomain").sort((a,b)=>String(a.label).localeCompare(String(b.label))).forEach(s=>laneKeys.push(s.id));
  const COLGAP=320,ROWGAP=66,LANEGAP=64;
  let y=0;
  laneKeys.forEach(k=>{
    const nodes=GRAPH.nodes.filter(n=>lane[n.id]===k&&n.id!=="target");
    if(!nodes.length)return;
    const cols={};nodes.forEach(n=>{(cols[depth[n.id]]=cols[depth[n.id]]||[]).push(n);});
    let maxRows=1;for(const d in cols)maxRows=Math.max(maxRows,cols[d].length);
    const laneH=(maxRows-1)*ROWGAP;
    for(const d in cols){const arr=cols[d],total=(arr.length-1)*ROWGAP;
      arr.forEach((n,i)=>{n.x=(+d)*COLGAP;n.y=y+i*ROWGAP+(laneH-total)/2;});}
    y+=laneH+LANEGAP;
  });
  if(byId["target"]){byId["target"].x=0;byId["target"].y=(y-LANEGAP)/2;}
}
function doLayout(){if(saved.layout==="lanes")computeLayoutSwimlanes();else computeLayout();}
doLayout();
GRAPH.nodes.forEach(n=>{const p=saved.pos[n.id];if(p){n.x=p.x;n.y=p.y;}});

/* ---- SVG ---- */
const svg=document.getElementById("svg");
const defs=document.createElementNS(SVGNS,"defs");
defs.innerHTML='<marker id="arr" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="var(--edge)"/></marker>';
const gEdges=document.createElementNS(SVGNS,"g"),gNodes=document.createElementNS(SVGNS,"g"),gNotes=document.createElementNS(SVGNS,"g");
svg.append(defs,gEdges,gNodes,gNotes);
function el(t,a){const e=document.createElementNS(SVGNS,t);if(a)for(const k in a)e.setAttribute(k,a[k]);return e;}
function esc(s){return String(s).replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));}

let nodeEls={},edgeEls=[];
function colorFor(n){return n.color||PRIORITY_COLORS[n.priority]||TYPE_COLORS[n.type]||"#3a4250";}

function renderNodes(){
  gNodes.innerHTML="";nodeEls={};
  GRAPH.nodes.forEach(n=>{
    const g=el("g",{class:"node","data-id":n.id,transform:`translate(${n.x},${n.y})`});
    const fill=colorFor(n);
    const lines=String(n.label).split("\n"),fs=n.type==="target"?14:12,lh=fs+4,y0=-(lines.length-1)*lh/2,texts=[];
    lines.forEach((ln,i)=>{const t=el("text",{x:0,y:y0+i*lh,"text-anchor":"middle",fill:"#fff"});t.style.fontSize=fs+"px";t.textContent=ln;g.appendChild(t);texts.push(t);});
    gNodes.appendChild(g);
    let mx=30;texts.forEach(t=>{try{mx=Math.max(mx,t.getComputedTextLength());}catch(e){}});
    const h=lines.length*lh+14,w=mx+26;
    n._hw=w/2;n._hh=h/2;
    const box=el("rect",{class:"box",x:-w/2,y:-h/2,width:w,height:h,rx:9,fill,stroke:"rgba(255,255,255,.35)"});
    g.insertBefore(box,g.firstChild);
    // status ring (outside the box) + glyph in the corner
    const ring=el("rect",{class:"statusring",x:-w/2-4,y:-h/2-4,width:w+8,height:h+8,rx:12});
    g.insertBefore(ring,g.firstChild);
    const glyph=el("text",{class:"statusglyph",x:w/2-2,y:-h/2+2,"text-anchor":"end","dominant-baseline":"hanging"});
    g.appendChild(glyph);
    const cg=el("text",{class:"collapseglyph",x:w/2-2,y:h/2-3,"text-anchor":"end"});
    g.appendChild(cg);
    g.addEventListener("pointerdown",e=>startDrag(n,e));
    g.addEventListener("dblclick",e=>{e.stopPropagation();openDrawer(n);});
    g.addEventListener("contextmenu",e=>{e.preventDefault();e.stopPropagation();openNodeMenu(n,e);});
    nodeEls[n.id]=g;
    applyStatus(n.id);
  });
}
const STATUS_GLYPH={test:"⋯",done:"✓",fail:"✗"};
function applyStatus(id){const g=nodeEls[id];if(!g)return;const st=saved.status[id];
  g.classList.remove("st-test","st-done","st-fail");
  const gl=g.querySelector(".statusglyph");
  if(st){g.classList.add("st-"+st);if(gl){gl.textContent=STATUS_GLYPH[st]||"";gl.setAttribute("fill",st==="done"?"#3fb950":st==="test"?"#58a6ff":"#8b949e");}}
  else if(gl){gl.textContent="";}}
function setStatus(id,st){if(st)saved.status[id]=st;else delete saved.status[id];applyStatus(id);save();}
function border(n,tx,ty){const dx=tx-n.x,dy=ty-n.y,hw=(n._hw||60)+4,hh=(n._hh||20)+4;
  if(!dx&&!dy)return{x:n.x,y:n.y};
  const t=Math.min(dx?hw/Math.abs(dx):1e9,dy?hh/Math.abs(dy):1e9);return{x:n.x+dx*t,y:n.y+dy*t};}
function curve(a,b){const p=border(a,b.x,b.y),q=border(b,a.x,a.y),c=Math.max(28,Math.abs(q.x-p.x)*0.4);
  return `M${p.x},${p.y} C${p.x+c},${p.y} ${q.x-c},${q.y} ${q.x},${q.y}`;}
function renderEdges(){
  gEdges.innerHTML="";edgeEls=[];
  GRAPH.edges.forEach(e=>{const a=byId[e.from],b=byId[e.to];if(!a||!b)return;
    const p=el("path",{class:"edge",d:curve(a,b),"marker-end":"url(#arr)"});gEdges.appendChild(p);edgeEls.push({p,a,b});});
}
function updateEdges(){edgeEls.forEach(o=>o.p.setAttribute("d",curve(o.a,o.b)));}

/* ---- drawer ---- */
const drawer=document.getElementById("drawer");
function row(k,v){return `<div class="row"><div class="k">${esc(k)}</div><div class="v">${v}</div></div>`;}
function openDrawer(n){
  document.getElementById("drtitle").textContent=String(n.label).replace(/\n/g," ");
  document.getElementById("drsub").textContent=TYPE_LABEL[n.type]||n.type;
  let h="";
  if(n.priority){const c=PRIORITY_COLORS[n.priority]||"#666";h+=row("Priority",`<span class="badge" style="background:${c}">${esc(n.priority)}</span>`);}
  if(n.confidence)h+=row("Confidence",esc(n.confidence));
  if(n.source)h+=row("Signal source",esc(n.source));
  if(n.note)h+=row("Signature note",esc(n.note));
  if(n.path)h+=row("Path",esc(n.path)+(n.status?" → "+esc(n.status):""));
  if(n.service)h+=row("Service",esc(n.service));
  if(n.type==="hub"&&n.paths){h+=row("Paths without a signature ("+n.paths.length+")",`<div class="plist">${n.paths.map(esc).join("<br>")}</div>`);}
  const stL={test:"testing",done:"exploited",fail:"failed"};
  const cst=saved.status[n.id];
  if(cst)h=row("Status",`<span class="badge" style="background:${cst==="done"?"#3fb950":cst==="test"?"#58a6ff":"#8b949e"}">${stL[cst]}</span>`)+h;
  if(!h)h=`<div class="v" style="color:var(--muted)">No additional data.</div>`;
  document.getElementById("drbody").innerHTML=h;
  drawer.classList.add("open");
}
document.getElementById("drclose").onclick=()=>drawer.classList.remove("open");

/* ---- pan / zoom ---- */
let vb={x:-400,y:-400,w:1600,h:1200};
function applyVB(){svg.setAttribute("viewBox",`${vb.x} ${vb.y} ${vb.w} ${vb.h}`);}
function contentBox(){let a=1e9,b=1e9,c=-1e9,d=-1e9;GRAPH.nodes.forEach(n=>{const hw=n._hw||60,hh=n._hh||20;a=Math.min(a,n.x-hw);c=Math.max(c,n.x+hw);b=Math.min(b,n.y-hh);d=Math.max(d,n.y+hh);});
  if(a>c)return{x:-400,y:-400,w:1600,h:1200};const pad=120;return{x:a-pad,y:b-pad,w:(c-a)+pad*2,h:(d-b)+pad*2};}
function fit(){const C=contentBox(),r=svg.getBoundingClientRect(),ar=r.width/r.height,car=C.w/C.h;vb={...C};
  if(ar>car){const nw=C.h*ar;vb.x=C.x-(nw-C.w)/2;vb.w=nw;}else{const nh=C.w/ar;vb.y=C.y-(nh-C.h)/2;vb.h=nh;}applyVB();}
svg.addEventListener("wheel",e=>{e.preventDefault();const r=svg.getBoundingClientRect();
  const mx=vb.x+(e.clientX-r.left)/r.width*vb.w,my=vb.y+(e.clientY-r.top)/r.height*vb.h;
  const f=e.deltaY>0?1.12:0.89,nw=Math.min(16000,Math.max(200,vb.w*f)),nh=nw*(vb.h/vb.w);
  vb.x=mx-(mx-vb.x)*(nw/vb.w);vb.y=my-(my-vb.y)*(nh/vb.h);vb.w=nw;vb.h=nh;applyVB();},{passive:false});
let pan=null;
svg.addEventListener("pointerdown",e=>{if(e.target.closest(".node")||e.target.closest(".note"))return;
  if(e.button===0){pan={x:e.clientX,y:e.clientY,vx:vb.x,vy:vb.y};svg.classList.add("panning");svg.setPointerCapture(e.pointerId);}});
svg.addEventListener("pointermove",e=>{if(!pan)return;const r=svg.getBoundingClientRect();
  vb.x=pan.vx-(e.clientX-pan.x)/r.width*vb.w;vb.y=pan.vy-(e.clientY-pan.y)/r.height*vb.h;applyVB();});
function endPan(){pan=null;svg.classList.remove("panning");}
svg.addEventListener("pointerup",endPan);svg.addEventListener("pointercancel",endPan);
function svgPt(cx,cy){const r=svg.getBoundingClientRect();return{x:vb.x+(cx-r.left)/r.width*vb.w,y:vb.y+(cy-r.top)/r.height*vb.h};}

/* ---- drag node ---- */
function startDrag(n,ev){if(ev.button!==0)return;ev.stopPropagation();
  const r=svg.getBoundingClientRect(),sx=ev.clientX,sy=ev.clientY,ox=n.x,oy=n.y;let moved=false;
  const g=nodeEls[n.id];g.classList.add("dragging");
  function mv(e){const dx=(e.clientX-sx)*(vb.w/r.width),dy=(e.clientY-sy)*(vb.h/r.height);
    n.x=ox+dx;n.y=oy+dy;if(Math.hypot(e.clientX-sx,e.clientY-sy)>3)moved=true;
    g.setAttribute("transform",`translate(${n.x},${n.y})`);updateEdges();}
  function up(){removeEventListener("pointermove",mv);removeEventListener("pointerup",up);g.classList.remove("dragging");
    if(moved){n.x=Math.round(n.x);n.y=Math.round(n.y);g.setAttribute("transform",`translate(${n.x},${n.y})`);updateEdges();
      saved.pos[n.id]={x:n.x,y:n.y};save();}}
  addEventListener("pointermove",mv);addEventListener("pointerup",up);}

/* ---- notes ---- */
let noteEls={};
function renderNotes(){gNotes.innerHTML="";noteEls={};saved.notes.forEach(l=>{
  const g=el("g",{class:"note","data-nid":l.id,transform:`translate(${l.x},${l.y})`});
  const t=el("text",{"text-anchor":"start","dominant-baseline":"hanging"});
  String(l.text).split("\n").forEach((ln,i)=>{const ts=el("tspan",{x:0,dy:i===0?0:18});ts.textContent=ln;t.appendChild(ts);});
  g.appendChild(t);g.addEventListener("pointerdown",e=>{if(e.button!==0)return;e.stopPropagation();dragNote(l,e);});
  g.addEventListener("dblclick",e=>{e.stopPropagation();editNote(l);});noteEls[l.id]=g;gNotes.appendChild(g);});}
function dragNote(l,ev){const r=svg.getBoundingClientRect(),sx=ev.clientX,sy=ev.clientY,ox=l.x,oy=l.y;let moved=false;
  function mv(e){const dx=(e.clientX-sx)*(vb.w/r.width),dy=(e.clientY-sy)*(vb.h/r.height);l.x=ox+dx;l.y=oy+dy;
    if(Math.hypot(e.clientX-sx,e.clientY-sy)>3)moved=true;noteEls[l.id].setAttribute("transform",`translate(${l.x},${l.y})`);}
  function up(){removeEventListener("pointermove",mv);removeEventListener("pointerup",up);if(moved){l.x=Math.round(l.x);l.y=Math.round(l.y);save();}}
  addEventListener("pointermove",mv);addEventListener("pointerup",up);}
/* ---- styled note input (replaces prompt) ---- */
const notebox=document.getElementById("notebox"),nbinput=document.getElementById("nbinput"),nbtitle=document.getElementById("nbtitle");
let nbCtx=null;
function openNoteBox(ctx){nbCtx=ctx;nbtitle.textContent=ctx.mode==="edit"?"Edit note":"New note";
  nbinput.value=ctx.mode==="edit"?ctx.note.text:"";notebox.classList.add("open");setTimeout(()=>{nbinput.focus();nbinput.select();},30);}
function closeNoteBox(){notebox.classList.remove("open");nbCtx=null;}
function commitNote(){if(!nbCtx)return;const t=nbinput.value.trim();
  if(nbCtx.mode==="add"){if(t)saved.notes.push({id:"n"+Date.now().toString(36),x:Math.round(nbCtx.x),y:Math.round(nbCtx.y),text:t});}
  else{if(t)nbCtx.note.text=t;else saved.notes=saved.notes.filter(x=>x!==nbCtx.note);}
  closeNoteBox();renderNotes();save();}
document.getElementById("nbsave").onclick=commitNote;
document.getElementById("nbcancel").onclick=closeNoteBox;
nbinput.addEventListener("keydown",e=>{if(e.key==="Enter"&&!e.shiftKey){e.preventDefault();commitNote();}else if(e.key==="Escape"){e.preventDefault();closeNoteBox();}});
notebox.addEventListener("pointerdown",e=>{if(e.target===notebox)closeNoteBox();});
function editNote(l){openNoteBox({mode:"edit",note:l});}
function addNoteAt(x,y){openNoteBox({mode:"add",x,y});}
document.getElementById("addnote").onclick=()=>addNoteAt(vb.x+vb.w/2,vb.y+vb.h/2);
svg.addEventListener("contextmenu",e=>{e.preventDefault();if(e.target.closest(".note"))return;const p=svgPt(e.clientX,e.clientY);addNoteAt(p.x,p.y);});

/* ---- node status menu ---- */
const menu=document.getElementById("menu");
function hideMenu(){menu.classList.remove("open");}
function openNodeMenu(n,ev){
  const cur=saved.status[n.id];
  const items=[["test","⋯ Testing"],["done","✓ Exploited"],["fail","✗ Failed"]];
  let h=`<div class="mhead">${esc(String(n.label).replace(/\n/g," "))}</div>`;
  items.forEach(([k,l])=>{h+=`<div class="mi" data-st="${k}">${cur===k?"● ":""}${l}</div>`;});
  if(cur)h+=`<div class="sep"></div><div class="mi" data-st="">— Clear status</div>`;
  const vulnKids=(OUTADJ[n.id]||[]).filter(c=>byId[c]&&byId[c].type==="vuln");
  if(vulnKids.length){
    h+=`<div class="sep"></div>`;
    h+=saved.collapsed[n.id]
      ? `<div class="mi" data-act="expand">⊕ Expand hypotheses</div>`
      : `<div class="mi" data-act="collapse">⊖ Collapse hypotheses (${vulnKids.length})</div>`;
  }
  if(n.type!=="target")h+=`<div class="sep"></div><div class="mi" data-act="hide">⊘ Hide node</div>`;
  menu.innerHTML=h;menu.classList.add("open");
  const mw=menu.offsetWidth,mh=menu.offsetHeight;
  menu.style.left=Math.min(ev.clientX,innerWidth-mw-8)+"px";
  menu.style.top=Math.min(ev.clientY,innerHeight-mh-8)+"px";
  menu.querySelectorAll(".mi").forEach(mi=>mi.onclick=()=>{
    const a=mi.dataset.act;
    if(a==="hide")setHidden(n.id,true);
    else if(a==="collapse")setCollapsed(n.id,true);
    else if(a==="expand")setCollapsed(n.id,false);
    else setStatus(n.id,mi.dataset.st||null);
    hideMenu();applyFilters();});
}
document.addEventListener("pointerdown",e=>{if(!e.target.closest("#menu")&&!e.target.closest(".node")&&!e.target.closest("#hidden"))hideMenu();});

/* ---- hide / restore nodes ---- */
const hiddenBtn=document.getElementById("hidden");
function setHidden(id,on){if(on)saved.hidden[id]=1;else delete saved.hidden[id];updateHiddenBtn();save();}
function setCollapsed(id,on){if(on)saved.collapsed[id]=1;else delete saved.collapsed[id];save();}
function updateHiddenBtn(){hiddenBtn.textContent="Hidden ("+Object.keys(saved.hidden).length+")";}
function openHiddenMenu(ev){
  const ids=Object.keys(saved.hidden);
  let h=`<div class="mhead">Hidden nodes (${ids.length})</div>`;
  if(!ids.length){h+=`<div class="mi" style="opacity:.55;cursor:default">nothing hidden</div>`;}
  else{ids.forEach(id=>{const nm=byId[id]?String(byId[id].label).replace(/\n/g," "):id;
      h+=`<div class="mi" data-rid="${esc(id)}">↩ ${esc(nm)}</div>`;});
    h+=`<div class="sep"></div><div class="mi" data-rall="1">↩ Restore all</div>`;}
  menu.innerHTML=h;menu.classList.add("open");
  const mw=menu.offsetWidth,mh=menu.offsetHeight;
  menu.style.left=Math.min(ev.clientX,innerWidth-mw-8)+"px";
  menu.style.top=Math.min(ev.clientY,innerHeight-mh-8)+"px";
  menu.querySelectorAll(".mi").forEach(mi=>mi.onclick=()=>{
    if(mi.dataset.rall){saved.hidden={};updateHiddenBtn();save();}
    else if(mi.dataset.rid!==undefined)setHidden(mi.dataset.rid,false);
    else return;
    hideMenu();applyFilters();});
}
hiddenBtn.onclick=e=>openHiddenMenu(e);

/* ---- search + filters ---- */
const searchEl=document.getElementById("search"),fprioEl=document.getElementById("fprio"),fstatusEl=document.getElementById("fstatus");
const PRIO_RANK={CRITICAL:0,HIGH:1,MEDIUM:2,LOW:3};
function nodeMatchesSearch(n,q){if(!q)return true;
  return (String(n.label)+" "+(n.path||"")+" "+(n.note||"")+" "+(n.source||"")).toLowerCase().includes(q);}
function nodeMatchesPrio(n,f){if(f==="all")return true;
  // priority filter applies only to hypothesis nodes; structural nodes stay visible
  if(n.priority===undefined)return true;
  return PRIO_RANK[n.priority]<=PRIO_RANK[f];}
function nodeMatchesStatus(n,f){if(f==="all")return true;const st=saved.status[n.id];
  return f==="none"?!st:st===f;}
function effectiveHidden(withCollapse){
  if(withCollapse===undefined)withCollapse=true;
  const H=Object.assign({},saved.hidden);
  const C=withCollapse?(saved.collapsed||{}):{};
  let changed=true;
  while(changed){changed=false;
    GRAPH.nodes.forEach(n=>{
      if(H[n.id]||(n.type!=="vuln"&&n.type!=="db"))return;
      const ns=NBR[n.id]||[];
      const parents=INADJ[n.id]||[];
      const orphan=ns.length&&ns.every(x=>H[x]);
      const collapsed=parents.length&&parents.every(p=>H[p]||C[p]);
      if(orphan||collapsed){H[n.id]=1;changed=true;}
    });}
  return H;
}
function applyFilters(){
  const q=searchEl.value.trim().toLowerCase(),fp=fprioEl.value,fs=fstatusEl.value;
  const H=effectiveHidden();const vis={};
  GRAPH.nodes.forEach(n=>{
    const hid=!!H[n.id];
    const searchOn=q?nodeMatchesSearch(n,q):true;
    const show=!hid&&searchOn&&nodeMatchesPrio(n,fp)&&nodeMatchesStatus(n,fs);
    vis[n.id]=show;const g=nodeEls[n.id];if(!g)return;
    g.classList.toggle("hidden",hid);
    g.classList.toggle("dim",!hid&&!show);
    g.classList.toggle("match",!!q&&!hid&&searchOn);
    const cg=g.querySelector(".collapseglyph");
    if(cg){
      if(!hid&&saved.collapsed[n.id]){
        const kids=(OUTADJ[n.id]||[]).filter(c=>byId[c]&&byId[c].type==="vuln");
        cg.textContent="+"+kids.length;cg.style.display="block";
      }else{cg.textContent="";cg.style.display="none";}
    }
  });
  edgeEls.forEach(o=>{const hid=!!(H[o.a.id]||H[o.b.id]);
    o.p.classList.toggle("hidden",hid);
    o.p.classList.toggle("dim",!hid&&!(vis[o.a.id]&&vis[o.b.id]));});
}
searchEl.addEventListener("input",applyFilters);
fprioEl.addEventListener("change",applyFilters);
fstatusEl.addEventListener("change",applyFilters);

/* ---- confirm modal (replaces native confirm) ---- */
const confirmbox=document.getElementById("confirmbox"),cfmsg=document.getElementById("cfmsg");
let cfYes=null;
function askConfirm(msg,onYes){cfmsg.textContent=msg;cfYes=onYes;confirmbox.classList.add("open");}
function closeConfirm(){confirmbox.classList.remove("open");cfYes=null;}
document.getElementById("cfyes").onclick=()=>{const f=cfYes;closeConfirm();if(f)f();};
document.getElementById("cfno").onclick=closeConfirm;
confirmbox.addEventListener("pointerdown",e=>{if(e.target===confirmbox)closeConfirm();});

/* ---- PNG export ---- */
function exportPNG(){
  const C=contentBox(),scale=2;
  const clone=svg.cloneNode(true);
  clone.setAttribute("viewBox",`${C.x} ${C.y} ${C.w} ${C.h}`);
  clone.setAttribute("width",C.w);clone.setAttribute("height",C.h);
  clone.querySelectorAll("marker path").forEach(p=>p.setAttribute("fill","#46536a"));
  const st=document.createElementNS(SVGNS,"style");
  st.textContent="text{font-family:-apple-system,Segoe UI,Roboto,Arial,sans-serif;font-weight:600}"
    +".edge{fill:none;stroke:#46536a;stroke-width:1.5px}.edge.dim{opacity:.06}.node.dim{opacity:.12}"
    +".node.hidden,.edge.hidden{display:none}"
    +".node .box{stroke-width:1.7px}"
    +".node .statusring{display:none;fill:none;stroke-width:3px}"
    +".node.st-test .statusring{display:block;stroke:#58a6ff}.node.st-done .statusring{display:block;stroke:#3fb950}.node.st-fail .statusring{display:block;stroke:#8b949e;stroke-dasharray:4 3}"
    +".node .statusglyph{display:none;paint-order:stroke;stroke:#0b0e14;stroke-width:3px}"
    +".node.st-test .statusglyph,.node.st-done .statusglyph,.node.st-fail .statusglyph{display:block}"
    +".note text{fill:#e8eef6;paint-order:stroke;stroke:#0b0e14;stroke-width:3px}";
  clone.insertBefore(st,clone.firstChild);
  const bg=el("rect",{x:C.x,y:C.y,width:C.w,height:C.h,fill:"#0b0e14"});
  clone.insertBefore(bg,clone.firstChild);
  const xml=new XMLSerializer().serializeToString(clone),img=new Image();
  img.onload=()=>{const cv=document.createElement("canvas");cv.width=Math.round(C.w*scale);cv.height=Math.round(C.h*scale);
    const ctx=cv.getContext("2d");ctx.scale(scale,scale);ctx.drawImage(img,0,0);
    cv.toBlob(b=>{const a=document.createElement("a");a.href=URL.createObjectURL(b);
      a.download="recon-graph-"+TARGET.replace(/[^a-z0-9.-]/gi,"_")+".png";a.click();
      setTimeout(()=>URL.revokeObjectURL(a.href),1000);},"image/png");};
  img.onerror=()=>alert("PNG export failed");
  img.src="data:image/svg+xml;charset=utf-8,"+encodeURIComponent(xml);
}

/* ---- markdown report + kill chain ---- */
function mdEsc(s){return String(s).replace(/\n/g," ").replace(/\|/g,"\\|").trim();}
function bfsTree(){
  const depth={},pred={},q=[];
  if(byId["target"]){depth["target"]=0;q.push("target");}
  while(q.length){const c=q.shift();(OUTADJ[c]||[]).forEach(nx=>{if(depth[nx]===undefined){depth[nx]=depth[c]+1;pred[nx]=c;q.push(nx);}});}
  return {depth,pred};
}
function breadcrumb(id,pred){const parts=[];let c=id,guard=0;
  while(c!==undefined&&guard++<60){parts.unshift(mdEsc(byId[c]?byId[c].label:c));c=pred[c];}
  return parts.join(" → ");}
const STATUS_WORD={test:"testing",done:"exploited",fail:"failed"};
function exportMarkdown(){
  const H=effectiveHidden(false);                       // keep collapsed nodes, drop only hidden ones
  const {depth,pred}=bfsTree();
  let md="# Recon report — "+TARGET+"\n\n_generated "+new Date().toISOString().slice(0,16).replace("T"," ")+" UTC_\n";

  const exploited=GRAPH.nodes.filter(n=>saved.status[n.id]==="done"&&!H[n.id])
    .sort((a,b)=>(depth[a.id]||0)-(depth[b.id]||0));
  if(exploited.length){
    md+="\n## Kill chain\n\n";
    exploited.forEach((n,i)=>{md+=(i+1)+". "+breadcrumb(n.id,pred)+"\n";});
  }

  md+="\n## Findings\n";
  GRAPH.nodes.filter(n=>n.type==="port"&&!H[n.id]).forEach(port=>{
    const parent=(INADJ[port.id]||[])[0];
    const host=parent&&byId[parent]?(byId[parent].host||mdEsc(byId[parent].label).split(" ")[0]):TARGET;
    const kids=(OUTADJ[port.id]||[]).map(id=>byId[id]).filter(Boolean);
    const stacks=kids.filter(k=>k.type==="stack"&&!H[k.id]).map(k=>mdEsc(k.label));
    md+="\n### "+host+":"+mdEsc(port.label).split(" ")[0]+(stacks.length?"  — "+stacks.join(", "):"")+"\n\n";
    const seen={};
    kids.filter(k=>k.type==="stack").forEach(st=>{(OUTADJ[st.id]||[]).forEach(vid=>{
      const v=byId[vid];if(v&&v.type==="vuln"&&!H[vid]&&!seen[v.label]){seen[v.label]=1;
        md+="- "+(v.priority?"**"+v.priority+"** ":"")+mdEsc(v.label)+"\n";}});});
    kids.filter(k=>(k.type==="path"||k.type==="gated")&&!H[k.id]).forEach(p=>{
      const st=saved.status[p.id];
      const hyps=(OUTADJ[p.id]||[]).filter(id=>!H[id]).map(id=>byId[id]).filter(v=>v&&v.type==="vuln").map(v=>mdEsc(v.label));
      let line="- "+(st?"**["+STATUS_WORD[st]+"]** ":"")+"`"+mdEsc(p.path||p.label)+"`"+(p.status?" → "+mdEsc(String(p.status)):"");
      if(hyps.length)line+="  — "+hyps.join(" · ");
      md+=line+"\n";});
    kids.filter(k=>k.type==="hub"&&!H[k.id]).forEach(hb=>{md+="- _"+mdEsc(hb.label)+"_\n";});
  });

  if(saved.notes&&saved.notes.length){
    md+="\n## Notes\n\n";saved.notes.forEach(nt=>{md+="- "+mdEsc(nt.text)+"\n";});
  }

  const blob=new Blob([md],{type:"text/markdown"});
  const a=document.createElement("a");a.href=URL.createObjectURL(blob);
  a.download="recon-report-"+TARGET.replace(/[^a-z0-9.-]/gi,"_")+".md";a.click();
  setTimeout(()=>URL.revokeObjectURL(a.href),1000);
}

/* ---- controls ---- */
document.getElementById("fit").onclick=fit;
document.getElementById("png").onclick=exportPNG;
document.getElementById("report").onclick=exportMarkdown;
document.getElementById("reset").onclick=()=>askConfirm("Reset node layout? Notes and statuses are kept.",()=>{
  saved.pos={};doLayout();renderNodes();renderEdges();applyFilters();fit();save();});
const lanesBtn=document.getElementById("lanes");
function updateLanesBtn(){lanesBtn.textContent=saved.layout==="lanes"?"Auto layout":"Swimlanes";}
lanesBtn.onclick=()=>{saved.layout=saved.layout==="lanes"?"auto":"lanes";updateLanesBtn();
  saved.pos={};doLayout();renderNodes();renderEdges();applyFilters();fit();save();};
addEventListener("resize",fit);

/* ---- init ---- */
updateLanesBtn();
renderNodes();renderEdges();renderNotes();updateHiddenBtn();applyFilters();fit();
</script>
</body>
</html>
"""
