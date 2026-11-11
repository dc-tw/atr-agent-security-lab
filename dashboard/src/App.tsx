import { FormEvent, ReactNode, useCallback, useEffect, useMemo, useState } from "react";
import { api, Auth, Finding, Policy } from "./api";

type Tab = "overview" | "findings" | "policy" | "approvals" | "evidence" | "rules" | "receipts" | "exports";
type Row = Record<string, unknown>;
type RuleStat = Row & {
  rule_id: string; severity: string; detections: number; blocked: number;
  false_positive_rate: number | null; recommended_for_blocking: boolean;
};

const tabs: Tab[] = ["overview", "findings", "policy", "approvals", "evidence", "rules", "receipts", "exports"];
const severities = ["informational", "low", "medium", "high", "critical"];
const boundaryActions: Record<string, string[]> = {
  request_input: ["detect", "block"], planner_output: ["detect", "block"],
  tool_call: ["detect", "block", "require_approval"],
  tool_response: ["detect", "block", "quarantine"],
  model_output: ["detect", "block"],
};

export default function App() {
  const [tab, setTab] = useState<Tab>("overview");
  const [auth, setAuth] = useState<Auth>(() => ({
    kind: (sessionStorage.getItem("auth-kind") as Auth["kind"]) || "api-key",
    token: sessionStorage.getItem("auth-token") || "",
  }));
  const [connected, setConnected] = useState(false);
  const [error, setError] = useState("");
  const [findings, setFindings] = useState<Finding[]>([]);
  const [policy, setPolicy] = useState<Policy | null>(null);
  const [policies, setPolicies] = useState<Row[]>([]);
  const [stats, setStats] = useState<RuleStat[]>([]);
  const [rules, setRules] = useState<Row[]>([]);
  const [bundles, setBundles] = useState<Row[]>([]);
  const [receipts, setReceipts] = useState<Row[]>([]);
  const [verification, setVerification] = useState<{valid: boolean; count: number} | null>(null);
  const [sinks, setSinks] = useState<Row[]>([]);
  const [approvals, setApprovals] = useState<Row[]>([]);
  const [evidence, setEvidence] = useState<Row[]>([]);
  const [sinkType, setSinkType] = useState<"jsonl" | "webhook">("jsonl");
  const [sinkUrl, setSinkUrl] = useState("");
  const [sinkSecret, setSinkSecret] = useState("");

  const load = useCallback(async () => {
    if (!auth.token) return;
    setError("");
    try {
      const data = await Promise.all([
        api<{findings: Finding[]}>("/v1/security/threat-findings?limit=100", auth),
        api<Policy>("/v1/security/atr/policies/active", auth),
        api<{policies: Row[]}>("/v1/security/atr/policies", auth),
        api<{rules: RuleStat[]}>("/v1/security/threat-findings/stats/rules", auth),
        api<{rules: Row[]}>("/v1/security/atr/rules?limit=1000", auth),
        api<{bundles: Row[]}>("/v1/security/atr/rules/bundles", auth),
        api<{receipts: Row[]}>("/v1/security/atr/receipts?limit=100", auth),
        api<{valid: boolean; count: number}>("/v1/security/atr/receipts/verify", auth),
        api<{sinks: Row[]}>("/v1/security/atr/exports/sinks", auth),
        api<{approvals: Row[]}>("/v1/security/atr/approvals/pending", auth),
        api<{evidence: Row[]}>("/v1/security/atr/lab/evidence", auth),
      ]);
      setFindings(data[0].findings); setPolicy(data[1]); setPolicies(data[2].policies);
      setStats(data[3].rules); setRules(data[4].rules); setBundles(data[5].bundles);
      setReceipts(data[6].receipts); setVerification(data[7]); setSinks(data[8].sinks);
      setApprovals(data[9].approvals); setEvidence(data[10].evidence);
      setConnected(true);
    } catch (value) { setConnected(false); setError(String(value)); }
  }, [auth]);

  useEffect(() => { void load(); }, [load]);
  const mutate = async (path: string, method: string, body?: unknown) => {
    setError("");
    try {
      await api(path, auth, { method, body: body === undefined ? undefined : JSON.stringify(body) });
      await load();
    } catch (value) { setError(String(value)); }
  };
  const authenticate = (event: FormEvent) => {
    event.preventDefault(); sessionStorage.setItem("auth-kind", auth.kind);
    sessionStorage.setItem("auth-token", auth.token); void load();
  };
  const totals = useMemo(() => ({
    findings: stats.reduce((sum, row) => sum + row.detections, 0),
    blocked: stats.reduce((sum, row) => sum + row.blocked, 0),
    calibrated: stats.filter(row => row.false_positive_rate !== null).length,
  }), [stats]);

  if (!connected) return <main className="login-shell"><section className="login-card">
    <p className="eyebrow">AI OPERATIONS GATEWAY</p><h1>ATR Control Plane</h1>
    <p className="muted">Connect with a development API key or production OIDC access token.</p>
    <form onSubmit={authenticate}>
      <label>Credential type<select value={auth.kind} onChange={e => setAuth({...auth, kind: e.target.value as Auth["kind"]})}><option value="api-key">API key</option><option value="bearer">OIDC bearer</option></select></label>
      <label>Credential<input type="password" value={auth.token} onChange={e => setAuth({...auth, token: e.target.value})}/></label>
      <button>Connect</button>{error && <pre className="error">{error}</pre>}
    </form>
  </section></main>;

  return <div className="shell"><aside><div><p className="eyebrow">CONTROL PLANE</p><h2>ATR / Gateway</h2></div>
    <nav>{tabs.map(item => <button className={tab === item ? "active" : ""} onClick={() => setTab(item)} key={item}>{item}</button>)}</nav>
    <div className="status"><i/>Connected<button onClick={() => { sessionStorage.clear(); setConnected(false); }}>Disconnect</button></div></aside>
    <main><header><div><p className="eyebrow">TENANT SECURITY</p><h1>{tab}</h1></div><button className="secondary" onClick={() => void load()}>Refresh</button></header>
      {error && <pre className="error">{error}</pre>}
      {tab === "overview" && <><section className="metrics"><Metric label="Findings" value={totals.findings}/><Metric label="Enforced" value={totals.blocked}/><Metric label="Calibrated rules" value={totals.calibrated}/><Metric label="Receipt chain" value={verification?.valid ? "Valid" : "Invalid"}/></section><Panel title="Runtime posture"><dl><dt>Policy mode</dt><dd>{policy?.mode}</dd><dt>Policy version</dt><dd>{policy?.version}</dd><dt>Rule inventory</dt><dd>{rules.length}</dd><dt>Receipts</dt><dd>{verification?.count}</dd></dl></Panel></>}
      {tab === "findings" && <Panel title="Detection & calibration"><Table rows={findings} columns={["created_at","rule_id","severity","action","review_status"]} actions={row => <><button onClick={() => void mutate(`/v1/security/threat-findings/${row.finding_id}/review`, "POST", {verdict:"true_positive",reason:"Dashboard review"})}>True positive</button><button className="secondary" onClick={() => void mutate(`/v1/security/threat-findings/${row.finding_id}/review`, "POST", {verdict:"false_positive",reason:"Dashboard review"})}>False positive</button><button className="secondary" onClick={() => void mutate(`/v1/security/atr/findings/${row.finding_id}/exempt`, "POST", {reason:"Approved in Control Plane",valid_for_minutes:60})}>One-time exempt</button></>}/></Panel>}
      {tab === "policy" && policy && <><Panel title={`Active policy v${policy.version}`}><div className="policy-grid"><label>Mode<select value={policy.mode} onChange={e => setPolicy({...policy,mode:e.target.value as Policy["mode"]})}><option value="detection_only">Detection only</option><option value="blocking">Blocking</option></select></label></div><div className="table-wrap"><table><thead><tr><th>Boundary</th>{severities.map(severity => <th key={severity}>{severity}</th>)}</tr></thead><tbody>{Object.entries(boundaryActions).map(([boundary, actions]) => <tr key={boundary}><td>{boundary}</td>{severities.map(severity => <td key={severity}><select value={policy.boundary_action_map[boundary]?.[severity] ?? "detect"} onChange={e => setPolicy({...policy,boundary_action_map:{...policy.boundary_action_map,[boundary]:{...policy.boundary_action_map[boundary],[severity]:e.target.value}}})}>{actions.map(action => <option key={action}>{action}</option>)}</select></td>)}</tr>)}</tbody></table></div><button onClick={() => void mutate("/v1/security/atr/policies/active","PUT",policy)}>Publish new version</button></Panel><Panel title="Immutable policy history"><Table rows={policies} columns={["version","mode","created_by","created_at"]} actions={row => <button className="secondary" onClick={() => void mutate(`/v1/security/atr/policies/${row.version}/rollback`,"POST")}>Rollback as new version</button>}/></Panel></>}
      {tab === "approvals" && <Panel title="Pending ATR & tool approvals"><Table rows={approvals} columns={["updated_at","request_id","kind","tool","approval_id","policy_version"]}/></Panel>}
      {tab === "evidence" && <Panel title="ATR Lab run evidence"><Table rows={evidence} columns={["created_at","run_id","model","passed","scenario_count","bundle_checksum"]}/></Panel>}
      {tab === "rules" && <><Panel title="Active rule registry"><button onClick={() => void mutate("/v1/security/atr/rules/reload","POST")}>Atomic reload mounted bundle</button><Table rows={rules} columns={["rule_id","title","severity","status","condition_count"]}/></Panel><Panel title="Bundle history"><Table rows={bundles} columns={["version","checksum","rule_count","active","activated_at"]} actions={row => <button className="secondary" onClick={() => void mutate(`/v1/security/atr/rules/bundles/${row.bundle_id}/rollback`,"POST")}>Rollback</button>}/></Panel></>}
      {tab === "receipts" && <><Panel title="Chain verification"><p className={verification?.valid ? "good" : "error"}>{verification?.valid ? `Verified ${verification.count} chained receipts` : "Receipt chain failed verification"}</p></Panel><Panel title="Enforcement receipts"><Table rows={receipts} columns={["sequence","rule_id","decision","action","policy_version","created_at"]}/></Panel></>}
      {tab === "exports" && <Panel title="SIEM export sinks"><div className="sink-form"><label>Type<select value={sinkType} onChange={e => setSinkType(e.target.value as "jsonl"|"webhook")}><option value="jsonl">JSONL</option><option value="webhook">Signed webhook</option></select></label>{sinkType === "webhook" && <><label>HTTPS URL<input value={sinkUrl} onChange={e => setSinkUrl(e.target.value)} placeholder="https://siem.example/atr"/></label><label>Signing secret<input type="password" value={sinkSecret} onChange={e => setSinkSecret(e.target.value)}/></label></>}<button onClick={() => void mutate("/v1/security/atr/exports/sinks","POST",{sink_type:sinkType,url:sinkType === "webhook" ? sinkUrl : null,secret:sinkType === "webhook" ? sinkSecret : ""})}>Create sink</button></div><Table rows={sinks} columns={["sink_type","url","enabled","created_at"]} actions={row => <button className="secondary" onClick={() => void mutate(`/v1/security/atr/exports/sinks/${row.sink_id}`,"DELETE")}>Delete</button>}/></Panel>}
    </main></div>;
}

function Metric({label,value}:{label:string;value:string|number}) { return <article className="metric"><span>{label}</span><strong>{value}</strong></article>; }
function Panel({title,children}:{title:string;children:ReactNode}) { return <section className="panel"><h3>{title}</h3>{children}</section>; }
function Table({rows,columns,actions}:{rows:Row[];columns:string[];actions?:(row:Row)=>ReactNode}) { return <div className="table-wrap"><table><thead><tr>{columns.map(column => <th key={column}>{column}</th>)}{actions && <th>Actions</th>}</tr></thead><tbody>{rows.map((row,index) => <tr key={String(row.finding_id ?? row.receipt_id ?? row.bundle_id ?? row.rule_id ?? index)}>{columns.map(column => <td key={column}>{String(row[column] ?? "—")}</td>)}{actions && <td className="actions">{actions(row)}</td>}</tr>)}</tbody></table>{rows.length === 0 && <p className="empty">No records yet.</p>}</div>; }
