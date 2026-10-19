//! Replay agent requests against an Init-Data policy using the kata-agent's policy crate.
//!
//! Usage: `kata-policy-eval <policy.rego>`; stdin carries one JSON object per line,
//! `{"kind": "<AgentService request message>", "request": {...}}`, and stdout answers one
//! JSON object per line, `{"kind", "allowed", "error", "prints"}`. The first stdout line
//! describes the evaluator itself. Policy state (`pstate`) persists for the process lifetime,
//! exactly like one guest agent lifetime.
//!
//! Every request is deserialized into the agent's protobuf type (missing fields take protobuf
//! defaults) and serialized back the way `kata-agent` does before `allow_request`, so the policy
//! sees the same input it would see in the guest. No policy logic lives here.
use std::io::{self, BufRead, Write};

use anyhow::{anyhow, bail, Context, Result};
use kata_agent_policy::policy::{AgentPolicy, PolicyCopyFileRequest};
use protocols::agent as pb;
use serde::Deserialize;
use serde_json::{json, Value};

const KATA_REVISION: &str = "cf82bb35c80320178bf7570252fe75d6fb263209";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Case {
    kind: String,
    request: Value,
}

macro_rules! via {
    ($request:expr, $type:ty) => {{
        let typed: $type = serde_json::from_value($request).context("request does not match the agent message")?;
        serde_json::to_string(&typed)?
    }};
}

/// Serialize the request exactly as `kata-agent` does in `rpc.rs` before policy evaluation.
fn agent_input(kind: &str, request: Value) -> Result<String> {
    Ok(match kind {
        "AllowRequestsFailingPolicy" => {
            if request != json!({}) {
                bail!("AllowRequestsFailingPolicy takes an empty request");
            }
            "{}".to_string()
        }
        "CopyFileRequest" => {
            let typed: pb::CopyFileRequest = serde_json::from_value(request)?;
            let policy_request = PolicyCopyFileRequest::try_from(&typed).map_err(|e| anyhow!("{e}"))?;
            serde_json::to_string(&policy_request)?
        }
        "AddARPNeighborsRequest" => via!(request, pb::AddARPNeighborsRequest),
        "AddSwapPathRequest" => via!(request, pb::AddSwapPathRequest),
        "AddSwapRequest" => via!(request, pb::AddSwapRequest),
        "CloseStdinRequest" => via!(request, pb::CloseStdinRequest),
        "CreateContainerRequest" => via!(request, pb::CreateContainerRequest),
        "CreateSandboxRequest" => via!(request, pb::CreateSandboxRequest),
        "DestroySandboxRequest" => via!(request, pb::DestroySandboxRequest),
        "ExecProcessRequest" => via!(request, pb::ExecProcessRequest),
        "GetDiagnosticDataRequest" => via!(request, pb::GetDiagnosticDataRequest),
        "GetIPTablesRequest" => via!(request, pb::GetIPTablesRequest),
        "GetMetricsRequest" => via!(request, pb::GetMetricsRequest),
        "GetOOMEventRequest" => via!(request, pb::GetOOMEventRequest),
        "GuestDetailsRequest" => via!(request, pb::GuestDetailsRequest),
        "ListInterfacesRequest" => via!(request, pb::ListInterfacesRequest),
        "ListRoutesRequest" => via!(request, pb::ListRoutesRequest),
        "MemAgentCompactConfig" => via!(request, pb::MemAgentCompactConfig),
        "MemAgentMemcgConfig" => via!(request, pb::MemAgentMemcgConfig),
        "MemHotplugByProbeRequest" => via!(request, pb::MemHotplugByProbeRequest),
        "OnlineCPUMemRequest" => via!(request, pb::OnlineCPUMemRequest),
        "PauseContainerRequest" => via!(request, pb::PauseContainerRequest),
        "ReadStreamRequest" => via!(request, pb::ReadStreamRequest),
        "RemoveContainerRequest" => via!(request, pb::RemoveContainerRequest),
        "RemoveStaleVirtiofsShareMountsRequest" => via!(request, pb::RemoveStaleVirtiofsShareMountsRequest),
        "ReseedRandomDevRequest" => via!(request, pb::ReseedRandomDevRequest),
        "ResizeVolumeRequest" => via!(request, pb::ResizeVolumeRequest),
        "ResumeContainerRequest" => via!(request, pb::ResumeContainerRequest),
        "SetGuestDateTimeRequest" => via!(request, pb::SetGuestDateTimeRequest),
        "SetIPTablesRequest" => via!(request, pb::SetIPTablesRequest),
        "SetPolicyRequest" => via!(request, pb::SetPolicyRequest),
        "SignalProcessRequest" => via!(request, pb::SignalProcessRequest),
        "StartContainerRequest" => via!(request, pb::StartContainerRequest),
        "StatsContainerRequest" => via!(request, pb::StatsContainerRequest),
        "TtyWinResizeRequest" => via!(request, pb::TtyWinResizeRequest),
        "UpdateContainerRequest" => via!(request, pb::UpdateContainerRequest),
        "UpdateEphemeralMountsRequest" => via!(request, pb::UpdateEphemeralMountsRequest),
        "UpdateInterfaceRequest" => via!(request, pb::UpdateInterfaceRequest),
        "UpdateRoutesRequest" => via!(request, pb::UpdateRoutesRequest),
        "VolumeStatsRequest" => via!(request, pb::VolumeStatsRequest),
        "WaitProcessRequest" => via!(request, pb::WaitProcessRequest),
        "WriteStreamRequest" => via!(request, pb::WriteStreamRequest),
        other => bail!("unsupported request kind: {other}"),
    })
}

fn emit(out: &mut impl Write, value: Value) -> Result<()> {
    serde_json::to_writer(&mut *out, &value)?;
    out.write_all(b"\n")?;
    out.flush()?;
    Ok(())
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let _guard = slog_scope::set_global_logger(slog::Logger::root(slog::Discard, slog::o!()));
    let path = std::env::args().nth(1).ok_or_else(|| anyhow!("usage: kata-policy-eval <policy.rego>"))?;
    if std::env::args().count() != 2 {
        bail!("usage: kata-policy-eval <policy.rego>");
    }
    let text = std::fs::read_to_string(&path).with_context(|| format!("cannot read {path}"))?;
    let mut policy = AgentPolicy::new();
    let stdout = io::stdout();
    let mut out = stdout.lock();
    if let Err(error) = policy.set_policy(&text).await {
        emit(&mut out, json!({"self": {"kata_revision": KATA_REVISION, "loaded": false, "error": error.to_string()}}))?;
        std::process::exit(2);
    }
    // Mirror AgentPolicy::update_allow_failures_flag: an undefined rule means the flag is off.
    let failing_allowed = match policy.allow_request("AllowRequestsFailingPolicy", "{}").await {
        Ok((allowed, _)) => allowed,
        Err(_) => false,
    };
    emit(&mut out, json!({"self": {"kata_revision": KATA_REVISION, "loaded": true,
                                   "allow_requests_failing_policy": failing_allowed}}))?;
    for (number, line) in io::stdin().lock().lines().enumerate() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let case: Case = match serde_json::from_str(&line) {
            Ok(case) => case,
            Err(error) => {
                emit(&mut out, json!({"line": number + 1, "allowed": null, "error": format!("invalid case: {error}"), "prints": ""}))?;
                continue;
            }
        };
        let verdict = match agent_input(&case.kind, case.request) {
            Err(error) => json!({"kind": case.kind, "allowed": null, "error": error.to_string(), "prints": ""}),
            Ok(input) => match policy.allow_request(&case.kind, &input).await {
                Ok((allowed, prints)) => json!({"kind": case.kind, "allowed": allowed, "error": null, "prints": prints, "input": input}),
                Err(error) => json!({"kind": case.kind, "allowed": null, "error": error.to_string(), "prints": ""}),
            },
        };
        emit(&mut out, verdict)?;
    }
    Ok(())
}
