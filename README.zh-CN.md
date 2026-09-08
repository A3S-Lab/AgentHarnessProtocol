# 代理线束协议 (AHP) v2.4

<p>
  <strong>Language / 语言:</strong>
  <a href="README.md">English</a> ·
  <a href="README.zh-CN.md">中文</a>
</p>


**用于自主人工智能代理的与传输无关的监督协议。**

AHP 将代理执行与策略执行分开。代理发出结构化的
在有意义的控制点发生事件，线束评估这些事件，并且
代理在继续之前应用返回的决定。

第一个原则很简单：**起作用的组件不应该是唯一的
决定操作是否安全、有用、授权或
上下文良好。**

## 为什么存在层次分析法

代理框架公开不同的钩子系统、回调形状和传输
假设。这使得策略难以重用：

- 为一个框架编写的安全策略通常无法监督另一个框架。
- 审核、批准、内存和上下文逻辑在每个运行时都会重复。
- 操作控制与代理实现耦合。

AHP 定义了代理和工具之间的小型共享契约：

1. 代理在有意义的工作之前或之后发送事件。
2. 阻塞事件是JSON-RPC请求，必须收到决定。
3. 即发即忘事件是 JSON-RPC 通知，不会阻止执行。
4. 该工具拥有策略、丰富、批准、审计和背压逻辑。
5. 代理人负责执行退回的决定。

## 设计原则

- **实现前的协议** — JSON-RPC 消息形状是契约；
  Rust 是一种实现。
- **传输独立性** — stdio、HTTP、WebSocket 和 Unix 套接字携带
  相同的协议语义。
- **控制路径失败关闭** — 批量决策中的处理程序失败变为
  `Block`决定，不是沉默允许的。
- **显式同步** — 阻塞事件使用请求；非阻塞
  遥测使用通知。
- **形状很重要的打字决策** - 背景、记忆、计划、
  推理、速率限制、确认、空闲和意图检测使用专门的
  决策有效负载。
- **持久运行时合约** — 运行生命周期、任务列表、验证和
  证据参考使用稳定的事件形状进行重放、UI 渲染和
  审计。
- **政策足够的通用决策** — 行动和提示门使用
  通用`Decision`形状。
- **首先进行能力协商** — 客户端在发送事件之前握手。
- **有界递归和批处理** - 线束配置可以限制事件
  深度和批量大小。

## 当前功能

- JSON-RPC 2.0 协议消息。
- 与主要版本兼容性检查握手。
- 具有 stdio、HTTP、WebSocket 和 Unix 套接字传输的 Rust 客户端。
- Rust 服务器调度请求和通知。
- HTTP 和 WebSocket 客户端的可选 API 密钥和不记名令牌身份验证。
- 传输超时配置。
- JSON-RPC 版本、请求 ID、错误和缺失的响应验证
  结果。
- 用于专门事件系列的类型化线束处理程序。
- 持久运行生命周期、任务列表和验证合同事件。
- 通用决策事件的批量请求。
- 用于广告线束信息和验证限制的服务器构建器方法。
- 完整事件客户端 API，可保留调用者提供的会话、代理、深度、
  上下文和元数据。
- HTTP 和 WebSocket Rust 示例在其传输功能背后进行门控。
- gRPC 功能占位符保留用于将来的实现。

## 协议版本

- 协议版本：`2.4`
- crate版本：`2.4.0`
- 生Rust的箱子：`a3s-ahp`
- 存储库：`https://github.com/A3S-Lab/AgentHarnessProtocol`

该crate可以在不更改协议版本的情况下接收补丁版本。一个
握手期间协议主版本不匹配被拒绝。

## 消息模型

AHP 使用 JSON-RPC 2.0。

### 阻止事件请求

```json
{
  "jsonrpc": "2.0",
  "id": "req-123",
  "method": "ahp/event",
  "params": {
    "event_type": "pre_action",
    "session_id": "sess-abc",
    "agent_id": "agent-xyz",
    "timestamp": "2026-05-01T00:00:00Z",
    "depth": 0,
    "payload": {
      "tool_name": "bash",
      "arguments": {
        "command": "cargo test"
      }
    }
  }
}
```

### 决策响应

```json
{
  "jsonrpc": "2.0",
  "id": "req-123",
  "result": {
    "decision": "allow"
  }
}
```

### 即发即忘通知

```json
{
  "jsonrpc": "2.0",
  "method": "ahp/event",
  "params": {
    "event_type": "post_action",
    "session_id": "sess-abc",
    "agent_id": "agent-xyz",
    "timestamp": "2026-05-01T00:00:02Z",
    "depth": 0,
    "payload": {
      "status": "ok"
    }
  }
}
```

## 方法

|方法|方向 |目的|
| ---| ---| ---|
| `ahp/handshake` |代理驾驭|协商协议兼容性、功能和利用限制。 |
| `ahp/event` |代理驾驭|根据事件类型将一个事件作为请求或通知发送。 |
| `ahp/query` |代理驾驭|向线束询问额外信息。 |
| `ahp/batch` |代理驾驭|在一个请求中发送多个通用决策事件。 |

## 事件类型

|活动 |时间 |封锁|决策形状|可批量|
| ---| ---| ---| ---| ---|
| `pre_action` |在执行工具/操作之前 |是的 | `Decision` |是的 |
| `post_action` |工具/操作完成后 |没有 |通知 |是的 |
| `pre_prompt` |在申请LLM之前|是的 | `Decision` |是的 |
| `post_response` |法学硕士回应后|没有 |通知 |是的 |
| `session_start` |会议开始 |没有 |通知 |是的 |
| `session_end` |会议结束 |没有 |通知 |是的 |
| `error` |操作失败 |没有 |通知 |是的 |
| `heartbeat` |定期活跃度/状态 |没有 |通知 |是的 |
| `success` |操作成功 |没有 |通知 |是的 |
| `idle` |代理询问是否应该运行后台工作 |是的 | `IdleDecision` |没有 |
| `intent_detection` |在更深入的上下文工作之前对用户意图进行分类 |是的 | `IntentDetectionDecision` |没有 |
| `context_perception` |检索或注入工作区上下文 |是的 | `ContextPerceptionDecision` |没有 |
| `memory_recall` |从记忆中检索事实 |是的 | `MemoryRecallDecision` |没有 |
| `planning` |选择或修改规划策略|是的 | `PlanningDecision` |没有 |
| `reasoning` |提供推理提示或块推理 |是的 | `ReasoningDecision` |没有 |
| `rate_limit` |达到限制后确定背压 |是的 | `RateLimitDecision` |没有 |
| `confirmation` |请求批准、拒绝或升级 |是的 | `ConfirmationDecision` |没有 |
| `run_lifecycle` |持久运行状态转换 |没有 |通知 |是的 |
| `task_list` |权威任务列表快照|没有 |通知 |是的 |
| `verification` |验证状态和证据快照 |没有 |通知 |是的 |

出于分类目的，`handshake` 和 `query` 在 `EventType` 中表示，
但普通客户应使用专用的`ahp/handshake`和`ahp/query`
方法。

## 持久运行时合约

AHP v2.4 添加了非阻塞运行时合约事件。这些活动都是精心设计的
用于主管、仪表板、重播系统和审核日志。他们不取代
策略挂钩，例如`pre_action`；相反，它们提供稳定状态快照
可以通过更丰富的运行时特定事件流来减少。

### 运行生命周期

`run_lifecycle` 记录单个代理运行的持久状态转换。

```json
{
  "event_type": "run_lifecycle",
  "session_id": "sess-abc",
  "agent_id": "agent-xyz",
  "timestamp": "2026-05-01T00:00:00Z",
  "depth": 0,
  "payload": {
    "run_id": "run-123",
    "session_id": "sess-abc",
    "status": "executing",
    "prompt": "fix the failing tests",
    "started_at": "2026-05-01T00:00:00Z",
    "updated_at": "2026-05-01T00:00:01Z"
  }
}
```

支持的 `RunStatus` 值为 `created`、`planning`、`executing`、
`verifying`、`completed`、`failed` 和 `cancelled`。

### 任务列表

`task_list` 发送当前任务图的权威快照。它是
对于需要类似 Codex 的任务跟踪而不知道发出的 UI 非常有用
运行时的私有事件模型。

```json
{
  "event_type": "task_list",
  "session_id": "sess-abc",
  "agent_id": "agent-xyz",
  "timestamp": "2026-05-01T00:00:02Z",
  "depth": 0,
  "payload": {
    "run_id": "run-123",
    "session_id": "sess-abc",
    "updated_at": "2026-05-01T00:00:02Z",
    "tasks": [
      {
        "id": "step-1",
        "title": "Inspect failing test",
        "status": "completed",
        "evidence": [
          {
            "kind": "log",
            "summary": "cargo test reproduced the failure"
          }
        ]
      }
    ]
  }
}
```

支持的 `TaskStatus` 值为 `pending`、`in_progress`、`completed`、
`failed`、`skipped`、`cancelled`。

### 确认

`verification` 报告验证状态、检查、工件和残留风险
跑步。

```json
{
  "event_type": "verification",
  "session_id": "sess-abc",
  "agent_id": "agent-xyz",
  "timestamp": "2026-05-01T00:00:03Z",
  "depth": 0,
  "payload": {
    "run_id": "run-123",
    "session_id": "sess-abc",
    "status": "passed",
    "updated_at": "2026-05-01T00:00:03Z",
    "checks": [
      {
        "id": "cargo-test",
        "subject": "Rust workspace tests",
        "status": "passed",
        "command": "cargo test --all-features"
      }
    ],
    "residual_risks": []
  }
}
```

支持的 `VerificationStatus` 值为 `pending`、`running`、`passed`、
`failed`、`skipped`、`needs_review`。

即使这些有效负载作为通知到达，服务器也会验证它们。不好
运行时合约有效负载被拒绝，而不是被默默接受。

## 决策形状

### 通用`Decision`

通用决策由普通操作和提示门使用。

|决定|意义|
| ---| ---|
| `allow` |继续，可以选择使用元数据或修改后的有效负载。 |
| `block` |停止并返回一个原因。 |
| `modify` |继续修改线束参数。 |
| `defer` |稍后重试。 |
| `escalate` |转发至人工或外部批准路径。 |

### 专门决策

一些线束点需要比通用允许/阻止更丰富的返回类型：

- `IdleDecision` 可以允许或推迟空闲/后台工作。
- `IntentDetectionDecision` 返回检测到的意图、置信度和目标
  提示。
- `ContextPerceptionDecision` 注入事实、文件片段、项目摘要、
  知识或建议。
- `MemoryRecallDecision` 注入回忆事实。
- `PlanningDecision` 选择计划策略或修改任务。
- `ReasoningDecision` 返回推理提示或阻止推理。
- `RateLimitDecision` 重试、排队或跳过。
- `ConfirmationDecision` 批准、拒绝或升级。

特殊事件必须通过 `send_typed_event` 或
等效的 JSON-RPC 调用。它们被有意排除在批量请求之外
因为批量响应包含`Vec<Decision>`。

## 客户端生命周期

1. 创建一个带有传输的 `AhpClient`。
2. 运行带有代理功能的`handshake`。
3. 使用`send_event_decision`或`send_typed_event`发送阻塞事件。
4. 使用 `send_event_full`、`send_event_full_value` 或发送预建事件
   `send_typed_event_full` 当调用者需要保留上下文并且
   元数据。
5. 通过`send_event`发送即发即弃事件以实现非阻塞事件
   类型。
6. 仅将 `send_batch` 用于通用决策事件类型。
7. 完成后关闭客户端。

Rust 客户端验证：

- JSON-RPC 版本是`2.0`。
- 响应 ID 与请求 ID 匹配。
- 错误响应变为`AhpError::Protocol`。
- 缺失的结果将被拒绝。
- 事件和批次需要完成握手。
- 批量响应决策计数必须与请求事件计数匹配。
- 完整事件 API 保留调用者提供的会话、代理、深度、上下文和
  元数据。

## Rust 客户端示例

```rust
use a3s_ahp::{AhpClient, Decision, EventType, Transport};

async fn run_agent() -> a3s_ahp::Result<()> {
    let client = AhpClient::new(Transport::Stdio {
        program: "python3".into(),
        args: vec!["harness.py".into()],
    })
    .await?;

    client
        .handshake(vec![
            "pre_action".to_string(),
            "post_action".to_string(),
        ])
        .await?;

    let decision = client
        .send_event_decision(
            EventType::PreAction,
            serde_json::json!({
                "tool_name": "bash",
                "arguments": {
                    "command": "cargo test --all-features"
                }
            }),
        )
        .await?;

    match decision {
        Decision::Allow { .. } => {
            // Execute the action.
        }
        Decision::Block { reason, .. } => {
            // Surface the policy reason to the caller.
            eprintln!("blocked: {reason}");
        }
        Decision::Modify {
            modified_payload, ..
        } => {
            // Execute using modified_payload.
            println!("modified: {modified_payload}");
        }
        Decision::Defer { retry_after_ms, .. } => {
            // Retry later.
            println!("retry after {retry_after_ms}ms");
        }
        Decision::Escalate { reason, .. } => {
            // Hand off to a human approval path.
            eprintln!("escalated: {reason}");
        }
    }

    client.close().await?;
    Ok(())
}
```

## 类型化事件示例

```rust
use a3s_ahp::{AhpClient, ContextPerceptionDecision, EventType};

async fn inject_context(client: &AhpClient) -> a3s_ahp::Result<()> {
    let decision: ContextPerceptionDecision = client
        .send_typed_event(
            EventType::ContextPerception,
            serde_json::json!({
                "session_id": "session-1",
                "intent": "understand",
                "target": {
                    "location": {
                        "path": ".",
                        "location_type": "workspace"
                    }
                },
                "context": {
                    "workspace": "/repo",
                    "query": "How is the protocol structured?"
                }
            }),
        )
        .await?;

    match decision {
        ContextPerceptionDecision::Allow {
            injected_context, ..
        } => {
            println!("facts: {}", injected_context.facts.len());
        }
        ContextPerceptionDecision::Block { reason, .. } => {
            eprintln!("context blocked: {reason}");
        }
        ContextPerceptionDecision::Refine { scope_hints, .. } => {
            println!("refine with hints: {scope_hints:?}");
        }
    }

    Ok(())
}
```

## 完整事件示例

当运行时已经完成时使用`send_event_full`或`send_event_full_value`
组装了一个`AhpEvent`并且必须保留它的上下文。

```rust
use a3s_ahp::{AhpClient, AhpEvent, EventContext, EventType, SessionStats};

async fn send_runtime_context(client: &AhpClient) -> a3s_ahp::Result<()> {
    let event = AhpEvent {
        event_type: EventType::PreAction,
        session_id: "session-1".to_string(),
        agent_id: "agent-1".to_string(),
        timestamp: "2026-05-01T00:00:00Z".to_string(),
        depth: 1,
        payload: serde_json::json!({"tool_name": "bash"}),
        context: Some(EventContext {
            current_task: Some("run tests".to_string()),
            session_stats: Some(SessionStats {
                total_actions: 3,
                total_tokens: 42,
                duration_ms: 1000,
                error_count: 0,
            }),
            ..EventContext::default()
        }),
        metadata: None,
    };

    let decision = client.send_event_full(&event).await?;
    println!("decision: {decision:?}");
    Ok(())
}
```

## 服务器示例

```rust
use a3s_ahp::{
    AhpEvent, AhpServer, Decision, EventHandler, HarnessConfig, Result,
};
use async_trait::async_trait;
use std::sync::Arc;

struct PolicyHarness;

#[async_trait]
impl EventHandler for PolicyHarness {
    async fn handle_event(&self, event: &AhpEvent) -> Result<Decision> {
        if event.payload["tool_name"] == "rm" {
            return Ok(Decision::Block {
                reason: "destructive command requires approval".to_string(),
                metadata: None,
            });
        }

        Ok(Decision::Allow {
            modified_payload: None,
            metadata: None,
        })
    }
}

async fn run_harness() -> Result<()> {
    let server = AhpServer::new(Arc::new(PolicyHarness))
        .with_capabilities(["pre_action", "post_action", "batch"])
        .with_config(HarnessConfig {
            timeout_ms: Some(10_000),
            batch_size: Some(100),
            max_depth: Some(10),
        });

    server.run_stdio().await
}
```

`AhpServer` 验证事件深度，拒绝发送的阻塞事件
通知，拒绝作为请求发送的即发即忘事件，并拒绝
需要专门决策负载的批处理条目。
它还验证 `run_lifecycle`、`task_list` 和 `task_list` 的键入有效负载
`verification` 通知。

## 交通

|交通 |特色|状态 |笔记|
| ---| ---| ---| ---|
|工作室| `stdio` |已实施 |默认功能；对于本地子流程线束很有用。 |
| HTTP | `http` |已实施 |支持 API 密钥和不记名身份验证。 |
| WebSocket | `websocket` |已实施 |支持通过 URL 查询参数进行 API 密钥和承载身份验证。 |
| Unix 套接字 | `unix-socket` |已实施 | Unix 平台上的本地 IPC。 |
| gRPC | `grpc` |保留 |功能占位符；不包含在`all-transports`中。 |

特征示例：

```bash
cargo add a3s-ahp
cargo add a3s-ahp --features http
cargo add a3s-ahp --features all-transports
```

## 传输配置

```rust
use a3s_ahp::{AhpClient, Transport, TransportConfig};

async fn connect() -> a3s_ahp::Result<AhpClient> {
    AhpClient::new_with_config(
        Transport::Http {
            url: "https://harness.example.com/ahp".to_string(),
            auth: None,
        },
        TransportConfig {
            timeout_ms: Some(5_000),
        },
    )
    .await
}
```

相同的超时配置在实施过程中一致应用
涉及请求/响应等待的传输。

## 验证

```rust
use a3s_ahp::{AuthConfig, Transport};

let http = Transport::Http {
    url: "https://harness.example.com/ahp".to_string(),
    auth: Some(AuthConfig::bearer("token")),
};

let websocket = Transport::WebSocket {
    url: "wss://harness.example.com/ahp".to_string(),
    auth: Some(AuthConfig::api_key("key")),
};
```

## 批处理规则

批处理的存在是为了分摊同质通用策略的传输开销
检查。它不是适用于每种事件类型的多路复用机制。

规则：

- `ahp/batch` 返回`BatchResponse { decisions: Vec<Decision> }`。
- 事件顺序被保留。
- 返回的决策数必须等于提交的事件数。
- 服务器端处理程序失败变为`Decision::Block`。
- 拒绝专门的决策事件。
- `handshake`和`query`被批量拒绝。
- 批量大小可以受`HarnessConfig.batch_size`限制。

## 深度和递归

代理可以在处理另一个 AHP 决策时发出 AHP 事件。 `depth`
字段使递归可见。安全带可以做广告和执行
`HarnessConfig.max_depth` 防止不受控制的循环。

## 仓库布局

```text
ahp/
├── src/
│   ├── lib.rs
│   ├── auth.rs
│   ├── client.rs
│   ├── error.rs
│   ├── protocol.rs
│   ├── protocol/
│   │   ├── core.rs
│   │   ├── context.rs
│   │   ├── events.rs
│   │   └── json_rpc.rs
│   ├── server.rs
│   ├── server/
│   │   └── tests.rs
│   └── transport/
│       ├── http.rs
│       ├── stdio.rs
│       ├── unix_socket.rs
│       └── websocket.rs
├── examples/
└── Cargo.toml
```

## 开发

从此箱目录运行检查：

```bash
cargo fmt --all -- --check
cargo check --all-features
cargo check --no-default-features
cargo check --features all-transports
cargo test --all-features
```

## 许可证

MIT
