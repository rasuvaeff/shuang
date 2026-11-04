# shuang — 霜

**VPN 掉线时冻结你的应用 —— 暂停,而不是杀掉。**

`shuang` 是一个免费、开源的按应用 kill switch。当你的外部 IP 不在白名单里时,
所选应用的**整棵进程树会被挂起**(`SIGSTOP`):不执行任何指令、不发送任何数据。
正确的 IP 回来后,它从暂停的地方继续运行。若在宽限期内始终没有回来,进程树将被停止。

为 AI 编程代理(Claude Code、Codex、Gemini CLI)以及任何绝不能以错误地址联网的
应用而生。没有服务器、没有账号、没有遥测 —— 只有一个二进制文件。

## 为什么需要

VPN 客户端自带的 kill switch 会切断整个网络。`shuang` 按应用工作:被冻结的应用
不会泄露任何流量,其他一切照常。与防火墙规则不同,挂起是可逆的 —— VPN 闪断两秒,
Claude Code 暂停后从原处继续,会话完好无损。

## 安装

目前支持 Linux 和 macOS;Windows 将在 0.2 版本与托盘图标一起提供。

### 一行命令(Linux 和 macOS)

```bash
curl -fsSL https://raw.githubusercontent.com/rasuvaeff/shuang/master/scripts/install.sh | sh
```

下载会与发布版附带的 `.sha256` 校验;不匹配则拒绝安装。可用 `INSTALL_DIR=…`
覆盖安装目录,用 `VERSION=vX.Y.Z` 固定版本。

### Cargo

```bash
cargo install --git https://github.com/rasuvaeff/shuang
```

## 用法

### 单条命令的 kill switch

```bash
shuang run -- claude -p "fix the tests"
```

- **启动时** IP 不允许 → 命令根本不运行,退出码 **69**;
- **运行中** IP 变坏 → 整棵进程树(MCP 服务器、`curl`、`git`……)被冻结;
  宽限期内正确 IP 回来则继续,否则停止,退出码 **75**;
- 其他情况退出码为命令自身的退出码。

**白名单为空**时,首次运行会把启动时的 IP 记为允许(即"变化时冻结")。
添加条目:

```bash
shuang allow 203.0.113.42      # 单个 IP
shuang allow 185.12.40.0/24    # 网段
shuang allow NL                # 整个国家
```

### 一次性检查

```bash
shuang check          # 人类可读
shuang check --json   # {"ipv4": "...", "ipv6": "...", "country": "NL", "quorum": true, "allowed": true}
```

退出码:`0` 允许,`3` 不允许,`1` 错误。

### 守护进程:监控应用

```toml
# ~/.config/shuang/config.toml
[[apps]]
name = "claude-code"
match = ["claude", "args:claude"]   # 进程名 / 路径子串 / args: 参数子串

[allow]
countries = ["NL"]

[ip_check]
min_agree = 2        # 至少 2 个服务给出相同 IP 才算数
interval_secs = 5

[timing]
grace_secs = 20      # 冻结后等待正确 IP 的时间
close_secs = 5       # 强制杀死前的优雅停止时间
```

```bash
shuang daemon
```

## 检查的工作原理

每隔 `interval_secs` 秒,并行询问所有配置的服务:调用方的 IPv4 **和** IPv6 地址。
只有 `min_agree` 个服务给出一致答案才算数 —— 更少即为"未知",而**未知永远不会
被允许**(fail-closed)。VPN 只隧道 IPv4 时绕行的 IPv6 直连路由,会被单独的
IPv6 检查捕获。

`shuang allow` 的运行时条目存储在配置旁边的 `state.toml` 里 —— 你手写的、带注释
的 `config.toml` 永远不会被改写。

## shuang 会向网络发送什么

只有你配置的 IP 检查(默认:`api.ipify.org`、`ipv4.icanhazip.com`、
`v4.ident.me`、`checkip.amazonaws.com` 及 IPv6 对应服务;国家:`api.country.is`)。
没有遥测、没有更新探测、没有我们的服务器。可以把 `ip_services` 指向你自己的、
以纯文本返回 IP 的服务端点。

## 平台支持

| 平台 | 状态 |
|---|---|
| Linux | ✅ v0.1 |
| macOS | ✅ v0.1 |
| Windows | 🚧 0.2(与托盘图标、`NtSuspendProcess` 一起) |
| HarmonyOS PC | 📋 之后可通过 Rust 的 `aarch64-unknown-linux-ohos` 目标支持 —— 暂无计划 |

v0.1 面向服务器、CI 和终端(无界面)。托盘图标、网络事件订阅(即时响应而非轮询)、
Telegram 通知在路线图中;同类闭源工具的云端部分被有意排除在核心之外。

## 退出码

| 码 | 含义 |
|---|---|
| `0` | 允许 / 命令成功结束 |
| `1` | 错误(配置错误、无法启动命令……) |
| `3` | `check`:当前 IP 不允许 |
| `69` | `run`:启动时 IP 不允许,命令未运行 |
| `75` | `run`:已停止 —— 允许的 IP 始终没有回来 |

## 安全说明

- 被挂起的进程不会发送任何数据,但冻结发生在网络变化之后几毫秒:要获得"一个包都
  不漏"的硬保证,请把 `shuang` 与 VPN 客户端网络层的 kill switch 结合使用 ——
  本工具是对它的补充,不是替代。
- root / 系统服务的进程不会被触碰;`shuang` 以启动它的用户权限工作。
- `daemon` 按名称匹配进程 —— 攻击者进程伪装成你的应用不在 v0.1 的威胁模型内。

## 开发

```bash
cargo fmt
cargo clippy --all-targets --locked -- -D warnings
cargo test --all --locked
```

Rust 1.85+(edition 2024)。`Cargo.lock` 已提交(二进制 crate)。

## 许可证

[GPL-3.0-or-later](./COPYING)。分支必须保持开源。
