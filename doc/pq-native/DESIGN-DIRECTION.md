# TOS PQ-Native Design Direction

## 1. Core direction

TOS 将改为 **PQ-native from Genesis + minimal crypto agility + resource-budget-first** 路线。

主网从 Genesis 起直接使用一种批准的后量子签名算法，不再承担旧 Ed25519 共识链的迁移、双栈兼容和自动降级成本。

保留最小算法抽象：

```text
algorithm_id
public_key: variable bytes
signature: variable bytes
```

未来若需要从当前 PQ 算法升级到新的 PQ 算法，通过明确的协议升级完成；**不在初始主网同时运行多套共识签名算法，不做 legacy fallback，不做 C0/C2/C3 多时代切换。**

> **重要边界：现有 `feat/validator-auth-p0` 分支整体舍弃，不再继续开发、不合并到主线。后续 PQ-native 实现必须基于最新 `main` 重新建立新的独立开发分支。旧分支仅保留为研究参考。**

---

## 2. Keep identity/address independent from PQ public keys

PQ Public Key 可能达到数 KB，因此绝不能直接作为用户地址或 Validator 身份展示。

TOS 统一分成三层：

```text
Address / Validator ID   = fixed 32 bytes
Key ID                   = fixed 32 bytes
PQ Public Key            = variable length
```

建议：

```text
key_id = Hash(domain || algorithm_id || public_key)
```

钱包地址继续由账户/state hash 决定，PQ Public Key 只是账户状态中的验证凭证。

因此未来：

```text
key rotation
PQ algorithm upgrade
public-key size change
```

都不需要改变用户地址。

Validator 同样使用固定 32-byte Validator ID。完整 PQ Public Key 只作为链上验证材料保存；钱包、RPC 和区块浏览器默认显示短地址 / Validator ID / Key ID，需要时再展开完整公钥。

---

## 3. Validator model: PQ-native, not a new authority framework

新的 PQ-native 共识尽量继承 TOS/TON 现有 ValidatorSet 和 Simplex 结构。

目标是：

```text
ValidatorSet
  -> Validator ID
  -> PQ consensus public key
  -> weight
  -> ADNL/network identity

Simplex proposal / vote / certificate
  -> PQ signature

BlockProof
  -> PQ validator signatures
  -> existing weighted quorum rules
```

初始版本不再引入旧 `feat/validator-auth-p0` 中的：

```text
Config46 Validator Auth registry
C0 / C2 / C3 phases
five-role key hierarchy
VAC1 universal certificate
Signer Permit hierarchy
legacy/PQ era split
migration checkpoint
historical fallback
algorithm coexistence policy
```

除非新的 PQ-native 实现证明某个机制确实不可缺少，否则不要重新引入。

---

## 4. 21 validators is a launch size, not a protocol maximum

**21 个 Validator 只作为主网上线初期的 active masterchain committee size，不作为 PQ 协议永久上限。**

继续保留 TOS 原生 ConfigParam16 的动态数量机制：

```text
max_validators
max_main_validators
min_validators
```

建议初始配置方向：

```text
Genesis active masterchain validators = 21

max_main_validators = 100
max_validators      = 400
min_validators      = 4
```

未来网络可按实际性能和去中心化需求逐步扩大：

```text
21 -> 32 -> 50 -> 64 -> 100
```

扩大委员会不应要求重新修改 PQ 协议，只需在既定资源预算内调整链上配置。

---

## 5. Resource-budget-first consensus

PQ-native 设计真正限制的不是“Validator 必须等于 21”，而是**一个共识证书在网络、CPU、区块和验证时间预算内是否可安全处理**。

每个批准的 PQ suite 必须声明并锁定：

```text
max_public_key_bytes
max_signature_bytes
max_certificate_bytes
max_certificate_signers
max_verification_work / verification-time budget
```

主网配置必须满足：

```text
committee_size <= max_main_validators

committee_size * max_signature_bytes
  + certificate framing
  <= max_certificate_bytes

worst_case_certificate_verification
  <= consensus verification budget
```

如果一次 ConfigParam16 调整会使当前 PQ suite 超过证书大小或验证成本预算，节点必须拒绝该配置，而不是截断 Validator、减少签名或静默降级。

**资源预算才是硬安全边界，21 只是初始运行参数。**

---

## 6. PQ suite abstraction

建议使用最小结构，而不是通用密码学策略系统：

```text
PQSuite {
    algorithm_id
    max_public_key_bytes
    max_signature_bytes
}
```

Validator descriptor 只需要表达：

```text
Validator ID
algorithm_id
PQ public key
weight
ADNL/network identity
```

共识消息中的签名表达：

```text
algorithm_id
signature bytes
```

Genesis 只允许一个 active consensus PQ algorithm。

未知 `algorithm_id` 必须 fail closed。

未来算法升级必须通过显式网络升级完成，不允许节点本地自行选择算法，也不允许验证失败后回退到 Ed25519。

---

## 7. Implementation scope

新的 PQ-native 分支优先只做以下六件事：

```text
Q1. PQ sign / verify primitive
Q2. ValidatorSet carries PQ public keys
Q3. Simplex proposal / vote / certificate use PQ signatures
Q4. BlockSignatures / BlockProof become PQ-native
Q5. Lite client verifies PQ finality proofs
Q6. Wallet / TVM gains PQ signature verification where required
```

同时完成：

```text
genesis tooling
key generation/import
RPC/block explorer display
cross-language C++/Rust vectors
multi-node consensus rehearsal
signature/certificate size benchmarks
verification latency benchmarks
```

不在这一阶段扩张到：

```text
general-purpose validator identity framework
multi-algorithm consensus
legacy-chain migration
automatic fallback
DA redesign
ZK redesign
cross-chain redesign
unrelated node-actor refactors
```

---

## 8. Required measurements before mainnet

在确定最终 Genesis 参数前，必须用真实实现测量：

```text
21 validators
32 validators
64 validators
100 validators
```

至少记录：

```text
public-key state size
single-signature size
full certificate size
certificate verification latency
proposal/vote propagation latency
block size impact
CPU utilization
memory utilization
lite-proof size and verification cost
```

根据这些实测结果确定：

```text
Genesis active validator count
max_main_validators
max_certificate_bytes
verification budget
network propagation budget
```

而不是先把某个 Validator 数量硬编码成协议常量。

---

## 9. Design principle

TOS PQ-native 的核心原则是：

> **Genesis 就是 PQ，不迁移旧共识；地址与公钥分离；协议只保留最小算法可升级接口；Validator 数量由链上配置决定，而安全上限由明确、可测量、可执行的 PQ 资源预算决定。**

目标不是再造一套 Validator Authority 系统，而是在尽量保持现有 TOS/TON 共识结构的前提下，把 Ed25519 共识签名干净地替换成 PQ-native 签名，并为未来算法升级留下最小而明确的接口。
