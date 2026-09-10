# third_party — 第三方资源清单

本目录收纳随仓库分发的第三方二进制，**全部为官方发布物的原样拷贝，未做任何
修改**。`SHA256SUMS.txt` 覆盖仓库内全部文件；另有体积较大的上游发布物原件
（VxKex 安装包）不随仓库分发，其 SHA-256 见 `UPSTREAM-SHA256.txt`，可自行从
官方 releases 下载校验。

## vxkex/ — VxKex NEXT 运行时二进制

| 项 | 内容 |
|---|---|
| 名称 | VxKex NEXT（Windows 7 API Extensions） |
| 来源仓库 | https://github.com/YuZhouRen86/VxKex-NEXT （上游：vxiiduu/VxKex） |
| 版本 | 1.2.3.2462 |
| 官方发布物 | `KexSetup_Release_1_2_3_2462.exe`（Inno Setup 安装包）；**本仓库不分发原件**，需从上游 releases 自行下载，其 SHA-256 见 `UPSTREAM-SHA256.txt` |
| 许可证 | 上游未附带 LICENSE 文件；README 声明基于 vxiiduu VxKex 完全开源。**再分发前请与上游作者确认条款** |
| 修改 | 无（DLL 为官方发布物解包后的原样拷贝） |

### 文件与用途

- 本目录的 `Core64/KexDll.dll` 与 `Kex64/Kx*.dll` 来自官方安装包
  `KexSetup_Release_1_2_3_2462.exe`。**安装包原件本仓库不分发**；需要复核来源时
  从上游 releases 下载（URL 与 SHA-256 见 `UPSTREAM-SHA256.txt`），用 7-Zip
  解开（`7z x KexSetup_Release_1_2_3_2462.exe`），其中的 `Core64/`、`Kex64/`
  应与本目录同名文件逐字节一致。
- `Core64/KexDll.dll` — VxKex 核心：基础 inline hook 引擎（`KexHkInstallBasicHook`）、
  直接 syscall 封装（`KexNtCreateUserProcess`/`KexNtMapViewOfSection`/
  `KexNtQueryVirtualMemory`）、CPIW 子系统版本检查绕过
  （`KexPatchCpiwSubsystemVersionCheck`）等约 130 个导出函数。
  本方案**不安装** VxKex（不跑 KexSetup、不写注册表、不进 system32），
  仅把 KexDll.dll 作为普通文件随 Python 树分发，由自研 PyKexLdr/PyKexBoot 按进程注入。
- `Kex64/Kx*.dll`（13 个）— Win8+ API 的回退实现（扩展 DLL），按
  `runtime/PyKexBoot/PyKexBoot.c` 的 `g_Redirects` 表在加载期接管宿主 DLL 的导入。
  所有 Kx*.dll 都静态 import KexDll.dll，因此必须与 KexDll.dll **同目录**摆放。

### 部署取舍

`build_pack.py` 只部署 **12 个** Kx*.dll（外加 KexDll.dll），**不部署 KxDw.dll**：
KxDw.dll 静态导入 `dwrw10.dll!DWriteCoreCreateFactory`（DirectWrite，
Chromium 系应用专用，无法回移到裸 Win7）。Python 场景用不到 DirectWrite，
带上它反而多一个无法解析的导入面。KxDw.dll 保留在本目录中备查。

## yy-thunks/ — YY-Thunks 对象库（官方发布物存档）

| 项 | 内容 |
|---|---|
| 名称 | YY-Thunks（ChuyuTeam） |
| 来源仓库 | https://github.com/Chuyu-Team/YY-Thunks |
| 版本 | v1.2.2 |
| 官方发布物 | `YY-Thunks-Objs.zip`（本目录附有原件，SHA-256 见 `SHA256SUMS.txt`）；另有 `YY-Thunks-Lib.zip` |
| 许可证 | MIT |
| 修改 | 无 |

本方案**不使用** YY-Thunks 的对象库重编 CPython（统一路线不需要重编译），
保留该发布物是因为 zip 内含两件本项目在用的东西：

- `Config\<arch>\<version>.txt` — 各 Windows 版本系统 DLL 导出函数数据库。
  本项目的 Win7 SP1 基线 `assets/baseline/x64/6.1.7600.txt` 即取自其中的
  `Config\x64\6.1.7600.txt`（逐字节一致）。`tools/scan_tree.py` 靠它判定
  "某导入在裸 Win7 SP1 上是否存在"。
- `YY.Depends.Analyzer.exe` — PE 导入缺失分析器，可用于交互式排查单个
  二进制的导入问题。它只在这份 zip 里（体积大且仅开发机用），需要时从
  zip 解出即可。

如需自行重编带 YY-Thunks 的应用（与本方案无关的场景），用此 zip 内的 obj
或官方 `YY-Thunks-Lib.zip` 链接即可。

## VC-LTL5 — 仅给出获取指引（不随仓库分发）

| 项 | 内容 |
|---|---|
| 名称 | VC-LTL5（ChuyuTeam，VC 运行时低版本支持库） |
| 来源仓库 | https://github.com/Chuyu-Team/VC-LTL5 |
| 版本 | v5.3.1（发布物 `VC-LTL-Binary.7z`） |
| 许可证 | 见上游仓库 |

**仅当你选择自行重编 CPython 时才需要它**（把 msvcrt/vcruntime 依赖降到
Win7 可承载）。本方案的统一路线不重编 CPython，因此不分发、不使用 VC-LTL5。
安装方式见上游 README（NuGet/发布包均可）。

## 下载与校验

仓库内随附资产可直接校验（Git Bash 自带 `sha256sum`，相对路径以本目录为基准）：

```bash
cd third_party
sha256sum -c SHA256SUMS.txt          # 期望全部 OK
```

上游发布物原件复核（可选；`KexSetup_Release_1_2_3_2462.exe` 不在仓库内）：

```bash
# GitHub 直连不通时走代理（示例端口 7890，按实际改）
curl -x http://127.0.0.1:7890 -L -o KexSetup_Release_1_2_3_2462.exe \
  https://github.com/YuZhouRen86/VxKex-NEXT/releases/download/1.2.3.2462/KexSetup_Release_1_2_3_2462.exe
curl -x http://127.0.0.1:7890 -L -o YY-Thunks-Objs.zip \
  https://github.com/Chuyu-Team/YY-Thunks/releases/download/v1.2.2/YY-Thunks-Objs.zip

# 校对下载到的原件
sha256sum -c UPSTREAM-SHA256.txt
```

手动备选：浏览器开代理访问上述 releases 页面下载，再用 `sha256sum` 对照。
