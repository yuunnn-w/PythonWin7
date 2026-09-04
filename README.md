# PythonWin7

让**官方 CPython（x64）**在**裸 Windows 7 SP1** 上运行的开源工具集：目标机不打任何 KB 补丁、不装任何软件、无需管理员权限、不写注册表 / system32，改造后的 Python 树自包含、可整体打包分发。一条工具链覆盖 **Python 3.9 ~ 3.14+**（含 3.13t/3.14t free-threaded 变体）：

- **3.12 ~ 3.14+**：官方已放弃 Win7，本工具集恢复支持；
- **3.9 ~ 3.11**：官方本支持 Win7，但要求目标机安装 KB2999226（UCRT）。本工具集把 UCRT 文件集树内私有化，**免掉这个前提**，并为未来安装的第三方wheel（可能带 Win8+ 导入）加上运行时保险；
- 覆盖 `pip install` 进来的 wheel 自带二进制（numpy、cryptography 等）：加载期运行时改写 + 安装期门禁扫描双保险。

## 特性

- **四层纵深防御**：静态文件层 + 引导 IAT 补丁 + 运行时注入改写 + 安装门禁，一次 `build_pack.py` 全部完成；
- **零系统足迹**：全部机制在 Python 目录内，目标机不打补丁、不装软件、不需要管理员；
- **扫描驱动，无版本硬编码**：版本 stem、入口 exe、引导补丁条目全部靠扫描目标树自动发现，换版本不用改工具；
- **幂等、可回滚**：重复执行安全；`--restore` 一键还原（原件备份 `*.pyw7bak`、全部动作记入清单）；
- **自带验收套件**：`tests/test_win7_tree.py`（G0–G5+S，纯 stdlib），开发机与 Win7 目标机通用；
- **资源自包含**：全部运行时资产（KB2999226 UCRT、VxKex 二进制、API 基线、预编译组件）随仓库附带并附 SHA-256 校验，见 `assets/` 与 `third_party/`。

## 原理架构（一条主路线，四层纵深）

```text
官方 Python 树
  │
  ├─ 1. 静态文件层（所有版本的根基）KB2999226 UCRT（ucrtbase.dll + 23 个 api-ms-*.dll）、vcruntime140*、msvcp140* 复制进树根 —— 应用目录优先于 system32，loader 直接解析，不依赖目标机安装任何补丁。
  │
  ├─ 2. 引导 IAT 补丁（核心 DLL 按需最小化，扫描驱动）python3XX.dll 里 Win7 上无法解析的导入被离线重定向到 KxBase.dll（3.14.x 为 2 条：AddDllDirectory/RemoveDllDirectory；3.12.0 为 7 条：再加 CopyFile2/Pss*×3 与 core-path 整描述符换名）。必要性：注入发生在进程创建之后，主 exe 依赖树的导入快照先于注入完成，核心 DLL 的这些导入必须静态修 —— 但它是"引导"，不是逐二进制修补的主路线。原件保留为 *.pyw7bak。
  │
  ├─ 3. 运行时层（主路线核心；默认启用，--no-launcher 可关）PyKexLdr 启动器顶替入口 exe（python.exe/pythonw.exe/pythonX.Yt.exe），挂起创建真解释器进程并注入 KexDll.dll + PyKexBoot.dll：
  │  • NtCreateUserProcess hook + watcher 线程 → 同套注入递归传播到所有后代进程（pip、f2py、multiprocessing spawn、os.system 链）；
  │  • NtMapViewOfSection hook → 每个后加载的 PE 映像（任何 wheel 的.pyd/.dll）在导入快照前被内存改写导入描述符：kernel32/ntdll/user32/advapi32/api-ms-win-* 等 167 条名字按 VxKex redirects 表换成 Kx*.dll（Kx* 转发宿主 DLL 全部表面 + 补齐 Win8+ 实现）。结果：wheel 里的 pyd **不需要逐文件修**就能在 Win7 上加载。
  │
  └─ 4. 门禁兜底（pywin7gate，随树安装 sitecustomize + pip 包装）新装 wheel 的二进制对照"裸 Win7 SP1 API 基线"扫描；运行时层覆盖不了的（独立 exe 的自有导入、无 Kx 实现的函数）做静态 IAT 手术或vendored DLL 复制；修不了的拒装并给出确切原因。
```

### 为什么是"目录内启动器 + 注入"，而不是别的机制

| 候选机制 | 结论 |
|---|---|
| IFEO / AppInit_DLLs / 全局 VxKex 安装 | 需要管理员 + 写注册表，目标机有系统足迹 —— 出局 |
| 私有 kernel32.dll 转发（文件顶替） | kernel32 在 Known DLLs 列表里，loader 强制从 system32 加载，应用目录副本无效 —— 不可行 |
| 逐二进制静态 IAT 修补全部 wheel | 维护噩梦：每个新 wheel 都要重做；仅保留为"引导 + 兜底" |
| **目录内 shim 启动器 + 进程内 hook 传播** | 零注册表、零服务、零 system32、可随树拷贝分发 —— 采用 |

VxKex 官方的导入改写子系统只在 IFEO verifier 加载时激活，且其关键函数不在KexDll.dll 导出表（依据见 `docs/design.md` §5.1），因此本工具集按同一原理自研了等价机制（CRT-free，仅用 KexDll 导出的 hook/syscall 原语）。完整论证、IAT 手术细节、Kx 覆盖度数据见 **[docs/design.md](docs/design.md)**。

## 系统要求

| 角色 | 要求 |
|---|---|
| 开发机（执行改造/打包） | 任意现代 Windows + 任意一套 Python 3.9+（跑工具用）；重编自研 C 组件才需要 VS2022（预编译件已随库附带，通常不需要） |
| 目标机 | **裸 Windows 7 SP1 x64**——不打任何补丁（含 KB2999226）、不装任何软件、无管理员权限要求 |
| Python 树 | 官方 CPython 3.9+ x64 安装版或 embeddable 树（32 位不在范围内） |

## 快速开始（任意官方 3.9+ x64 树，5 步）

```bat
rem 0. 在开发机（任意现代 Windows）准备：
rem    - 本仓库 clone 到任意位置
rem    - 一套官方 Python 树（安装版或 embeddable 均可），记为 %PYDIR%
rem    - 另备一套"工具 Python"跑脚本（任意 3.9+：系统 Python、py 启动器、
rem      或另一棵树均可），记为 %PYTOOLS%
rem    !! 不要用 %PYDIR% 自己的 python.exe 跑 build_pack —— 目标树的核心
rem       python3XX.dll 会被该进程加载锁定，原地改写必然失败；build_pack
rem       检测到这种情况会拒绝执行（退出码 2）。--dry-run 不受限。
set PYDIR=<PYTHON_DIR>
set PYTOOLS=py

rem 1. 构建运行时组件（需要 VS2022 社区版；仅需一次；产物已随仓库预编译，可跳过）
runtime\PyKexLdr\build.bat
runtime\PyKexBoot\build.bat
runtime\PyKexShim\build.bat

rem 2. 干跑预演（不写任何文件；列出将执行的全部动作并真实校验补丁可行性）
%PYTOOLS% tools\build_pack.py --target %PYDIR% --dry-run

rem 3. 正式实施（幂等，可重复跑；版本差异由扫描自动适配）
%PYTOOLS% tools\build_pack.py --target %PYDIR%

rem 4. 验证（开发机与 Win7 目标机通用，同一脚本）
%PYTOOLS% tests\test_win7_tree.py --tree %PYDIR%

rem 5. 之后装包走门禁包装（替代 python -m pip install）
%PYDIR%\python.exe -m pywin7gate pip install <pkg>

rem 撤销全部改动（恢复成未打补丁的原树；同样要用另一套解释器跑；
rem *.pyw7bak 备份保留）
%PYTOOLS% tools\build_pack.py --target %PYDIR% --restore
```

不用 VxKex 二进制的纯自研回退路线：`tools\build_pack.py --no-vxkex`（核心 DLL 改指 `PyKexShim.dll`，放弃子进程传播与 Kx* 覆盖面，pyd 退回逐文件静态修复）。只装静态层、不装运行时层：`--no-launcher`。

### 改造后树的布局（以 3.14 为例）

```text
Python314\
├─ python.exe / pythonw.exe / python3.14t.exe / pythonw3.14t.exe   ← PyKexLdr 变体
├─ python314.exe / pythonw314.exe / python314t.exe / pythonw314t.exe ← 真解释器（改名）
├─ python314.dll / python314t.dll        ← 引导 IAT 已补丁（+.pyw7bak 备份）
├─ PyKexBoot.dll / KexDll.dll / KxBase.dll + 11 个 Kx*.dll
├─ ucrtbase.dll + 23 个 api-ms-win-*.dll（KB2999226 官方件）
├─ msvcp140*.dll ×3（vcruntime140*.dll 等官方原有件不动）
├─ pywin7-pack-manifest.json             ← 打包清单 v2（--restore 依据）
├─ Lib\pywin7gate\ + Lib\sitecustomize.py                ← 门禁
├─ Lib\site-packages\.pywin7-gate-manifest.json          ← 门禁清单
└─ Lib\ DLLs\ Scripts\ tcl\ …（官方结构不变；Scripts\ 可增 .bat 包装）
```

## 使用

### 装包（门禁，长期入口）

```bat
python.exe -m pywin7gate pip install <pkg>   :: 装包 + 自动门禁
python.exe -m pywin7gate fix-all             :: 手工触发全量门禁
python.exe -m pywin7gate status / verify     :: 状态 / 哈希校验
python.exe -m pywin7gate restore <file>      :: 回滚单文件修复
```

绕开 wrapper 也安全：import 时 audit hook 会对未过门禁的 pyd 现场补门（修不了的抛 ImportError 并附确切 blocker）。总开关：环境变量 `PYW7GATE=0` 全关。

### Scripts 入口 stub（搬家保险，推荐）

`Scripts\*.exe`（pip.exe/f2py.exe 等）内嵌安装时绝对路径，树搬家后旧路径不存在即失效。两种处置（可叠加）：

1. 约定一律用 `python.exe -m <模块>`（pip → `python -m pip`，f2py → `python -m numpy.f2py`；入口模块名查该包 dist-info 的 entry_points.txt）；
2. 生成相对路径 .bat 包装（原 .exe 可留可删）：
```bat
%PYTOOLS% tools\make_stub_bats.py %PYDIR%
```

### 打包分发

1. 开发机装好全部目标机需要的包（走门禁），跑一遍验收套件全绿；
2. （可选）删 `Lib\site-packages\**\__pycache__\` 与不需要的 t 变体文件；
3. zip 整树（内部相对结构不可动；`*.pyw7bak` 建议保留，体积敏感可删但失去就地回滚能力）；
4. 目标机解压到任意路径，直接 `python.exe -V`。

### 诊断开关（进程内，无需改文件）

| 变量 | 作用 |
|---|---|
| `PYW7DEBUG=1` | 运行时层向 `%TEMP%\pykexboot-dbg.log` 写低频事件日志（子进程创建、注入结果、导入改写） |
| `PYW7HOOK=0` | 关闭加载期导入改写 hook（隔离改写引擎问题） |
| `PYW7GATE=0` | 关闭门禁（sitecustomize + audit hook） |

## 验证

验收套件 `tests/test_win7_tree.py`（纯 stdlib，开发机与 Win7 目标机通用）：

```bat
%PYTOOLS% tests\test_win7_tree.py --tree %PYDIR%
```

- 分组与通过标准见 **[docs/testing.md](docs/testing.md)**；
- 该套件在官方 3.14.7（普通 + free-threaded）与 3.12.0 树上全部通过；未列明版本的引导补丁条数与行为以 `--dry-run` 输出为准；
- 在真实 Win7 SP1 机器上的验证清单同样见 docs/testing.md——发布前的打包流程要求至少在目标环境跑过一遍。

## 版本差异矩阵（扫描驱动，无需手工指定）

| 版本 | 官方 Win7 支持 | 本包的核心动作 | 备注 |
|---|---|---|---|
| 3.9 / 3.10 | 有（需 KB2999226） | 静态文件层私有化 UCRT；引导补丁预期 0 条 | venv 复制式（getpath.c 时代，无 `__PYVENV_LAUNCHER__`），链路未在 Win7 实机验证过 |
| 3.11 | 有（需 KB2999226） | 同上 | getpath.py 起支持 `__PYVENV_LAUNCHER__` |
| 3.12 | 无 | + 引导补丁 + 运行时层；**3.12.0 需要 7 条**：AddDllDirectory/RemoveDllDirectory/CopyFile2/PssCaptureSnapshot/PssQuerySnapshot/PssFreeSnapshot 重定向到 KxBase + `api-ms-win-core-path-l1-1-0.dll` 整描述符换名（3.12 树内不带此文件，3.14 起官方自带） | OpenSSL 3.x（3.9-3.11 为 1.1），SSL 表面变化由文件层覆盖 |
| 3.13 | 无 | 同上（引导补丁条数扫描定） | 3.13+ venv 改用 redirector exe（Scripts\python.exe 非复制） |
| 3.14 / 3.14t | 无 | 引导补丁 2 条（AddDllDirectory/RemoveDllDirectory）×2 变体 | free-threaded（t）变体自动识别、独立处理 |
| embeddable 任意版 | — | + 扩展 `python3XX._pth`（补 Lib、site-packages、import site） | 原 ._pth 内容进 manifest，可 --restore |

> 引导补丁条数只能扫描确定，不能按版本猜（3.12.0 比 3.14 还多就是例子）。
> 各版本的具体条数以 `--dry-run` 输出为准。

## 资源与第三方依赖获取

三类外部资产随仓库附带（官方原件 + SHA-256 校验值，`third_party/SHA256SUMS.txt` 全量可验）。重新获取方式：

| 资产 | 用途 | 获取 |
|---|---|---|
| VxKex NEXT 1.2.3.2462 二进制 | 运行时层（KexDll + 12 个 Kx*.dll） | `third_party/vxkex/`（附官方安装包原件）；官方源 https://github.com/YuZhouRen86/VxKex-NEXT/releases/tag/1.2.3.2462 |
| YY-Thunks v1.2.2 发布物 | Win7 API 基线数据库 + Depends 分析器 | `third_party/yy-thunks/`（附官方 zip 原件）；官方源 https://github.com/Chuyu-Team/YY-Thunks/releases/tag/v1.2.2 |
| KB2999226 UCRT 文件集 | 静态文件层 | `assets/kb2999226/amd64/`（附 .msu 原件）；用 `tools\extract_kb2999226.py` 从微软官方 .msu 重新解出（脚本内含下载指引） |
| MSVC vcruntime/msvcp140 | 静态文件层 | `assets/msvc-redist/`；或从本机 VS2022 的 `VC\Redist\MSVC\*\x64` 目录提取（build_pack 自动探测） |
| VC-LTL5 v5.3.1 | **仅自研重编 CPython 才需要**（本路线不需要） | https://github.com/Chuyu-Team/VC-LTL5/releases/tag/v5.3.1 |

GitHub 直连不通时走代理（示例端口按实际改）：

```bash
curl -x http://127.0.0.1:7890 -L -O <release asset URL>
```

校验与手动备选见 `third_party/README.md`（含每个文件的 SHA-256）：

```bash
cd third_party && sha256sum -c SHA256SUMS.txt --ignore-missing
```

## 目录结构

```text
PythonWin7\
├── README.md                 ← 本文件
├── LICENSE                   ← GPL-3.0 官方原文（适用于自研代码；第三方资产受各自条款约束，见下方 License 节）
├── docs\
│   ├── design.md             ← 架构与技术决策（统一路线论证、VxKex 机制考证、覆盖度数据）
│   └── testing.md            ← 验收套件说明与 Win7 目标机验证指南
├── src\
│   ├── pywin7gate\           ← 门禁与修补引擎（随树安装到 Lib\pywin7gate）
│   │   ├── pe.py             ← 纯 stdlib PE 解析（导入/延迟导入/导出+转发追踪）
│   │   ├── iatpatch.py       ← IAT 手术：函数级重定向（donor 自动选取）+ 整描述符换名
│   │   ├── fixers.py         ← 修复动作与运行时重定向表（RUNTIME_REDIRECT_PAIRS）
│   │   ├── gate.py           ← 扫描→判读→修复编排 + 清单（.pywin7-gate-manifest.json）
│   │   ├── hook.py           ← import 时 audit hook 兜底
│   │   ├── __main__.py       ← CLI: scan/fix/fix-all/flatten/pip/verify/restore/status
│   │   └── baseline_6_1_7600.json  ← 裸 Win7 SP1 API 基线（make_baseline.py 生成）
│   └── sitecustomize.py      ← 随树安装到 Lib\，启动时装 hook（PYW7GATE=0 可关）
├── runtime\                  ← 自研 C 组件（CRT-free，仅 import kernel32；含预编译产物）
│   ├── PyKexLdr\             ← 通用入口启动器（console/GUI 两变体；任意 3.9+ 动态解析）
│   ├── PyKexBoot\            ← 传播 + CPIW 绕过 + 加载期导入改写引擎
│   └── PyKexShim\            ← --no-vxkex 回退 shim
├── tools\
│   ├── build_pack.py         ← 一键打包/还原（扫描驱动、幂等、--dry-run/--restore）
│   ├── pe_scan.py            ← 单文件导入表 vs Win7 基线扫描（开发机 CLI）
│   ├── scan_tree.py          ← 整树静态验收扫描
│   ├── iat_patch.py          ← IAT 重定向 CLI（含 --show/--restore/--donor）
│   ├── make_baseline.py      ← YY-Thunks 数据库 → 随树 JSON 基线
│   ├── make_stub_bats.py     ← Scripts\*.exe → 相对路径 .bat 包装
│   └── extract_kb2999226.py  ← 从 .msu 解出 UCRT 文件集（不安装 KB）
├── tests\
│   ├── test_win7_tree.py     ← G0–G5+S 验收套件（开发机与 Win7 目标机通用）
│   └── testdll\              ← TestWin8Api.dll（导入 3 个 Win8+ API 的探针 DLL）
├── assets\                   ← KB2999226 UCRT 文件集、MSVC redist、API 基线
└── third_party\              ← VxKex/YY-Thunks 官方发布物原件 + 校验（见该目录 README）
```

## 已知限制（兼容性边界）

- 仅 **x64**；32 位 Python 不在范围内（WOW64 子进程自动跳过注入；KB x86 文件集已备在 `assets/kb2999226/x86/`，如需 32 位支持需另行实现对应的 PyKexBoot）。
- 目标机 = **Win7 SP1 x64 裸机**；开发机 = 任意现代 Windows（构建/打包在开发机做）。
- `msvcp_win.dll` / Chromium 系（dwrw10、icuuc 等）依赖的包明确拒装（msvcp_win 依赖 `ResolveDelayLoadedAPI`，Win7 无真实现；且 KB 的 ucrtbase 10240 缺其引用的 `__uncaught_exceptions`）。
- Kx*.dll 的覆盖是"语法级"的（导出表对齐），非语义级保证：个别 VxKex 实现自身有缺陷（已知：VxKex-NEXT 1.2.3.2462 的 `KxBase!GetThreadDescription` 上游实现有栈损坏 bug；`Get/SetThreadDescription` 这类依赖 Win10 1607+ 原语的 API 在裸 Win7 上本来也无法实现）。命中的包会在门禁或运行期暴露，已知缺陷列表见 `docs/design.md` §5.4。
- 动态 `GetProcAddress` 查 Win8+ API 是静态扫描盲区（CPython 对老系统普遍有版本守卫，实际命中概率低），只能靠 Win7 目标机实测暴露，见 `docs/testing.md` 的验证指南。
- KxBase 的 AddDllDirectory 模拟不改真 loader 搜索路径——受害场景（delvewheel 包靠 `os.add_dll_directory` 加载 vendored DLL）由门禁的 vendored 摊平静态化解。
- 运行时层依赖远程注入（VirtualAllocEx + CreateRemoteThread），**杀软/EDR 可能拦截或告警**；这是该技术路线的固有特征，部署前请在目标环境的杀软策略下实测。纯静态回退路线（`--no-vxkex`）不用任何注入。
- 调用方自求 CREATE_SUSPENDED 的子进程不注入（文档化降级场景，实践中极少）。
- 3.9/3.10 的 venv 链路（getpath.c 时代，无 `__PYVENV_LAUNCHER__`）未在 Win7 实机验证过，属已知边界。

## 故障排查

| 症状 | 指向 | 处置 |
|---|---|---|
| build_pack 报 "the running interpreter lives inside the target tree" | 用了目标树自己的 python.exe 跑工具 | 换另一套解释器（系统 Python/py/另一棵树）；这是守卫，不是故障 |
| dry-run/实施输出 "STILL MISSING … KERNEL32!Xxx" | 新版 CPython 新增 Win8+ 导入 | 查 Kx*.dll 是否导出同名函数：`iat_patch.py --show` 引擎可直加条目；无导出则评估 PyKexShim 扩展或拒升该版本 |
| dry-run/实施报 "no built-in donor … short enough" | 受害函数名太短，内置 donor 候选放不下 | `iat_patch.py --donor <更短的、目标 OS 存在的同名 DLL 导出>` 显式指定 |
| 目标机弹窗"找不到 api-ms-win-crt-*.dll / ucrtbase.dll" | 树根文件没拷全 / 目录结构被改 | 重跑 build_pack；确认 zip 保留了内部相对结构 |
| 目标机 0xC000013D 点名 KERNEL32!AddDllDirectory | 引导 IAT 补丁未生效（文件被覆盖回原版） | `iat_patch.py --show python3XX.dll` 核对；重跑 build_pack |
| 目标机 import 某 wheel 的 pyd 报缺 DLL | 该 pyd 未过门禁且未被运行时改写覆盖 | `python -m pywin7gate fix <该pyd>` 现场修；看报错中的 blocker 清单 |
| import 抛 "pywin7gate: … cannot run on bare Windows 7" | 门禁拒装（有真无解依赖） | 换包/换版本；或 `PYW7GATE=0` 绕过（风险自负，运行时多半会崩） |
| 杀软报毒/拦截注入 | PyKexLdr/PyKexBoot 的注入行为 | 加白名单；或退回纯静态（`--restore` 后重跑 `--no-launcher`，或干脆 `--no-vxkex`） |
| 目标机上 numpy 报缺 libopenblas | vendored 摊平未做/被还原 | `python -m pywin7gate flatten` + `fix-all` |
| `Scripts\xxx.exe` 搬家后从旧路径加载/报错 | stub 内嵌绝对路径 | 用 `python -m <模块>` 或跑 `make_stub_bats.py` 生成 .bat |
| venv 创建后 venv 内 python 起不来 | 改名链被手工破坏 | 确认 venv 用的是 PyKexLdr 版 python.exe；重跑 build_pack |
| 进程一创建子进程就崩溃 | 运行时层改写引擎异常 | `PYW7DEBUG=1` 复现并看 `%TEMP%\pykexboot-dbg.log` 最后一行；`PYW7HOOK=0` 隔离是否为改写 hook |
| 某包调用 Win8+ API 运行期失败/崩溃 | Kx 实现的上游缺陷（覆盖是语法级的） | 查 `docs/design.md` §5.4 已知列表；如实记录并评估该包替代方案 |
| 工具（build_pack 等）在已改造树的 python 下跑出旧行为 | 该树 sitecustomize 预装了树内旧版 pywin7gate | 工具已内置模块逐出（强制用仓库代码）；自定义脚本请同样处理或直接换解释器 |

## 升级与换版本流程（3.9–3.14+）

工具链扫描驱动、无版本硬编码，换树即换目标：

1. `build_pack.py --restore` 还原旧树（可选；也可直接换新目录）；
2. 官方安装新版到同结构目录，把旧树 `Lib\site-packages\`、pip 隔离配置
   （pip.ini、local-pip.bat，若有）平移过来；
3. 重跑 `--dry-run` → 正式实施（脚本幂等；stem/入口 exe/核心 DLL 全部重新
   扫描自动适配；embeddable 树的 `python3XX._pth` 会被扩展后记录进 manifest）；
4. 重跑验收套件与打包。

注意点：新版若新增 Win8+ 导入，dry-run 会立刻暴露（"STILL MISSING"），按故障排查表处理（多半加一个 IAT 重定向条目即可；函数名太短放不下内置 donor 时用 `--donor` 显式指定）。

## License

本仓库自研代码（`src/`、`tools/`、`runtime/`、`tests/`、`docs/`）以 [GPL-3.0-or-later](LICENSE) 发布（`LICENSE` 文件为 GNU 官方原文）。`third_party/` 与 `assets/` 内的第三方资产**不受 GPL-3.0 约束**，分别由其各自权利人的条款管辖：VxKex NEXT 二进制（上游未附许可证，使用前需自行确认）、微软 KB2999226/VC++ 运行库（微软再分发条款）、YY-Thunks 数据库（MIT）。各项资产的来源、版本与许可证明细见 `third_party/README.md` 与 `assets/README.md`。
