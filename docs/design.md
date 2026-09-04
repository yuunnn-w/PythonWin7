# PythonWin7 设计文档

> 本文记录架构与技术决策的依据。执行步骤见仓库 README，验证方法见 [testing.md](testing.md)。
> 机制考证的技术依据：Python 3.14.7 / 3.12.0 官方树（含 free-threaded 变体）的二进制导入表核对，以及 VxKex NEXT 1.2.3.2462 源码（`KexDll/`、`01-Extended DLLs/`）的逐文件阅读。

## 1. 统一路线：一条主路线，四层纵深

候选路线评估：

| 路线 | 做法 | 结论 |
|---|---|---|
| A. 目标机配套 | 目标机装 KB2999226 + 跑 KexSetup.exe | **出局**：违反"裸机、不打补丁、不装软件"约束；KexDll 进 system32 是全局改动 |
| B. 纯逐文件静态修补 | 树内补 DLL + 每个二进制 IAT 手术 | 可用但覆盖弱：新 wheel 要逐个重做；子进程场景依赖文件恰好落位 |
| **统一路线（采用）** | 静态文件层 + 引导 IAT + 树内运行时改写（注入+hook） + 门禁兜底 | 满足全部约束且对未来 wheel 有持续兜底 |
| C. 源码重编 | VC-LTL5 + YY-Thunks 重编 CPython | 工作量大；对 wheel 的预编译二进制毫无帮助；YY-Thunks 不覆盖 AddDllDirectory 仍需自写 thunk。维持备选 |

本方案收敛为一条主路线：运行时层默认安装，静态 IAT 从"主路线"降级为两个确定的小角色——

1. **引导（bootstrap）**：核心 DLL（python3XX.dll）的导入快照先于任何注入完成，其 Win8+ 静态导入必须离线修好，解释器进程才起得来、注入才发生得了。（3.14.x 为 2 条：KERNEL32!AddDllDirectory/RemoveDllDirectory → KxBase；3.12.0 为 7 条：上述 2 条 + CopyFile2/PssCaptureSnapshot/PssQuerySnapshot/PssFreeSnapshot → KxBase，外加 api-ms-win-core-path-l1-1-0.dll 整描述符换名 —— 3.12 树内不带该文件，3.14 起官方自带。条数只能扫描确定，不能按版本猜。扫描驱动，按扫描出的缺口打，不多打。）
2. **兜底（fallback）**：运行时层覆盖不了的形态——独立 .exe 的自有导入（子进程镜像的导入快照同样先于注入）、无 Kx 实现的函数——由门禁静态修。

加载期的主体覆盖交给**内存导入改写**（见 §5.3），wheel 的 pyd 不再逐文件动刀。

## 2. Python 3.14 在 Win7 的实际缺失（基于本树二进制的导入表核对）

工具：`tools/scan_tree.py`（纯 stdlib PE 解析）+ 裸 Win7 SP1 API 基线（`assets/baseline/x64/6.1.7600.txt`，YY-Thunks 数据库）。整树扫描（核心 + 标准库 pyd + numpy 全部二进制），缺失集合：

| # | 缺失 | 范围 | 处置 |
|---|---|---|---|
| 1 | `VCRUNTIME140[_1].dll`（13 符号） | 核心 + pyd | 树根已有（官方安装自带） |
| 2 | `api-ms-win-core-path-l1-1-0.dll!PathCchCombineEx/PathCchSkipRoot`（Win8.1+） | 仅核心 | 树根已有该 DLL |
| 3 | UCRT：`api-ms-win-crt-*` 12 套约 400 个符号位 | 核心 + pyd + numpy | KB2999226 私有部署（24 DLL 进树根） |
| 4 | `KERNEL32.dll!AddDllDirectory/RemoveDllDirectory`（Win8+ 真静态导入） | 仅 python314.dll / python314t.dll 各 2 处 | 引导 IAT 补丁 → KxBase.dll |

第三方依赖（libcrypto-3/libssl-3/libffi-8/libtommath/sqlite3/tcl90/tcl9tk90）全部已在树内 `DLLs\` 且对 Win7 基线**无独有缺失**。PE 头 OS/subsystem 版本 =6.0 ≤ 6.1，无 CPIW 拦截问题。

**这 4 类之外没有任何其他 Win8+ 独有静态导入**——这是"静态引导面积极小"的实证基础。注意"缺失面随版本单调变小"的直觉**不成立**：3.12.0 的引导缺口为 7 条（比 3.14.x 还多：python312.dll 静态导入 CopyFile2 与 PssCaptureSnapshot/PssQuerySnapshot/PssFreeSnapshot，且树内不带 api-ms-win-core-path-l1-1-0.dll）。3.11 及以前官方就支持 Win7，本包的贡献是免 KB2999226 前提 + 面向未来 wheel 的运行时保险。

## 3. IAT 补丁技术（src/pywin7gate/iatpatch.py）

### 3.1 函数级重定向（redirect）

把一个 by-name 导入从源 DLL 迁移到目标 DLL，同时**不碰其他任何导入**：

1. **donor 交换**：源描述符中被迁移函数的 hint/name 记录**就地改写**为一个更短的、目标 OS 上源 DLL 真实存在的函数名（donor）。donor 由 `pick_donor()` 从内置候选表（`DONOR_CANDIDATES`，kernel32: `GetLastError`/`Sleep`/`Beep` 等，按长度自动选第一个放得下的）自动选取，也可显式指定——受害名太短放不下内置候选的情形确实存在（3.12.0 的 `CopyFile2` 仅 9 字符，放不下 `GetLastError` 的 12 字符，自动选取会落到 `Sleep`）。loader 会把 donor 的有效地址写进受害 IAT 槽——无害占位。其它导入完全不动。（为什么不能把 thunk 清零：loader 遇 NULL 即停扫，会断掉其后所有导入；为什么不能压缩/重排 IAT：代码用绝对地址引用 IAT 槽。）
2. **追加描述符 + last-writer-wins**：新增一节 `.pyw7i`，把导入描述符表整体复制过去，末尾追加目标 DLL 的新描述符，其 `FirstThunk` 指向**同一个旧 IAT 槽**、其 ILT 指向新节里的新名字记录。loader 按表序处理，目标 DLL 的地址**后写覆盖** donor 占位。调用点透明地得到新目标。
3. 导入目录指针改指新表；NumberOfSections/SizeOfImage 修正；checksum 清零（用户态 loader 不校验）。原件备份为 `<file>.pyw7bak`，`--restore` 可回滚。

### 3.2 整描述符 DLL 换名（retarget）

donor 技术救不了"目标 OS 上根本没有这个文件"的 DLL 名（例如裸 Win7 无文件的 `api-ms-win-*` 名字）。此时把**整个描述符的 DLL 名字串原地替换**为目标名（长度不增、原地改写、必要时 VirtualProtect 加节内空间），IAT/ILT 不动。redirect 与 retarget 可在同一次 commit 里混合；bound import 描述符（TimeDateStamp≠0）拒绝操作。

默认引导重定向：`python3XX.dll[/t]` 的 `KERNEL32!AddDllDirectory`、`KERNEL32!RemoveDllDirectory` → `KxBase.dll`。`--no-vxkex` 时改指 `PyKexShim.dll`（自研 PATH 追加式模拟）。

## 4. UCRT 私有部署

- 文件来源：KB2999226（10.0.10240.16390，微软官方 Win7 目标构建），`tools/extract_kb2999226.py` 从 .msu 解出（expand.exe 两层 CAB，目标机不安装）。
- 清单：`ucrtbase.dll` + 16 个 `api-ms-win-crt-*-l1-1-0.dll`（CRT → ucrtbase 转发）+ 7 个 `api-ms-win-core-*`（Win7 官方转发，导出全部转发 kernel32）+ `api-ms-win-eventing-provider-l1-1-0.dll` = 24 个。
- 为什么不用 Win11 的 api-ms-win-core-* 文件：它们转发到 kernelbase.dll，Win7 没有。
- 符号覆盖：python314.dll/t + 67 pyd + numpy 23 二进制的 UCRT 符号并集对 10240 **零缺口**（唯一缺 `__uncaught_exceptions` 仅被 msvcp_win 引用 —— msvcp_win 在本方案中列为不支持，见 §7）。
- 备选：VxKex 预构建 ucrtbase 19041（Win10 目标构建），换文件即可切换，默认不用。

## 5. 运行时层（统一路线的核心）

### 5.1 VxKex 机制考证（为什么必须自研等价物）

阅读 VxKex NEXT 1.2.3.2462 源码可确认两件事：

1. **导入改写子系统只在 IFEO verifier 加载时激活**。`KexInitializeDllRewrite` / `KexRewriteImageImportDirectory` / DLL 通知回调整条链路仅在 `DLL_PROCESS_VERIFIER`（IFEO/AppVerifier 渠道加载）时挂接；纯 LoadLibrary 注入时 KexDll 的 DllMain 几乎什么都不做。且这些函数 **不在 KexDll.dll 的导出表**（导出列表中无 KexInitializeDllRewrite/KexDllNotificationCallback/KexRewriteImageImportDirectory/Ext_NtMapViewOfSection）。→ 想"零系统足迹"地使用 VxKex 的改写能力，只能按同一原理自研。
2. **VxKex 的原理**（本方案复刻的就是它）：hook `NtMapViewOfSection`，在 DLL 映射后、导入解析前，按 `KexDll/redirects.h` 表在**内存中**改写导入描述符的 DLL 名（kernel32→kxbase 等）；kxbase 再导出/转发宿主 DLL的全部表面并补齐 Win8+ 实现。

### 5.2 组件与触发链

- **PyKexLdr**（启动器，顶替入口 exe）：通用解析——扫描同级 `python3*.dll`得版本 stem（"39"…"314t"；排除 python3.dll/python3t.dll 稳定 ABI shim），按自身文件名尾 `t` 选 free-threaded 变体，`PYW7_GUI` 编译开关选 pythonw。找不到（≤3.12 复制式 venv 里启动器被复制到 Scripts\）则回退读上级 `pyvenv.cfg` 的 `home=` 行解析，并设 `__PYVENV_LAUNCHER__`=自身路径（getpath.py 3.11+ 用它识别 venv）。3.13+ venv 是 redirector exe（读 pyvenv.cfg home 执行基树 python.exe=启动器），链路天然闭合。命令行**原样透传**（venv 的 argv[0] 语义依赖这一点）。挂起创建真解释器 → 依次远程注入 KexDll.dll、PyKexBoot.dll → 恢复主线程。
- **KexDll.dll**：仅作原语提供者（KexHkInstallBasicHook inline hook 引擎、KexNt* 直接 syscall 封装、KexPatchCpiwSubsystemVersionCheck）。
- **PyKexBoot.dll**：注入后挂两个 hook + CPIW 补丁：
  1. `NtCreateUserProcess` hook → 子进程强制挂起+放宽句柄 → watcher 线程轮询 Toolhelp 快照至 kernel32 映射后注入同套 DLL（递归任意深度，上限 3 秒，超时/失败降级为无 Kex 运行，绝不卡死子进程）。
  2. `NtMapViewOfSection` hook → 内存导入改写引擎（§5.3）。

与官方 VxKex 的差异（都为满足零系统足迹）：官方靠注册表 IFEO（全局、需管理员）触发与传播；本方案全部在进程内完成。

### 5.3 内存导入改写引擎（PyKexBoot）

- 数据源：`g_Redirects` 表 167 条，蒸馏自 VxKex `redirects.h`（同一映射），**剔除** api-ms-win-crt→ucrtbase 条目（树内有真 KB2999226 文件，直接解析更优）。`src/pywin7gate/fixers.py` 的 `RUNTIME_REDIRECT_PAIRS` 是它的 Python 镜像，验收套件 S 组强制两表一致。
- 归一化：小写、去 `.dll`、api-/ext- 名字去 `-lX-Y-Z` 7 字符后缀后查表。
- 双表走查：导入表 + 延迟导入表（ImgDelayDescr.Attributes bit0=RVA 才处理）；改写后清零 bound-import 目录（原 bound 地址在 DLL 替换后无效）。
- 策略豁免：路径含 `\windows\` 的 OS 文件不动；基名 `kx*`/`api-ms-win-*`/`vcruntime140*`/`msvcp140*`/`pykex*`/`kexdll*`/`ucrtbase` 不动；路径查询失败保守跳过。
- **内存安全（无 SEH 的 CRT-free 构建，全显式边界检查）**：改写前先用 `KexNtQueryVirtualMemory`（MemoryBasicInformation）探测——仅处理 `MEM_COMMIT + MEM_IMAGE + 可读` 的视图。必要性：watcher 依赖的 Toolhelp 进程快照在 Win10 内部会把 PSS 快照段映射进本进程，这类 MEM_MAPPED 视图首字节可读性不受控，不探测直接按 PE解析会把整个进程读崩（access violation）。其余护栏：描述符上限 512、名单上限 64 字节、一切 RVA 对 SizeOfImage 校验。
- 生效范围的界定（"Not covered by design"）：注入前已映射的映像（解释器核心——由静态文件层 + 引导补丁负责）与子进程镜像自身的静态导入（快照先于注入——由门禁静态修）。

### 5.4 Kx 覆盖度（对 assets/baseline/x64/6.1.7600.txt）

| Kx 模块 | 覆盖宿主 DLL 导出 | 缺口 |
|---|---|---|
| KxBase | kernel32 1378/1386 | 8 个 xstate 函数 |
| KxNt | ntdll 1981/1983 | 2 |
| KxUser/KxAdvapi/KxNet/KxCryp/KxCrt/KxCom | 100% | 0 |

**Kx 覆盖是语法级的**（导出表对齐），个别实现有上游缺陷：已知VxKex-NEXT 1.2.3.2462 `KxBase!GetThreadDescription` 实现有栈损坏 bug（给 NtQueryInformationThread 传 `&Description` 而非 `Description`，调用即栈损坏/访问违例），且 Get/SetThreadDescription 依赖的 `ThreadNameInformation` 原语 Win7 没有。验收探针 DLL（tests/testdll）因此选用三个实现自包含的 Win8+ API（GetSystemTimePreciseAsFileTime / GetCurrentThreadStackLimits / IsWow64Process2）。

## 6. 第三方 wheel 门禁（pywin7gate）

三层触发，同一份引擎（`gate.py`）：

1. **打包时**：`build_pack.py` 对已装包的 site-packages 全量过门禁；
2. **装包时**：`python -m pywin7gate pip install ...`（pip 成功后自动 fix-all）；
3. **import 时**：`Lib/sitecustomize.py` 装的 audit hook 兜住"绕过上两条"的 pyd（手工复制进树的、用裸 pip 装的），未过门禁现场修，修不了抛 ImportError 并给原因。

判读表（对每个无法解析的导入；runtime 模式 = 树内有 PyKexBoot.dll + KexDll.dll，可自动检测或由 build_pack 显式给出）：

| 缺口 | 动作 |
|---|---|
| 私有包文件覆盖（api-ms-win-crt-*/vcruntime140/msvcp140/Kx*/树根各 dll） | 放行；若是子目录里的 .exe 则把运行时包铺到其目录（stamp 防重） |
| 系统 DLL 的 Win8+ 新函数，有 Kx 实现 | **runtime 模式且非 .exe → runtime-cover，不动文件**；否则 IAT 重定向（备份 .pyw7bak） |
| 未知 DLL，名字在运行时重定向表 | 同上分流（runtime-cover 或整描述符 retarget） |
| 未知 DLL，site-packages 内有 vendored 副本 | 复制到每个引用它的 .pyd 旁（delvewheel `<pkg>.libs` 惯例） |
| msvcp_win / icuuc / dwrw10 / mfdevmgr / mshtmlmedia | **拒装**（裸 Win7 无解，Chromium 系依赖） |
| 以上都不行 | **拒装**，报告确切 blocker |
| distlib 启动器模板（w32/w64/t32/t64(-arm).exe） | 免检（不是直接加载的镜像） |

.exe 一律走静态修：子进程镜像的导入快照先于注入完成（§5.3 的边界）。所有修复写入 `Lib\site-packages\.pywin7-gate-manifest.json`（前后 SHA-256、动作、产物清单），`python -m pywin7gate verify` 校验、`restore` 回滚单文件。

**delvewheel 摊平（flatten_vendored）的必要性**：KxBase 的 AddDllDirectory 模拟不改动真 loader 搜索路径，numpy 这类靠 `os.add_dll_directory(numpy.libs)` 加载vendored DLL 的包在 Win7 上会失败——门禁预先把 vendored DLL 复制到引用者旁边，让 loader 的"应用目录/同目录"规则天然命中。摊平产物记入`pywin7-pack-manifest.json`，`--restore` 可完整清退。

## 7. 明确不支持的项

- `msvcp_win.dll`（依赖 `ResolveDelayLoadedAPI`，Win7 无真实现；且 10240 ucrtbase缺其引用的 `__uncaught_exceptions`）——多数 wheel 不需要它。
- Chromium 系私有 DLL（dwrw10/icuuc/mfdevmgr/mshtmlmedia）。
- 32 位 Python / 32 位子进程注入（KB x86 文件集已备在 `assets/kb2999226/x86/`，如需可做对应的 32 位 PyKexBoot）。
- 调用方自求 CREATE_SUSPENDED 的子进程不注入（永远不恢复就永远不映射 kernel32；文档化的降级场景，实践中极少遇到）。

## 8. 与 VC-LTL5 / YY-Thunks 的关系

- 自研 C 组件全部 CRT-free（`/NODEFAULTLIB`，仅 kernel32.lib），**不需要** VC-LTL5。
- YY-Thunks 的 .obj/.lib 形态只对**链接期**有效，管不到预编译第三方 DLL；其**分析器数据库**（API 基线）是本方案门禁判据，其分析器 exe 可用于人工复核。
- 若未来遇到 Kx* 未覆盖且无法静态重定向的缺口，扩展方向是用 YY-Thunks 源码编一个兜底 DLL（"pythunk.dll" 思路）按同一 IAT 引擎接入；当前版本未包含这一组件。

## 9. 杀软/EDR 注意事项

运行时层使用 VirtualAllocEx + WriteProcessMemory + CreateRemoteThread 做远程注入，这是杀软/EDR 的重点盯防行为。全部注入目标都是本进程树内的 Python 后代进程、载荷是随树分发的白文件，但**部署前务必在目标环境的杀软策略下实测**。纯静态回退路线（`--no-vxkex`）不用任何注入。
