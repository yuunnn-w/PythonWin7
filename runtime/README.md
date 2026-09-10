# runtime — 自研 C 组件

四个组件全部 **CRT-free**（`/NODEFAULTLIB`，仅 import kernel32.dll），
因此在裸 Win7 SP1 上自身零依赖、零 UCRT 导入，不需要 VC-LTL/YY-Thunks。
构建需要 Visual Studio 2022（社区版即可）；每个子目录里的 `build.bat`
先 `call vcvars64.bat`（路径写在脚本头部，按需修改）再 `cl` 编译。
全部产物已随仓库预编译，无 VS2022 时可直接使用。

| 组件 | 产物 | 作用 |
|---|---|---|
| `PyKexLdr/` | `PyKexLdr.exe`（console）/ `PyKexLdrW.exe`（GUI，`/DPYW7_GUI`） | **通用入口启动器（任意 Python 3.9+ 树）**。打包时顶替树里实际存在的入口 exe（`python.exe`/`pythonw.exe`/`pythonX.Y.exe`/`pythonX.Yt.exe`……，原 exe 改名版本名如 `python314.exe`）。版本解析零硬编码：扫描同级 `python3*.dll` 得 stem（排除 `python3.dll`/`python3t.dll` 稳定 ABI shim），按自身文件名尾 `t` 选 free-threaded 变体；找不到时按 venv 回退（读上级 `pyvenv.cfg` 的 `home=`，UTF-8 解码，并设 `__PYVENV_LAUNCHER__` 供 getpath.py 识别 venv）。3.13+ 的官方 venv 重定向器（`venvlauncher.exe`，静态导入 api-ms-win-core-path，裸 Win7 起不来）由 build_pack 一并替换为本启动器，故 venv 回退对全版本生效。然后挂起创建真解释器 → 依次远程注入 `KexDll.dll`、`PyKexBoot.dll` → 恢复主线程 → 透传退出码。命令行**原样透传**（venv 的 argv[0] 语义依赖这一点）。注入失败不阻塞启动（降级为纯静态树）。环境隔离的启动期闸门也在这里：`CreateProcess` 前清 `PYTHONHOME`/`PYTHONPATH`/`PYTHONSTARTUP`、置 `PYTHONNOUSERSITE=1`（宿主机的其他 Python/Anaconda 配置无法劫持解释器的 stdlib/site-packages 解析；进程内一半见 `src/sitecustomize.py`，设计细节见 `docs/design.md` §6b） |
| `PyKexBoot/` | `PyKexBoot.dll` | 进程内兼容引导。被注入后挂两套机制：① `NtCreateUserProcess` hook + watcher 线程——每个子进程强制挂起+放宽句柄权限，watcher 轮询 Toolhelp 快照至 kernel32 映射后远程注入同套两个 DLL（递归任意深度；上限 3 秒，超时/失败降级）；② `NtMapViewOfSection` hook——**加载期内存导入改写引擎**：每个后映射的 PE 映像在导入快照前按 `g_Redirects` 表（167 条，蒸馏自 VxKex redirects.h）把导入描述符里的 DLL 名原地改写为 Kx*.dll，使 wheel 的 pyd 免逐文件修补即可在 Win7 加载。仅处理 `MEM_COMMIT+MEM_IMAGE+可读` 视图（先探测再解析，CRT-free 无 SEH 全靠显式边界检查）。另有 CPIW 子系统版本检查绕过（`KexPatchCpiwSubsystemVersionCheck`）。`PYW7HOOK=0` 关改写 hook，`PYW7DEBUG=1` 写低频诊断到 `%TEMP%\pykexboot-dbg.log` |
| `PyKexShim/` | `PyKexShim.dll` | `--no-vxkex` 回退路线的 IAT 重定向目标：`AddDllDirectory` 用"追加 PATH"模拟（LoadLibrary 标准搜索会拾取），`RemoveDllDirectory` 校验 cookie 后返回 TRUE。仅在不用 VxKex 二进制时由 build_pack 选用 |
| `PyKexExe/` | `PyKexExe.exe`（console）/ `PyKexExeW.exe`（GUI，`/DPYW7_GUI`） | **可搬迁的 Scripts shim stub**。替换 pip 生成的 distlib stub 后，shim 布局为 `[stub]["#!pyw7-relocatable" [参数]][zip 负载]`，不再内嵌任何绝对路径。运行时按自身相对位置解析解释器（同级 `python[w].exe` → venv\Scripts；上一级 → 树\Scripts），从自身文件读出 marker 行里的解释器参数，再以 `python.exe <shim自身> <原参数...>` 启动（CPython 将 shim 当 zipapp 执行，zip 负载经 EOCD 定位、与 stub 大小无关），等待子进程并透传退出码。整树移动/改名/拷贝后开箱即用、零命令。build_pack 把它复制到树根并转换 `Scripts\*.exe`；`python -m pywin7gate shims` 可随时补转（stub 字节漂移时自动刷新既有 shim）。与 PyKexLdr 一样在拉起解释器前执行环境隔离的启动期闸门（清 PYTHONHOME/PYTHONPATH/PYTHONSTARTUP、置 PYTHONNOUSERSITE=1） |

## 设计要点

- **不在 hook 里立刻注入**：`NtCreateUserProcess` 返回时子进程只映射了镜像与 ntdll，
  kernel32 尚未加载，无法 LoadLibrary。因此注入由 watcher 线程在 kernel32 出现后执行
  （轮询上限 3 秒，超时放弃，子进程照常运行）。
- **调用方要求 CREATE_SUSPENDED 的子进程不会被注入**（它永远不恢复就永远不映射 kernel32）；
  这是有文档记录的降级场景，实践中极少遇到。
- **WOW64（32 位）子进程跳过注入**（当前仅交付 x64）。
- **改写引擎的安全边界**：内存改写只发生在 `MEM_IMAGE` 视图上，且路径含
  `\windows\` 的 OS 文件与本方案自有文件（kx*/pykex*/kexdll/ucrtbase 等）一律豁免；
  路径查询失败保守跳过。watcher 依赖的 Toolhelp 进程快照会把 PSS 快照段映射进
  本进程，这类 MEM_MAPPED 非映像视图的首字节可读性不受控，直接按 PE 解析会导致
  access violation，因此改写前一律显式探测拦截。
- PyKexBoot 全部失败降级：最坏情况 = 子进程以"无 Kex"状态运行，
  而静态文件层本身已保证树内二进制可加载，运行时层是覆盖面增强。

机制原理与选型论证见 [../docs/design.md](../docs/design.md)；验证方法见
[../docs/testing.md](../docs/testing.md)。
