# assets — 打包所需的外部资产清单

本目录收纳打包流程所需的第三方/系统资产，全部为官方来源的原样拷贝。

## kb2999226/ — Universal C Runtime（UCRT）私有部署文件集

| 项 | 内容 |
|---|---|
| 名称 | KB2999226 — Update for Universal C Runtime in Windows |
| 来源 | 微软官方更新包 `Windows6.1-KB2999226-x64.msu`（本目录内含原件拷贝） |
| 版本 | 10.0.10240.16390 (th1_st1.150714-1601)，全部 24 个 DLL 同版本 |
| 许可证 | 微软软件许可条款（随 Windows 更新分发；作为 UCRT 可再分发运行时的组成部分使用） |
| 修改 | 无（用 `tools/extract_kb2999226.py` 从 .msu 解出，未改字节） |

- `amd64/`：`ucrtbase.dll` + 15 个 `api-ms-win-crt-*-l1-1-0.dll`（CRT 转发到 ucrtbase）
  + 7 个 `api-ms-win-core-*` Win7 官方转发文件（导出全部转发 `kernel32`）
  + `api-ms-win-eventing-provider-l1-1-0.dll` = 24 个 DLL。这是**默认 UCRT 来源**：
  微软官方 Win7 目标构建，裸 Win7 SP1 风险最低。
- `x86/`：同套 32 位文件（备用，当前方案仅交付 x64）。
- **目标机不安装此 KB**；这些 DLL 由 `tools/build_pack.py` 复制到 Python 树根做私有部署
  （应用目录在 DLL 搜索序中优先于 system32）。

备选来源（未采用）：VxKex 源码树 `02-Prebuilt DLLs/x64/ucrtbase.dll`
（10.0.19041.789，Win10 目标构建，符号覆盖更宽但非 Win7 官方件）。

## msvc-redist/ — MSVC++ 2015-2022 运行库

| 项 | 内容 |
|---|---|
| 名称 | Visual C++ Redistributable for Visual Studio 2015-2022（x64 CRT 组件） |
| 来源 | VS2022 安装目录 `VC\Redist\MSVC\14.44.35211\x64\Microsoft.VC143.CRT` |
| 版本 | 14.44.35211.0 |
| 许可证 | 微软可再分发组件（Distributable Code，随 VS 许可允许随应用分发） |
| 修改 | 无 |

`msvcp140.dll` / `msvcp140_1.dll` / `msvcp140_2.dll`：CPython 核心**不需要**，
为后续 pip 安装的 C++ 扩展 wheel（numpy 一类）预备——很多 wheel 不自带 C++ 运行时。
如需更新，从本机 VS2022 的 `VC\Redist\MSVC\<版本>\x64\Microsoft.VC143.CRT`
目录提取替换即可。

`vcruntime140_threads.dll`：14.51.36247（来源：conda-forge `vc14_runtime`
包的原样拷贝，同为微软可再分发组件）。新版 wheel（如 numpy 2.5 / sklearn 1.9）
开始引用其中的 `mtx_*` C++ 互斥函数，缺失会让门禁成片拒修；CPython 官方树不附带，
必须随包部署。

## baseline/ — 各 Windows 版本 API 导出数据库

| 项 | 内容 |
|---|---|
| 名称 | YY-Thunks 分析器配置数据库（`Config/x64/6.1.7600.txt`） |
| 来源 | YY-Thunks v1.2.2 发布包，https://github.com/Chuyu-Team/YY-Thunks |
| 许可证 | MIT |
| 修改 | 无（原样拷贝） |

- `x64/6.1.7600.txt`：裸 Windows 7 SP1 x64 每个系统 DLL 的完整导出表
  （INI 格式：`[dllname]` + `ordinal=FuncName`）。
  是"某 API 在裸 Win7 上是否存在"的判据来源。
- `tools/make_baseline.py` 把它压缩成 `src/pywin7gate/baseline_6_1_7600.json`，
  随 Python 树分发（目标机上没有 YY-Thunks 也能跑门禁）。

同一数据库的 GUI 分析器 `YY.Depends.Analyzer.exe` 在
`third_party/yy-thunks/YY-Thunks-Objs.zip` 内（体积大且仅开发机用，
不单独入仓），需要时从 zip 解出即可。
