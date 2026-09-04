# 测试与验证

> 本文说明如何验证一棵改造后的 Python 树：开发机上的验收套件（G0–G5+S）
> 与 Win7 SP1 目标机上的验证清单。架构与机制依据见 [design.md](design.md)。

## 1. 验收套件（tests/test_win7_tree.py）

纯 stdlib 脚本，开发机与 Win7 目标机通用，对被测树做"能启动、能 import、能干活、运行时改写生效、静态零缺失"五个层面的验收：

```bat
rem 任意一套 3.9+ 解释器跑脚本（不要用被测树自己的 python.exe 跑）
py tests\test_win7_tree.py --tree <PYTHON_DIR>

rem 只跑部分分组：
py tests\test_win7_tree.py --tree <PYTHON_DIR> --groups G0,G1,S

rem 跳过 S 组静态扫描（树很大时可省时间）：
py tests\test_win7_tree.py --tree <PYTHON_DIR> --skip-static
```

参数：`--tree` 被测树目录；`--python` 显式指定被测解释器；`--groups` 逗号分隔的分组列表（默认 `G0,G1,G2,G3,G4,G5,S`）；`--skip-static` 跳过 S 组。

### 分组与检查内容

| 组 | 内容 |
|---|---|
| G0 | 解释器启动 + 版本核对（按树的 python3XX.dll stem 自动判定预期版本） |
| G1 | 标准库二进制模块 import（ssl/sqlite3/ctypes/lzma/bz2/zstd/tkinter…） |
| G2 | 功能冒烟：SSL 上下文、ctypes 调用、add_dll_directory、时间源、zlib、sqlite |
| G3 | 第三方（装了 numpy 则跑 linalg）+ subprocess + multiprocessing spawn |
| G4 | venv 创建 + venv 解释器 prefix 检测 |
| G5 | 运行时改写探针：`tests/testdll/TestWin8Api.dll`（静态导入 3 个 Win8+ kernel32 API：GetSystemTimePreciseAsFileTime / GetCurrentThreadStackLimits / IsWow64Process2）不改文件直接 ctypes 加载；加载后其内存导入描述符应变为 `kxbase.dll`、3 个 API 调用成功；负对照 `PYW7HOOK=0` 时描述符保持 `KERNEL32.dll` |
| S | 静态验收：`tools/scan_tree.py` 全树零缺失 + 门禁清单哈希校验 + C 端 `g_Redirects` 与 Python 端 `RUNTIME_REDIRECT_PAIRS` 重定向表一致性 |

### 通过标准

- 所有分组 PASS；G3 在未安装 numpy 时该项记跳过不算失败；
- S 组要求 `missing=0`、门禁清单 0 问题、两表一致；
- 该套件在官方 3.14.7（普通 + free-threaded）与 3.12.0 树上全部通过。`--no-vxkex` 回退路线下 G5 不适用（无运行时层），跑 G0–G4+S 即可。

## 2. 在真实 Win7 SP1 硬件/虚拟机上验证

开发机（Win10/11）的验收不能替代 Win7 目标机验证——loader 细节、ucrtbase 10240 在裸 SP1 的运行时行为、tcl/tk GUI、杀软对注入行为的反应只有在目标环境才能暴露。打包分发前，在裸 Win7 SP1 x64 环境（虚拟机即可）按以下清单验证。

假设树解压到 `C:\Python314`（路径任意）：

```bat
set PY=C:\Python314
%PY%\python.exe -V                                                     :: G0 启动
%PY%\python.exe -c "import os,sys,json,zlib,sqlite3,_socket,ssl,select,_ctypes,ctypes,_hashlib,_asyncio,_multiprocessing,multiprocessing,_winapi; print('G1 ok')"
%PY%\python.exe -c "import ssl; c=ssl.create_default_context(); print('G2a ok', bool(c.get_ciphers()))"
%PY%\python.exe -c "import os; d=os.add_dll_directory('C:\\'); print('G2b ok'); d.close()"
%PY%\python.exe -c "import multiprocessing as m; q=m.Queue(); q.put(1); assert q.get()==1; print('G2c ok')"
%PY%\python.exe -m pywin7gate verify                                   :: 门禁清单
%PY%\python.exe -m pip freeze                                          :: G3 包清单
rem 仓库在目标机上可见时跑全组：
py tests\test_win7_tree.py --tree %PY%
```

在此基础上再做以下检查：

- **传播链抽查**：从 python 拉起 `cmd /c ping -n 20 127.0.0.1`，用外部工具（Process Explorer 等）枚举该子进程的模块表，应含 `KexDll.dll` 与 `PyKexBoot.dll`。（不要用 `timeout` 命令做测试子进程——句柄重定向下它会立即退出。）
- **G5 探针**：确认 TestWin8Api.dll 的内存导入描述符变为 kxbase.dll 且 3 个 API 调用成功。
- **系统日志**：事件查看器检查 SideBySide / 应用程序错误日志。
- **os.system 链**：cmd 孙进程的递归注入。
- **杀软/EDR**：运行时层依赖远程注入，在目标环境的杀软策略下确认无拦截，必要时加白名单或退回 `--no-vxkex`。
- 诊断：`PYW7DEBUG=1` 后运行时层向 `%TEMP%\pykexboot-dbg.log` 写低频事件日志。任一失败按 README 故障排查表处理。

已知需在真机留意的点：KxBase 的 AddDllDirectory 模拟在 Win7 上走的是模拟路径（开发机上走的是真 API），其主要受害场景（delvewheel 包）已由门禁的vendored 摊平静态化解；3.9/3.10 的 venv 链路（getpath.c 时代）建议在真机顺带验证。

## 3. 第三方资产校验

`third_party/` 与 `assets/` 内的第三方二进制均为官方发布物的原样拷贝，用 SHA-256 校验文件核对：

```bash
cd third_party && sha256sum -c SHA256SUMS.txt --ignore-missing
```

期望全部 `OK`；缺失文件（`--ignore-missing` 跳过的）需按 [third_party/README.md](../third_party/README.md) 的获取指引补齐后再验。

各资产与官方发布物的一致性亦可人工复核：

- `third_party/vxkex/`：用 7-Zip 解开官方安装包 `KexSetup_Release_1_2_3_2462.exe`，其中 `Core64/KexDll.dll` 、 `Kex64/Kx*.dll` 应与仓库同名文件逐字节一致；
- `third_party/yy-thunks/YY-Thunks-Objs.zip`：其中 `Config/x64/6.1.7600.txt`应与 `assets/baseline/x64/6.1.7600.txt` 逐字节一致；
- `assets/kb2999226/`：DLL 可由 `tools/extract_kb2999226.py` 从 .msu 原件重新解出对比。
