# 贡献指南

感谢参与 PythonWin7。本仓库的目标是：给任何官方 CPython 3.9+ x64 树打补丁，
使其能在**裸 Windows 7 SP1 x64**（不打补丁、不装软件、无需管理员）上以自包含、
可整体搬迁的方式运行。改动请围绕这一目标展开，并保持与现有实现风格一致。

## 报告问题

Issue 中请附上：

- 目标树来源与版本（官方安装版 / embeddable、3.12.0 / 3.14.7 / …，是否 free-threaded）；
- 目标机环境（裸 Win7 SP1 x64 的补丁状态、杀软，若相关）；
- 复现命令与完整输出；`build_pack.py --dry-run` 输出最能说明问题；
- 运行时层相关问题先设 `PYW7DEBUG=1` 复现，并附 `%TEMP%\pykexboot-dbg.log` 尾部。

## 开发环境

- 任意现代 Windows + 任意一套 Python 3.9+（跑工具用，纯 stdlib，无第三方依赖）；
- 重编 `runtime/` 下的 C 组件需要 Visual Studio 2022（社区版即可）；预编译产物
  随仓库附带，日常开发通常不需要重编；
- 改造目标树时必须用**另一套**解释器跑工具（`build_pack.py` 会检测并拒绝用被改造
  树自己的 `python.exe`）；
- 涉及 Win7 行为的问题只能在真实 Win7 SP1 环境验证，开发机验收不能替代，见
  `docs/testing.md`。

## 提交前检查

1. 语法检查与工具自检：

   ```bat
   python tools\build_pack.py --help
   python tests\test_win7_tree.py --tree <已改造树>
   python tests\test_isolation.py --tree <已改造树>
   ```

2. 改动涉及第三方资产时同步更新 `third_party/SHA256SUMS.txt` 并附来源与许可证说明；
3. 改动涉及文档中的步骤编号、命令或文件名时，同步更新 `README.md` / `docs/`；
4. **不要提交本机绝对路径、用户名、内网主机名或构建产物**（`__pycache__`、
   `*.pyw7bak`、manifest 等已在 `.gitignore` 中排除；`runtime/`、`assets/`、
   `third_party/` 中的预编译二进制是项目资产，必须保留）。

## 代码约定

- Python 代码纯 stdlib（目标机没有额外依赖可装），保持对 Python 3.9+ 可解析；
- C 组件保持 CRT-free（`/NODEFAULTLIB`，仅 kernel32），不要引入 UCRT 依赖；
- 二进制修补、注入与内存改写相关改动必须保留既有的显式边界检查与降级路径；
- 面向外部的文字（README、docs、CLI 帮助）用简洁的说明性语言，不写开发过程记录。

## 许可证

提交即表示同意以 [GPL-3.0-or-later](LICENSE) 授权你的贡献。`third_party/` 与
`assets/` 内的第三方资产受各自权利人条款约束，新增第三方资产前请确认其再分发条款。
