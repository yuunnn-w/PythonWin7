# Changelog

本项目遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/) 的组织方式，
版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

## [0.1.0] - 2026-09-10

首个公开版本。

### 新增

- 统一改造路线：静态文件层（KB2999226 UCRT + MSVC 运行库私有部署）、引导 IAT
  补丁（`tools/build_pack.py` + `src/pywin7gate/iatpatch.py`）、运行时注入改写
  （`runtime/PyKexLdr`、`runtime/PyKexBoot`，含预编译产物）、安装门禁
  （`src/pywin7gate`）与可搬迁 `Scripts\*.exe` shim（`runtime/PyKexExe`）；
- 环境隔离层（隐士树）：启动器清 `PYTHONHOME`/`PYTHONPATH`/`PYTHONSTARTUP`，
  `src/sitecustomize.py` 清洗 PATH / `sys.path` / user site 与 `CONDA_*`、
  `VIRTUAL_ENV`，使目标机上其他 Python/Anaconda 不干扰本树；
- 一键打包/回滚：`tools/build_pack.py`（扫描驱动、幂等、`--dry-run`/`--restore`、
  `--no-vxkex`/`--no-launcher` 回退路线）；
- 验收套件：`tests/test_win7_tree.py`（G0–G5+S）与 `tests/test_isolation.py`
  （I1–I7），开发机与裸 Win7 SP1 目标机通用；
- 随仓库分发的运行时资产：KB2999226 UCRT 文件集、MSVC redist、VxKex NEXT
  1.2.3.2462 二进制、YY-Thunks v1.2.2 基线数据库与 SHA-256 校验；
- 文档：`docs/design.md`（架构与技术决策）、`docs/testing.md`（验证指南）、
  `docs/playbook.md`（打包实战手册）、`docs/packages.md`（离线环境推荐包清单）。

### 已知限制

见 [README.md](README.md) 的"已知限制"节。
