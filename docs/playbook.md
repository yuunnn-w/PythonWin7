# 打包实战手册（playbook）

照做即可复现的实操要点合集：**build_pack 之外**的全部经验——目录内装包、批量安装、
已知包冲突、conda 独有资产移植、收尾与分发。前置：先按
[../README.md](../README.md) 的"快速开始"完成 build_pack 改造。

---

## 1. 目录内 pip 隔离（装包前必做）

分发树必须保证 pip 装的任何东西都落在树内（`Lib\site-packages` + `Scripts`）。
默认行为已是目录内安装，真正要防的是 `--user` 泄漏和开发机 PATH 阴影。两个文件
放**树根**：

`pip.ini`（site 级配置，优先级压过 user/global 级）：

```ini
[install]
user = false
```

`local-pip.bat`（安装 wrapper：`%~dp0` 自定位本树解释器，`--no-user` 兜住命令行 `--user`）：

```bat
@echo off
"%~dp0python.exe" -m pip install --no-user %*
```

**红线：`pip.ini` 必须纯 ASCII**——pip 按系统 ANSI 代码页解析它，混入中文（UTF-8）
会报 `Configuration file contains invalid cp936 characters` 且整个配置失效。

之后一律用 `local-pip.bat`（或全路径 `<树>\python.exe -m pip`）装包；不要把树加进系统 PATH。

## 2. 批量安装（推荐 uv）

- `uv pip install --python <树>\python.exe <包...>`，比 pip 快一个数量级；
- **`UV_CACHE_DIR` 必须指到与目标树同盘**——跨盘时硬链接退化为全量拷贝，在杀软
  实时扫描的机器上慢一个数量级；
- 代理：`--proxy http://127.0.0.1:7890` 或 `HTTPS_PROXY` 环境变量；PyPI 可直连时不用；
- 批量策略：整批安装，失败就从错误日志解析肇事包（**含被依赖牵连的间接包**），
  移出清单重试直至收敛；装不上的包（无对应 wheel）让安装器自动失败跳过并记录；
- **安装进行中不要跑导入测试**：python 进程锁住 DLL 会让安装器换包失败
  （`os error 5`），反之也会出现瞬时 import 假象；
- 中断（杀进程/关机）后体检三连：
  1. 删**双重 dist-info**（同包两个版本元数据并存 → `importlib.metadata.version()`
     返回 None）；
  2. 删**缺 METADATA 的 dist-info**（否则安装器报 `Failed to read metadata`）；
  3. 半安装的包：`uv pip install --python <树>\python.exe --force-reinstall --no-deps <包名>`。

## 3. 已知包坑速查

| 包 / 现象 | 要点 |
|---|---|
| `pyinstaller` | Win7 必须 `<6`（6 起官方弃 Win7），锁版本安装 |
| `numba` 生态 | numba 卡 numpy 上限（如 numba 0.62 要 numpy ≤2.3）；装完把 numpy/pandas/numba/sklearn 的版本组合核对回互相兼容 |
| 批量 resolve 把某包回退到古董版 | 装完后单独 `-U` 一次，再核对其连带升级的依赖 |
| `torch` / `torchaudio` | PyPI 的 Windows wheel 即 CPU 版，直接装即可；torchaudio 已停版（停在 2.11.x），与新 torch 可共存导入，深度使用有 ABI 风险时用 librosa/soundfile 替代；**不要**用 download.pytorch.org 索引（版本滞后易错位） |
| 新 wheel 引用 `vcruntime140_threads.dll` | 官方 CPython 树不带此文件；build_pack 已从 `assets/msvc-redist/` 自带进树根，老树手工补拷再 `fix-all` |
| wheel 自带哈希改名 CRT（`msvcp140-xxxx.dll`） | 门禁可能误报缺符号，属解析器已知限制；该 DLL 就是改名版官方 CRT，有树内 UCRT 即可加载 |
| 无新版 wheel 的包 / PyPI 不存在的包名 | 生态滞后或名字错误属客观缺口，跳过并用同类库兜底（示例：`pyqt5-tools` 只有 cp35~cp38 wheel、`sfepy` Windows 下编译失败、`pyfatigue`/`pyoptsparse` 包名不存在） |

## 4. 老包对新依赖的源码补丁（范例：acoustics）

`acoustics` 用了 scipy 已删除的 API（`sph_harm` 于 scipy 1.15 移除、`interp2d` 于 1.14
移除）。通法：定位报错行 → 找新 API 等价物 → try/except 双写 → 数值回归验证。已验证的
补丁（打进 `site-packages\acoustics\directivity.py`，注意 `sph_harm_y` 的 `(m,n)` 与
`(theta,phi)` 参数双双对调）：

```python
try:
    from scipy.interpolate import interp2d as interpolate
except ImportError:  # scipy>=1.14
    from scipy.interpolate import RectBivariateSpline as interpolate
try:
    from scipy.special import sph_harm
except ImportError:  # scipy>=1.15
    from scipy.special import sph_harm_y as _sph_harm_y

    def sph_harm(m, n, theta, phi):
        return _sph_harm_y(n, m, phi, theta)
```

## 4b. 弹窗抑制补丁（范例：jupyterlab 的 node 探测）

jupyterlab 每次启动会用 `which("node")` 沿 PATH 找 node 跑 yarn/node 版本探测；目标机
PATH 里的外部 node.exe（现代 Node 需 Win8+，常见于装有 Anaconda 的机器）在裸 Win7 上
加载失败会弹模态框并把 `check_output` 挂住。`build_pack` step 9 自动给
`site-packages\jupyterlab\commands.py` 打进以下补丁（幂等，jupyterlab 缺席则跳过）：
插入两个辅助函数，并用 SetErrorMode 包住 `_node_check` 与 `_yarn_config` 的探测调用
——错误模式被子进程继承，加载器失败静默化，函数照走原异常分支返回空配置。jupyter
lab 运行本身不依赖 node（仅构建扩展用），空配置无副作用。

```python
def _suppress_loader_popups():
    """On Windows, keep a broken child process (e.g. a Win8+-only node.exe
    found on PATH) from popping a modal loader dialog; the error mode is
    inherited by the child.  Returns the previous mode, else None."""
    if os.name != "nt":
        return None
    import ctypes
    SEM_FAILCRITICALERRORS = 0x1
    SEM_NOGPFAULTERRORBOX = 0x2
    SEM_NOOPENFILEERRORBOX = 0x8000
    return ctypes.windll.kernel32.SetErrorMode(
        SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX)


def _restore_error_mode(prev):
    if prev is not None:
        import ctypes
        ctypes.windll.kernel32.SetErrorMode(prev)
```

`_yarn_config` 改造示意（`_node_check` 同理，try 体内再嵌一层 try/finally 恢复错误
模式）：

```python
    _em = _suppress_loader_popups()
    try:
        output_binary = subprocess.check_output(
            [node, YARN_PATH, "config", "--json"], stderr=subprocess.PIPE, cwd=HERE)
        ...
    except Exception as e:
        logger.error(f"Fail to get yarn configuration. {e!s}")
    finally:
        _restore_error_mode(_em)
```

若 jupyterlab 大版本内部结构漂移导致自动补丁锚点失配，build_pack 会打印告警并跳过，
按上码手工补即可。同一手法适用于任何"拉起外部 Win8+ 进程探测"的包。

## 5. conda 独有资产移植（范例：pythonocc-core）

适用：包只在 conda-forge 有、pip 无 wheel（pythonocc-core 仅 cp312 构建）。**不要用
conda 直接装**（非 ASCII 路径会卡死、链接阶段在杀软机器上不可用），改为从 pkgs 缓存拷贝：

1. 跑一次 `conda create -p <任意路径> python=3.12 pythonocc-core=7.9.3 -c conda-forge -y`
   ——装失败也行，目的只是让包下载解压进 `<anaconda>\pkgs\` 缓存；
2. 从 pkgs 缓存按下表拷贝到树的 `Lib\site-packages\`：

   | 来源包（pkgs 内目录） | 取什么 | 放哪 |
   |---|---|---|
   | `pythonocc-core-*` | `Lib\site-packages\OCC\` 整目录 | `site-packages\OCC\` |
   | `occt-*` | `Library\bin\*.dll`（TK*.dll 全套） | `OCC\Core\` |
   | 依赖闭包（一次拷齐，免来回跑） | tbb12/tbbmalloc、freetype（包名是 **libfreetype6**）、FreeImage、jpeg8、libpng16、zlib、openjp2、libwebp/libwebpmux/libwebpdemux/libwebpdecoder、raw/raw_r、OpenEXR/OpenEXRCore/OpenEXRUtil/Iex/Imath、tiff、deflate/Lerc/liblzma/lcms2/openjph/zstd 各 dll | `OCC\Core\` |

3. 纯 Python 依赖补装：`uv pip install --python <树>\python.exe svgwrite`；
4. 验证（体积应为 6000.0，STEP/IGES Writer 可导入）：

   ```python
   from OCC.Core.BRepPrimAPI import BRepPrimAPI_MakeBox
   from OCC.Core.BRepGProp import brepgprop_VolumeProperties  # 7.9 起小写前缀
   from OCC.Core.GProp import GProp_GProps
   s = BRepPrimAPI_MakeBox(10, 20, 30).Shape()
   p = GProp_GProps(); brepgprop_VolumeProperties(s, p)
   assert abs(p.Mass() - 6000.0) < 1e-9
   from OCC.Core.STEPControl import STEPControl_Writer
   from OCC.Core.IGESControl import IGESControl_Writer
   ```

5. 已知例外：`OCC.Core.TKIVtk`（VTK 桥）不可用——conda 版 OCCT 要不带小版本号的
   `vtkCommonCore-9.6.dll`，pip 版 vtk 的 DLL 带全版本号，名字对不上。三维可视化走
   `BRepMesh` 剖分 → numpy → pyvista，不经 TKIVtk。

## 6. 收尾与分发检查单

1. `<树>\python.exe -m pywin7gate flatten` + `fix-all`（装包变更全部落盘后）；
2. 包升级删过文件后 `prune`，再 `verify` 应 0 问题；
3. `shims` 复核 Scripts 转换（走门禁装包会自动转换；此步手工兜底）；
4. `tests\test_win7_tree.py --tree <树>` 全绿（汇总行 `0 failed`）；
5. zip 整树 → 目标机解压即用（**零命令**；内部相对结构不可动）；
6. 门禁清单里的 `rejected` 不都是问题，三分类判读：**运行时层兜底类**（真缺 Win8+
   API 但 Kx*.dll 已导出同名实现，目标机经 PyKexLdr 注入后由内存改写救活）/
   **vendored 哈希名误报类**（见 §3 表）/ **环境真缺类**（该功能在原生 Windows 缺
   对应运行库时同样不可用）。详见 [../README.md](../README.md) 故障排查表与
   [testing.md](testing.md) 的口径说明。
