# 离线 / 内网环境 Python 包清单（推荐）

本清单给出一套在**离线、无外网**环境里可用的 Python 包组合，按用途分成 22 类，
并标注核心程度与兼容性风险。它针对的是本仓库的典型使用场景：

- 目标机为裸 Windows 7 SP1 x64，使用经
  [PythonWin7](../README.md) 改造后的自建 Python 3.12 / 3.14 树；
- 机器不能联网，所有 wheel 需预先在联网机下载、离线转运安装；
- 覆盖工程计算、数据处理、办公文档、桌面自动化与 Agent/LLM 开发等常见方向。

机器可读版本见 [`examples/requirements.txt`](../examples/requirements.txt)
（PyTorch 三件套单独在 [`examples/requirements-torch-cpu.txt`](../examples/requirements-torch-cpu.txt)）。
清单与 requirements 文件的差异见文末附录 A。

## 使用说明

1. **双树策略**：Python 3.12 树为主力，全量安装；Python 3.14 树只装子集 ——
   不少原生扩展（尤其 Rust 轮子）尚无 cp314 wheel，torch 等大件对 3.14 的支持
   也需届时确认。
2. **纯 CPU**：深度学习栈一律用 CPU 版 wheel（PyTorch 官方 CPU 源），不引入
   任何 CUDA 依赖。
3. **同功能去重**：同一功能只保留 1~3 个高星常用库；标"（可选）"的按需安装。
4. **标记说明**：
   - ⭐ 核心必装
   - （可选）按需安装
   - ⚠️ 需要额外二进制/外部组件（离线环境需另行部署，见文末外部组件清单）
   - ❗ Win7 或 cp314 兼容性需实测验证
   - 🆕 基础清单之外的补充推荐
5. 明确排除的库（TensorFlow、PyQt6/PySide6、其他 Agent 框架等）及原因见文末。

---

## 一、基础科学计算

| 包名 | 用途 | 标记 |
|---|---|---|
| numpy | 数组计算基石 | ⭐ |
| scipy | 科学计算全家桶（优化/插值/信号/统计） | ⭐ |
| sympy | 符号计算、公式推导 | ⭐ |
| mpmath | 任意精度数值计算 | |
| numba | JIT 加速数值循环 | ❗ |
| numexpr | 数组表达式加速 | |
| bottleneck | 移动窗口统计加速 | |
| PyWavelets | 小波变换（振动/声信号分析常用） | ⭐ |

## 二、数据处理与文件格式

| 包名 | 用途 | 标记 |
|---|---|---|
| pandas | 表格数据处理 | ⭐ |
| polars | 高性能 DataFrame（Rust） | ❗ |
| xarray | 多维标注数组 | |
| dask | 并行/超内存数据框 | （可选） |
| pyarrow | Parquet/Feather/Arrow | ⭐ |
| h5py | HDF5 读写 | ⭐ |
| tables | PyTables（HDF5 分层查询） | ❗ |
| netCDF4 | netCDF 网格数据 | ❗ |
| zarr | 分块数组格式 | （可选） |
| orjson | 高速 JSON（Rust） | ❗ |
| msgpack | 二进制序列化 | |
| jsonlines | JSONL 流式读写 | |
| jsonschema | JSON 结构校验 | |
| xmltodict | XML↔dict | |
| lxml | XML/HTML 高性能解析 | ⭐ |
| beautifulsoup4 | HTML 容错解析 | ⭐ |
| regex | 增强正则（Unicode/中文友好） | |
| charset-normalizer | 编码探测 | |
| py7zr | 7z 压缩包 | |
| zstandard | zstd 压缩 | ❗ |
| lz4 | lz4 压缩 | |
| xlrd | 老 .xls 读取 | |
| pyxlsb | .xlsb 读取 | |
| python-calamine | 高速 Excel 读取引擎 | （可选）❗ |
| duckdb | 嵌入式分析型数据库 | ⭐ |
| sqlite-utils | SQLite 工具库/CLI | |
| tinydb | 纯 Python JSON 小数据库 | |
| fsspec | 统一文件系统抽象 | |

## 三、数据库与消息中间件客户端

| 包名 | 用途 | 标记 |
|---|---|---|
| sqlalchemy | ORM/SQL 工具箱 | ⭐ |
| sqlmodel | 现代 ORM（FastAPI 作者） | |
| alembic | 数据库迁移 | |
| aiosqlite | 异步 SQLite | |
| pymysql | MySQL 驱动 | |
| psycopg2-binary | PostgreSQL 驱动 | |
| pyodbc | ODBC 通用接口（对接老系统） | ❗⚠️ |
| oracledb | Oracle 驱动（thin 模式纯 py） | （可选） |
| pymongo | MongoDB 客户端 | |
| redis | Redis 客户端 | |
| elasticsearch | Elasticsearch 客户端 | （可选） |
| minio | S3 兼容对象存储客户端 | |
| boto3 | AWS/S3 兼容客户端 | （可选） |
| pika | RabbitMQ 客户端 | （可选） |
| kafka-python | Kafka 客户端 | （可选） |
| paho-mqtt | MQTT（物联网/试验数据采集） | |

## 四、统计分析与可靠性

| 包名 | 用途 | 标记 |
|---|---|---|
| statsmodels | 经典统计建模/检验 | ⭐ |
| pingouin | 简洁统计检验 | |
| scikit-posthocs | 非参数事后检验 | （可选） |
| patsy | 统计公式语法 | |
| reliability | 可靠性工程（威布尔/寿命分析） | ⭐ |
| lifelines | 生存分析 | |
| uncertainties | 误差/不确定度传递 | ⭐ |
| pymc | 贝叶斯推断 | （可选）❗ |

## 五、机器学习

| 包名 | 用途 | 标记 |
|---|---|---|
| scikit-learn | 机器学习基石 | ⭐ |
| xgboost | GBDT | ⭐ |
| lightgbm | 高效 GBDT | ⭐ |
| catboost | 类别特征友好 GBDT | |
| imbalanced-learn | 不平衡数据采样 | |
| category_encoders | 类别变量编码 | 🆕 |
| feature-engine | 特征工程管道 | 🆕 |
| optuna | 超参数优化 | ⭐ |
| scikit-optimize | 贝叶斯调参 | （可选） |
| shap | 模型可解释性 | ⭐ |
| umap-learn | 流形降维 | 🆕 |
| hdbscan | 密度聚类 | 🆕 |
| mlxtend | sklearn 补充工具 | |
| yellowbrick | 模型可视化诊断 | （可选）🆕 |
| flaml | 轻量 AutoML（微软） | （可选）🆕 |
| sktime | 时间序列 ML | |
| statsforecast | 快速时序预测 | （可选）🆕 |
| darts | 时序全家桶 | （可选）❗🆕 |
| tsfresh | 时序特征自动提取 | （可选）❗ |
| mlflow | 实验跟踪（可完全自托管） | （可选）🆕 |

## 六、深度学习（纯 CPU）

| 包名 | 用途 | 标记 |
|---|---|---|
| torch | PyTorch 本体（CPU 版） | ⭐❗（cp314 支持待确认） |
| torchvision | 视觉模型/变换 | ⭐ |
| torchaudio | 音频深度学习（声学对口） | ⭐ |
| lightning | 训练工程化（pytorch-lightning） | |
| torchmetrics | 指标库 | |
| torchinfo | 模型结构摘要 | |
| einops | 张量操作语法糖 | |
| safetensors | 安全权重格式 | |
| transformers | HuggingFace 预训练模型 | ⭐ |
| tokenizers | 分词器（Rust） | ❗ |
| datasets | HF 数据集 | |
| accelerate | 训练加速封装 | |
| huggingface-hub | 模型库客户端（离线用本地目录） | |
| sentence-transformers | 句向量/RAG 嵌入 | ⭐ |
| timm | 视觉模型库 | |
| peft | LoRA 等参数高效微调 | （可选） |
| onnx | ONNX 模型格式 | |
| onnxruntime | CPU 推理引擎 | ⭐ |
| optimum | HF 推理/量化优化 | （可选）🆕 |
| tensorboard | 训练可视化 | |
| kornia | 可微分计算机视觉 | （可选）🆕 |

## 七、自然语言处理与中文工具

| 包名 | 用途 | 标记 |
|---|---|---|
| spacy | 工业级 NLP | 🆕 |
| nltk | 基础/教学 NLP | 🆕 |
| gensim | word2vec/主题模型 | （可选）❗🆕 |
| jieba | 中文分词 | ⭐ |
| pypinyin | 汉字转拼音 | |
| fasttext-wheel | 词向量 | （可选）❗ |

## 八、计算机视觉与 OCR

| 包名 | 用途 | 标记 |
|---|---|---|
| opencv-python | CV 基石 | ⭐ |
| opencv-contrib-python | contrib 扩展（与上一行二选一） | ❗ |
| scikit-image | 图像处理 | ⭐ |
| Pillow | 图像基础处理 | ⭐ |
| imageio | 多格式图像 IO | |
| imageio-ffmpeg | 视频 IO（wheel 自带 ffmpeg） | ⚠️ |
| albumentations | 图像数据增强 | |
| ultralytics | YOLO 目标检测 | （可选）❗ |
| supervision | 检测结果后处理 | （可选） |
| rapidocr-onnxruntime | 纯 pip OCR（onnx 运行时） | ⭐ |
| easyocr | torch 系 OCR | （可选）❗ |
| pytesseract | Tesseract 接口 | ⚠️（需装 Tesseract 程序） |
| imagehash | 感知哈希（图像去重） | 🆕 |
| qrcode | 二维码生成 | |
| pyzbar | 二维码/条码识别 | （可选）⚠️（zbar dll） |
| av | PyAV 视频处理（wheel 自带 ffmpeg 库） | ❗ |
| moviepy | 视频剪辑 | （可选）⚠️（ffmpeg） |
| open3d | 点云/三维数据处理 | （可选）❗ |

## 九、可视化、绘图与交互应用

| 包名 | 用途 | 标记 |
|---|---|---|
| matplotlib | 绘图基石 | ⭐ |
| seaborn | 统计绘图 | ⭐ |
| plotly | 交互式绘图 | ⭐ |
| kaleido | plotly 静态图片导出 | ❗ |
| bokeh | 交互式绘图 | |
| altair | 声明式统计图 | |
| pyecharts | 百度 ECharts 封装 | ⭐ |
| pyqtgraph | 高速实时曲线（工程监控利器） | ⭐ |
| adjustText | 标签防重叠 | |
| scienceplots | 论文风格样式 | （可选） |
| wordcloud | 词云 | |
| graphviz | 结构图绘制 | ⚠️（需 Graphviz 程序） |
| networkx | 图论/网络分析 | ⭐ |
| plotnine | ggplot 语法 | （可选） |
| dash | 纯 Python 数据应用（Plotly 系） | ⭐ |
| streamlit | 快速数据应用 | ⭐❗ |
| gradio | 模型演示界面 | 🆕 |
| panel | HoloViz 数据应用 | （可选） |
| shiny | Posit Shiny for Python | （可选）🆕 |
| nicegui | 现代 UI 框架 | （可选）🆕 |
| pywebio | 极简 Web 交互 | （可选）🆕 |
| itables | Jupyter 交互表格 | （可选）🆕 |
| ydata-profiling | 一键 EDA 报告 | 🆕 |
| sweetviz | EDA 对比报告 | （可选）🆕 |
| pygwalker | Jupyter 内拖拽式可视化（类 Tableau） | （可选）🆕 |

## 十、专业工程：有限元、网格与结构

| 包名 | 用途 | 标记 |
|---|---|---|
| pyvista | 网格/计算结果三维可视化 | ⭐ |
| meshio | 网格格式转换 | ⭐ |
| gmsh | 网格剖分（python 接口+自带二进制） | ⚠️ |
| pygmsh | gmsh 高层封装 | （可选） |
| scikit-fem | 轻量纯 Python FEM | ⭐ |
| sfepy | 全功能 Python FEM | ❗ |
| ansys-mapdl-core | PyMAPDL 客户端 | ⚠️（需 MAPDL 服务） |
| ansys-dpf-core | DPF 后处理客户端 | ⚠️（需 DPF Server） |
| pyamg | 代数多重网格求解器 | （可选）❗ |
| trimesh | 三角网格处理 | ⭐ |
| numpy-stl | STL 文件读写 | |
| sectionproperties | 截面特性分析 | ⭐🆕 |
| openseespy | OpenSees 结构分析 | （可选）🆕 |
| PyNiteFEA | 杆系/框架 FEM | （可选）🆕 |
| openmdao | NASA 多学科设计优化框架 | ⭐🆕 |
| pyoptsparse | 优化器统一接口 | 不装（PyPI 无 wheel，GitHub 源码需 Fortran 编译） |
| fipy | NIST 偏微分方程求解（有限体积法） | （可选）🆕 |
| ezdxf | DXF 图纸读写 | |

## 十一、专业工程：疲劳、振动与声学

| 包名 | 用途 | 标记 |
|---|---|---|
| pyLife | 疲劳寿命分析（Bosch 出品） | ⭐ |
| fatpack | 雨流计数/疲劳评估 | |
| rainflow | 雨流计数（C 加速） | ❗ |
| py_fatigue | 疲劳/循环应力分析工具集（owi-lab） | 两版本皆装（2.1.1 纯 Python；3.14 需 numba 0.65.x + numpy 2.4.x） |
| FLife | 频域疲劳分析 | （可选） |
| sdynpy | 结构动力学（Sandia） | |
| pyEMA | 试验模态分析 | （可选） |
| control | 控制理论/频域分析 | |
| librosa | 音频特征分析 | ⭐ |
| soundfile | 音频读写（libsndfile） | ⭐ |
| acoustics | 声学计算（python-acoustics） | ⭐ |
| pyroomacoustics | 室内声学仿真 | ❗ |
| pyfar | 声学研究工具集 | （可选）🆕 |
| pyloudnorm | 响度标准化 | （可选） |
| sounddevice | 音频实时 IO | ❗ |
| noisereduce | 频谱降噪 | （可选）🆕 |
| mutagen | 音频元数据 | 🆕 |
| pydub | 音频剪辑 | ⚠️（ffmpeg） |
| pyaudio | 音频 IO | （可选）❗ |
| soundcard | 音频 IO 替代 | （可选） |
| vosk | 离线语音识别 | （可选）❗🆕 |
| faster-whisper | 本地 Whisper 语音转写 | （可选）❗🆕 |

## 十二、专业工程：CAD、航空、单位与物性

| 包名 | 用途 | 标记 |
|---|---|---|
| pycatia | CATIA V5 COM 自动化 | ⭐⚠️（需装 CATIA V5） |
| pywin32 | Windows COM/Win32 API | ⭐ |
| comtypes | 纯 Python COM | |
| cadquery | 参数化 CAD 建模 | （可选）❗ |
| pythonocc-core | OpenCASCADE 内核 | （可选）❗（PyPI 无 wheel，走 conda-forge 环境复制，见文末附录 C） |
| pyautocad | AutoCAD COM 自动化 | （可选）🆕 |
| pint | 物理单位换算 | ⭐ |
| CoolProp | 流体热物性 | |
| fluids | 流体力学工程计算 | （可选） |
| ambiance | ICAO 标准大气 | |
| aerosandbox | 飞机设计/气动分析 | （可选）❗🆕 |
| jsbsim | 飞行动力学仿真 | （可选）🆕 |
| aviary | NASA 飞机总体设计/任务分析（基于 OpenMDAO） | （可选）🆕 |

## 十三、网络开发与 Web 服务

| 包名 | 用途 | 标记 |
|---|---|---|
| requests | HTTP 基石 | ⭐ |
| httpx | 现代同步/异步 HTTP | ⭐ |
| aiohttp | 异步 HTTP 服务端/客户端 | |
| curl-cffi | 浏览器指纹 HTTP | ❗ |
| urllib3 | HTTP 底层（requests 依赖） | |
| websocket-client | 同步 WebSocket | 🆕 |
| websockets | 异步 WebSocket | |
| python-socketio | Socket.IO 实时通信 | |
| fastapi | 现代 API 框架 | ⭐ |
| uvicorn | ASGI 服务器 | ⭐ |
| waitress | Windows 生产级 WSGI 服务器 | ⭐ |
| flask | 经典 Web 框架 | ⭐ |
| django | 全家桶 Web 框架 | （可选） |
| pydantic | 数据校验/模型 | ⭐ |
| pydantic-settings | 配置管理 | |
| authlib | OAuth/JWT 全家桶 | |
| pyjwt | JWT | |
| itsdangerous | 签名（Flask 生态） | |
| grpcio | gRPC | ❗ |
| grpcio-tools | gRPC 代码生成 | （可选） |
| protobuf | Protocol Buffers | |
| pyzmq | ZeroMQ 消息 | ❗ |
| celery | 分布式任务队列 | （可选）❗ |
| paramiko | SSH/SFTP | ⭐ |
| fabric | SSH 批量自动化 | （可选） |
| pyftpdlib | FTP 服务器 | |
| dnspython | DNS 工具 | |
| scapy | 数据包构造/分析 | （可选）⚠️（需 npcap） |
| pysnmp | SNMP 监控 | （可选）🆕 |
| rpyc | Python 远程调用 | （可选） |
| smbprotocol | SMB 文件共享访问 | （可选） |
| requests-ntlm | NTLM 认证（IIS/SharePoint） | （可选） |

## 十四、爬虫与网页解析

| 包名 | 用途 | 标记 |
|---|---|---|
| scrapy | 爬虫框架 | （可选） |
| parsel | 选择器（scrapy 生态） | |
| cssselect | CSS 选择器 | |
| fake-useragent | UA 伪装 | |
| crawl4ai | LLM 友好爬虫 | （可选）❗🆕 |

## 十五、桌面/浏览器自动化与 RPA

| 包名 | 用途 | 标记 |
|---|---|---|
| pyautogui | 键鼠控制+图像识别 | ⭐ |
| pywinauto | Windows 原生 UI 自动化 | ⭐ |
| uiautomation | UIAutomation 封装 | （可选） |
| pynput | 键鼠监听/控制 | |
| pyperclip | 剪贴板 | |
| pygetwindow | 窗口管理 | |
| pyscreeze | 截屏（pyautogui 依赖） | |
| pystray | 系统托盘 | |
| psutil | 进程/系统信息 | ⭐ |
| wmi | Windows WMI 管理 | |
| winshell | 快捷方式/回收站 | （可选） |
| watchdog | 文件系统监听 | ⭐ |
| schedule | 极简定时任务 | |
| apscheduler | 高级定时调度 | ⭐ |
| croniter | cron 表达式解析 | 🆕 |
| selenium | 浏览器自动化 | ⭐ |
| playwright | 现代浏览器自动化 | ⚠️（需离线下载浏览器二进制） |
| DrissionPage | 国产浏览器/请求一体化自动化 | ⭐ |
| robotframework | 关键字驱动自动化/测试 | （可选） |
| rpaframework | Robocorp RPA 组件库 | （可选）❗🆕 |
| screen_brightness_control | 屏幕亮度控制 | （可选） |
| plyer | 跨平台通知/系统能力 | （可选） |

## 十六、仪器控制与工业通信

| 包名 | 用途 | 标记 |
|---|---|---|
| pyserial | 串口通信 | ⭐ |
| pyvisa | VISA 仪器控制 | ⚠️（需 VISA 运行时） |
| pyvisa-py | 纯 Python VISA 后端 | |
| pymodbus | Modbus 协议 | |
| python-can | CAN 总线 | |
| cantools | DBC 文件解析 | |
| asyncua | OPC UA | （可选） |
| nidaqmx | NI 数据采集卡 | （可选）⚠️（需 NI 驱动） |
| mpi4py | MPI 并行计算 | （可选）⚠️（需 MPI 运行时） |

## 十七、远程开发与 Jupyter

| 包名 | 用途 | 标记 |
|---|---|---|
| jupyterlab | 主力交互式 IDE | ⭐ |
| notebook | 经典 Notebook 界面 | ⭐ |
| jupyter-server | 服务端（远程访问核心） | ⭐ |
| ipython | 增强解释器 | ⭐ |
| ipykernel | Jupyter 内核 | ⭐ |
| ipywidgets | 交互控件 | |
| ipympl | matplotlib 交互后端 | |
| nbconvert | 导出 HTML/PDF | ⭐ |
| nbformat | Notebook 格式处理 | |
| jupytext | .py 文件配对 | |
| papermill | 参数化批量执行 | |
| voila | Notebook 变仪表盘 | （可选） |
| nbdime | Notebook diff/合并 | （可选） |
| jupyter-dash | Dash 嵌入 Notebook | （可选） |
| marimo | 新型响应式 Notebook | （可选）❗🆕 |

## 十八、办公与文档处理

| 包名 | 用途 | 标记 |
|---|---|---|
| python-docx | Word 读写 | ⭐ |
| docxtpl | Word 模板渲染（试验报告利器） | ⭐ |
| docxcompose | docx 合并 | （可选）🆕 |
| python-pptx | PPT 读写 | ⭐ |
| openpyxl | Excel 读写 | ⭐ |
| xlsxwriter | Excel 写入（图表能力强） | ⭐ |
| xlwings | Excel COM 自动化 | ⚠️（需装 Office） |
| pypdf | PDF 合并/拆分 | ⭐ |
| PyMuPDF | PDF 高速处理 | ⭐ |
| pymupdf4llm | PDF→Markdown（喂 LLM） | |
| pdfplumber | PDF 表格/文本提取 | ⭐ |
| pikepdf | PDF 结构级处理 | ❗ |
| reportlab | PDF 程序化生成 | ⭐ |
| fpdf2 | 纯 Python PDF 生成 | |
| img2pdf | 图片转 PDF | |
| pdf2docx | PDF 转 Word | 🆕 |
| pdf2image | PDF 转图片 | ⚠️（需 poppler） |
| camelot-py | PDF 表格提取 | （可选）⚠️（需 ghostscript） |
| ocrmypdf | PDF OCR | （可选）⚠️（tesseract+ghostscript） |
| weasyprint | HTML→PDF | （可选）❗ |
| pdfkit | HTML→PDF | （可选）⚠️（wkhtmltopdf） |
| markdown | Markdown→HTML | |
| mistune | 快速 Markdown 解析 | |
| jinja2 | 模板引擎 | ⭐ |
| markitdown | 多格式→Markdown（微软出品） | （可选）❗🆕 |
| docling | 文档解析（IBM，RAG 向） | （可选）❗🆕 |
| mammoth | docx→HTML | （可选） |
| odfpy | ODF 格式 | （可选） |
| msoffcrypto-tool | Office 加密文件解密 | 🆕 |
| extract-msg | Outlook .msg 解析 | 🆕 |
| olefile | OLE 复合文档解析 | |
| yagmail | 简洁发邮件 | （可选） |
| exchangelib | Exchange/Outlook 集成 | （可选） |
| imapclient | IMAP 邮件 | （可选） |

## 十九、Agent 开发与 LLM 生态

**Agent 框架（本清单只列这三家）**

| 包名 | 用途 | 标记 |
|---|---|---|
| langchain | Agent/LLM 应用框架 | ⭐ |
| langchain-core | langchain 核心 | ⭐ |
| langchain-community | 社区集成 | ⭐ |
| langchain-text-splitters | 文本切分 | |
| langchain-openai | OpenAI 兼容接口（本地/内网模型服务用） | ⭐ |
| langchain-anthropic | Claude 集成 | （可选） |
| langchain-ollama | Ollama 集成 | |
| langchain-huggingface | HuggingFace 集成 | |
| langchain-chroma | Chroma 向量库集成 | （可选） |
| langchain-mcp-adapters | LangChain↔MCP 桥接 | 🆕 |
| langgraph | 有状态 Agent 图编排 | ⭐ |
| langgraph-checkpoint | Agent 状态持久化 | |
| langgraph-checkpoint-sqlite | SQLite 本地状态存储 | 🆕 |
| pyautogen | AutoGen 0.2 经典版 | ⭐ |
| autogen-agentchat | AutoGen 0.4 新版（与 0.2 可并存） | ❗ |
| autogen-core | AutoGen 0.4 核心 | ❗ |
| autogen-ext | AutoGen 0.4 扩展 | （可选）❗ |
| openai-agents | OpenAI Agents SDK | ⭐ |

**MCP 与 Agent 协议**

| 包名 | 用途 | 标记 |
|---|---|---|
| mcp | Model Context Protocol 官方 SDK | ⭐ |
| fastmcp | MCP 快速开发框架 | ⭐ |
| a2a-sdk | Google Agent2Agent 协议 | （可选）🆕 |
| mcp-use | MCP 客户端库（LLM 接任意 MCP 服务） | （可选）🆕 |

**LLM 客户端与本地推理**

| 包名 | 用途 | 标记 |
|---|---|---|
| openai | OpenAI 兼容客户端（内网服务用） | ⭐ |
| anthropic | Claude 客户端 | （可选） |
| litellm | 多 provider 统一调用/代理 | ⭐ |
| tiktoken | OpenAI 分词 | |
| instructor | 结构化输出 | |
| modelscope | 魔搭社区客户端（国内模型源） | 🆕 |

**RAG 与向量检索**

| 包名 | 用途 | 标记 |
|---|---|---|
| chromadb | 向量数据库 | ❗ |
| faiss-cpu | 向量检索 | ❗ |
| rank-bm25 | 关键词检索 | |
| sqlite-vec | SQLite 向量扩展 | （可选）❗ |
| ragas | RAG 效果评估 | （可选）🆕 |

## 二十、通用工具库

| 包名 | 用途 | 标记 |
|---|---|---|
| tqdm | 进度条 | ⭐ |
| rich | 终端富文本/表格/日志 | ⭐ |
| click | CLI 框架 | ⭐ |
| typer | 现代 CLI 框架 | ⭐ |
| fire | 零样板 CLI | |
| colorama | Windows 终端颜色 | |
| termcolor | 终端颜色 | （可选） |
| prompt_toolkit | 交互式输入 | |
| tabulate | 表格打印 | |
| loguru | 日志 | ⭐ |
| tenacity | 重试装饰器 | ⭐ |
| cachetools | 内存缓存 | |
| diskcache | 磁盘缓存 | |
| joblib | 缓存/并行（sklearn 依赖） | |
| more-itertools | 迭代器工具 | |
| toolz | 函数式工具 | （可选） |
| boltons | 杂项工具集 | （可选）🆕 |
| sortedcontainers | 有序容器 | 🆕 |
| humanize | 人性化数字/时间显示 | |
| filelock | 文件锁 | |
| send2trash | 安全删除到回收站 | |
| py-cpuinfo | CPU 信息 | |
| keyring | 系统凭据存储 | （可选） |
| pyyaml | YAML | ⭐ |
| toml | TOML 读写 | |
| tomli-w | TOML 写 | |
| ruamel.yaml | YAML 保格式读写 | （可选）🆕 |
| python-dotenv | .env 配置 | |
| python-dateutil | 日期解析 | ⭐ |
| pendulum | 时区友好日期 | |
| tzdata | 时区数据库 | |
| tzlocal | 本地时区获取 | |
| chinese_calendar | 中国法定节假日/调休 | （可选） |
| dateparser | 自然语言日期解析 | （可选） |
| faker | 假数据生成 | |
| freezegun | 时间冻结（测试） | |
| filetype | 文件类型探测（纯 py） | |
| icecream | 调试打印 | |
| ipdb | 调试器 | |
| pyinstrument | 采样性能分析 | 🆕 |
| memory_profiler | 内存分析 | |
| line_profiler | 行级性能分析 | |
| py-spy | 无侵入采样分析 | （可选）❗ |
| viztracer | 可视化执行追踪 | （可选）🆕 |
| snakeviz | cProfile 可视化 | （可选） |
| pipdeptree | 依赖树查看 | ⭐ |
| pip-tools | requirements 版本锁定 | |
| virtualenv | 虚拟环境 | |
| pypiserver | 内网私有 PyPI 源 | （可选，部署用） |
| GitPython | git 仓库操作 | |
| dulwich | 纯 Python git | （可选） |

## 二十一、开发质量、测试与文档

| 包名 | 用途 | 标记 |
|---|---|---|
| pytest | 测试框架 | ⭐ |
| pytest-cov | 覆盖率 | ⭐ |
| pytest-xdist | 并行测试 | |
| pytest-asyncio | 异步测试 | |
| pytest-mock | mock 支持 | |
| pytest-benchmark | 性能基准测试 | （可选）🆕 |
| pytest-html | HTML 测试报告 | |
| hypothesis | 属性测试 | （可选） |
| coverage | 覆盖率底层 | |
| responses | requests mock | |
| locust | 接口/服务压测 | （可选）🆕 |
| ruff | 超快 linter/格式化（Rust） | ❗ |
| black | 代码格式化 | |
| isort | import 排序 | |
| mypy | 类型检查 | |
| bandit | 安全扫描 | （可选） |
| pre-commit | 提交钩子 | （可选） |
| mkdocs | 文档站点 | |
| mkdocs-material | 文档主题 | |
| sphinx | 经典文档工具 | （可选） |

## 二十二、打包分发与 GUI 开发

| 包名 | 用途 | 标记 |
|---|---|---|
| pyinstaller | 打包 exe 分发 | ⭐❗（Win7 目标机需 `pyinstaller<6`，requirements 中已锁） |
| nuitka | 编译型分发 | （可选）❗ |
| cython | C 扩展构建 | |
| setuptools | 打包基石 | ⭐ |
| wheel | wheel 构建 | ⭐ |
| build | sdist/wheel 构建 | |
| PyQt5 | 桌面 GUI（Win7 兼容的最后大版本） | ⭐ |
| pyqt5-tools | Qt Designer 等工具 | （可选） |
| ttkbootstrap | 美化 tkinter | |
| customtkinter | 现代化 tkinter | （可选） |
| wxPython | 原生 GUI | （可选）❗ |

---

## 明确不装的库（及原因）

| 排除项 | 原因 |
|---|---|
| TensorFlow / Keras / JAX | GPU 导向；新版原生库对 Win7 风险大。CPU 深度学习统一走 PyTorch + ONNXRuntime |
| PyQt6 / PySide6 / PySide2 | Qt6 官方要求 Win10+；GUI 统一用 PyQt5 / tkinter 系 |
| crewai / semantic-kernel / agno / dspy / smolagents | Agent 框架只保留 langchain、autogen、openai-agents 三家 |
| llama-index / haystack | 与 langchain 生态功能重叠（如需请单独评估） |
| deepspeed / bitsandbytes / vllm / sglang | GPU/服务器专用 |
| flet | Flutter 引擎不支持 Win7 |
| textual | 依赖 VT 终端，Win7 控制台体验差（rich + prompt_toolkit 替代） |
| FEniCS | 官方仅 Linux/conda，Windows 需容器单独部署 |
| uv / poetry / pdm | 离线场景 pip + pypiserver 已够用 |
| langfuse / wandb / neptune | 强依赖云服务（自托管实验跟踪用 mlflow） |
| folium / geopandas / rasterio | GIS 类默认不装，如有测绘需求另行评估 |

## 安装与分发流程要点

1. **机器可读清单**：`examples/requirements.txt`（除 `pyinstaller<6` 外不锁版本；
   含全部"可选"项）；torch 三件套单独在 `examples/requirements-torch-cpu.txt`，
   走 PyTorch CPU 源。
2. **安装工具用 uv**：一律显式指定目标解释器
   `uv pip install --python <目标树>\python.exe ...`，保证装进打包目录而非本机
   用户目录（目标树 `pip.ini` 设 site 级 `user = false` 双保险，见
   [playbook.md](playbook.md)）。
3. **3.12 树全量装**：先整体 `uv pip install -r requirements.txt`（让 uv 统一解
   版本冲突），失败的包再逐条循环重试并记录。
4. **3.14 树逐条装**：无 cp314 wheel 的包失败自动跳过并记录，不影响其余包。
5. **离线分发**：联网机
   `pip download -r requirements.txt -d wheels --platform win_amd64 --python-version 3.12 --only-binary=:all:`，
   入离线环境后 `pip install --no-index --find-links=wheels ...`；长期可用
   pypiserver 搭内网源。
6. **外部组件清单**（另行部署）：ffmpeg、poppler、Tesseract、ghostscript、
   wkhtmltopdf、Graphviz、VISA 运行时、NI 驱动、CATIA V5、Office、MAPDL/DPF
   服务、playwright 浏览器包。
7. **pythonocc-core 特殊通道**：见附录 C。
8. ❗ 标记的包进离线环境前，先在改造后的 Python 树上实测（Win7 运行 +
   cp312/cp314 wheel 可得性）；无 cp314 wheel 的一律只进 3.12 树。

## 附录

### A. 与本仓库 requirements 文件的口径差异

- `examples/requirements.txt` 未收录「十四、爬虫与网页解析」一节（均为可选项）；
- `opencv-python` 与 `opencv-contrib-python` 二选一，requirements 只装
  `opencv-contrib-python`（超集，二者同装会文件冲突）；
- `torch` / `torchvision` / `torchaudio` 在 `examples/requirements-torch-cpu.txt`；
- `pythonocc-core`（PyPI 无 wheel）、`pyoptsparse`（需 Fortran 编译）不进入批量安装。

### B. 已知版本约束

- Win7 目标机：`pyinstaller<6`（6 起官方弃 Win7）；
- `numba` 及其依赖链：numba 对 numpy 有上限（如 numba 0.62 要求 numpy ≤ 2.3），
  装完需回核 numpy/pandas/numba/sklearn 的版本组合；
- `py_fatigue`：2.1.1 为纯 Python；3.14 树需 numba 0.65.x + numpy 2.4.x；
- `torchaudio`：新版发布节奏与 torch 不同步，深度使用有 ABI 风险时可用
  librosa / soundfile 替代。

### C. pythonocc-core（conda 复制法）

PyPI 无 wheel，conda-forge 有 win-64 构建（7.9.3）。不要用 conda 直接装进
目标树（conda 会把整棵树当作自己的 env 根，写入自己的 python 与 conda-meta，
破坏独立目录结构）。正确做法：

1. 开发机建独立环境
   `conda create -p <独立路径> python=3.12 pythonocc-core=7.9.3 -c conda-forge`；
2. 把 `<环境>\Lib\site-packages\OCC\` 复制进目标树 `Lib\site-packages\`；
3. 把 `<环境>\Library\bin\` 里的 OCCT 运行时 DLL 复制到 `OCC\Core\` 旁
   （与 .pyd 同目录即可被加载）；
4. 用 3.12 树（cp312 ABI 兼容）；3.14 树无对应构建。
