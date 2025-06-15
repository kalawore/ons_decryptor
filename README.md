
# NScripter 脚本通用解密工具

这是一个用于解密 NScripter 引擎所使用的多种脚本文件的 Python 工具。本工具的全部解密逻辑均基于对 `ScriptHandler.cpp` 文件的分析而来。

## 功能特性

* **自动检测文件格式**：通过输入文件的标准文件名（如 `nscript.dat`, `onscript.nt3`）自动识别加密类型。
* **支持多种加密格式**：涵盖了从简单的异或加密到复杂的流加密等多种算法。
* **跨平台**：使用标准 Python 库编写，可在 Windows, macOS 和 Linux 上运行。

## 系统要求

* Python 3.x

## 使用方法

### 1. 通用命令

在您的终端或命令行中执行以下命令：

```sh
python ons_decryptor.py <输入文件> <输出文件> [可选参数]
```

**参数说明:**

* `<输入文件>`: **必需**。要解密的脚本文件路径。
* `<输出文件>`: **必需**。解密后内容要保存到的文件路径。
* `[可选参数]`:
    * `--key-file <密钥表路径>`: **仅在解密 `nscript.___` 文件时需要**。

### 2. 使用示例

**示例 1：解密标准文件 (如 `onscript.nt2`, `nscript.dat` 等)**

```sh
python ons_decryptor.py onscript.nt2 decrypted_script.txt
```

**示例 2：解密 `nscript.___` (需要提供外部密钥表)**

`nscript.___` 格式的解密依赖一个从游戏主程序中提取的、256字节的密钥表。

```sh
python ons_decryptor.py nscript.___ decrypted_script.txt --key-file path/to/your/key.bin
```

## 支持的格式详解

本工具根据文件名自动选择相应的解密算法：

| 文件名 | 加密模式 (源) | 解密方法 | 备注 |
| :--- | :--- | :--- | :--- |
| `nscript.dat` | 模式 1 | 单字节异或 (密钥 `0x84`) | |
| `nscr_sec.dat`| 模式 2 | 5字节循环密钥异或 | 密钥: `{0x79, 0x57, 0x0d, 0x80, 0x04}` |
| `onscript.nt2` | 模式 4 | `(字节 + 1) ^ 0x81` | |
| `onscript.nt3` | 模式 5 | 有状态流加密 | 算法依赖文件头部的密钥和大小信息 |
| `nscript.___` | 模式 3 | 密钥表逆向查找 + 异或 | **必须**使用 `--key-file` 提供外部256字节密钥表 |
| `0.txt`, `00.txt` | 模式 0 | 明文 | 直接复制文件内容 |

## 免责声明

* 本工具仅供学习、研究和个人数据备份使用。
* 请在符合当地法律法规的前提下使用本工具。
