# VMS 阶段 1 数据处理原型

## 目标

使用脱敏样例验证资产表、青藤云、阿里云和绿盟扫描结果可以转换为统一标准漏洞清单。

## 安装

```powershell
cd D:\VMS_V1
python -m pip install -r .\prototype\requirements.txt
```

## 运行

```powershell
$env:PYTHONPATH='D:\VMS_V1\prototype\src'
.\prototype\run_stage1.ps1
```

也可以手动指定参数：

```powershell
$env:PYTHONPATH='D:\VMS_V1\prototype\src'
python -m vms_stage1.cli `
  --samples 'D:\VMS_V1\samples' `
  --output 'D:\VMS_V1\outputs\stage1' `
  --month '2026-05'
```

输出：

```text
D:\VMS_V1\outputs\stage1\阶段1_标准漏洞清单.xlsx
D:\VMS_V1\outputs\stage1\阶段1_导入统计.json
D:\VMS_V1\outputs\stage1\阶段1_运行报告.md
```

Excel 包含：

1. `标准漏洞清单`
2. `异常数据`
3. `导入统计`

## 测试

```powershell
$env:PYTHONPATH='D:\VMS_V1\prototype\src'
python -m pytest .\prototype\tests -q
```

## 说明

- 字段映射保存在 `prototype\config\field_mappings.json`。
- 解析器按列名读取数据，不依赖固定列号。
- 绿盟样例先读取 `index.xls`，只解析中危及以上主机报告。
- 绿盟主机报告中的端口、协议和服务支持合并单元格向下填充。
- 当前绿盟样例只提供一个主机报告，其余索引主机会进入异常列表。
- 标准清单包含 `上月处置状态` 和 `上月备注`。当前样例只有单月数据，因此默认显示“无”。
- 解析器可以读取 CVE 作为内部辅助信息，但标准业务清单不输出单独的 CVE 列。
