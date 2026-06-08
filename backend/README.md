# VMS 阶段 4：真实文件上传原型

## 目标

在网页中上传真实资产表和扫描器文件。系统先解析并展示预览，操作员确认后才写入资产库或正式漏洞清单。

本机开发使用 SQLite。后续部署时切换 PostgreSQL，并增加登录、权限和字段映射管理。

## 启动

```powershell
powershell -ExecutionPolicy Bypass -File D:\VMS_V1\backend\run_backend.ps1
```

浏览器打开：

```text
http://127.0.0.1:8000/
```

Swagger 接口页面：

```text
http://127.0.0.1:8000/docs
```

## 真实文件导入

1. 左侧打开“文件导入”。
2. 上传资产表 `.xls` 或 `.xlsx`，检查新增、更新和异常数量，点击“确认发布”。
3. 选择青藤云、阿里云或绿盟，填写月份。
4. 青藤云和阿里云上传 `.xls` 或 `.xlsx`；绿盟上传 `.zip`。
5. 检查有效漏洞数量、过滤数量和异常明细。
6. 无关键错误时点击“确认发布”。普通警告需要再次确认。

未发布预览保留 `24` 小时。过期后需重新上传。

## 测试

测试资料只保存在本机 `samples/`，不会上传 GitHub。

```powershell
$env:PYTHONPATH='D:\VMS_V1\backend;D:\VMS_V1\prototype\src'
python -m pytest .\backend\tests -q
```
