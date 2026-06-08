from __future__ import annotations

import argparse
from pathlib import Path

from .core import run_pipeline


def main() -> None:
    parser = argparse.ArgumentParser(description="VMS 阶段 1 数据标准化原型")
    parser.add_argument("--samples", type=Path, required=True, help="样例文件目录")
    parser.add_argument("--output", type=Path, required=True, help="输出目录")
    parser.add_argument("--month", required=True, help="扫描月份，例如 2026-05")
    parser.add_argument(
        "--config",
        type=Path,
        default=Path(__file__).parents[2] / "config" / "field_mappings.json",
        help="字段映射 JSON",
    )
    args = parser.parse_args()
    result = run_pipeline(args.samples, args.output, args.month, args.config)
    print(f"资产数量: {len(result['assets'])}")
    print(f"标准漏洞数量: {len(result['records'])}")
    print(f"异常数量: {len(result['anomalies'])}")
    print(f"输出目录: {args.output.resolve()}")


if __name__ == "__main__":
    main()
