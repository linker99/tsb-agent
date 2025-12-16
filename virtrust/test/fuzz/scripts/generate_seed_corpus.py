#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import struct

# ------------------------------------------
# Config
# ------------------------------------------
INPUT_FILE = "fuzz_inputs.csv"
OUTPUT_DIR = "../corpus/fuzz_domain_all"

os.makedirs(OUTPUT_DIR, exist_ok=True)

# ------------------------------------------
# Fuzz op -> ID 映射（必须与 fuzz_domain_all.cpp 对齐）
# ------------------------------------------
OP_MAP = {
    "create":   0,
    "destroy":  1,
    "start":    2,
    "list":     3,
    "undefine": 4,
    "migrate":  5,
}

# 每个 op 的最小 payload 字节数
OP_MIN_SIZE = {
    0: 1,   # create: [arg_count(1)] + 0+ bytes
    1: 6,   # destroy: [domainName\x00(1)] + [flags(4)] + [isOnlyTsb(1)]
    2: 6,   # start: same as destroy
    3: 5,   # list: [flags(4)] + [printErrToCli(1)]
    4: 6,   # undefine: same as destroy
    5: 6,   # migrate: [domainName\x00(1)] + [destUri\x00(1)] + [flags(4)]
}

# ------------------------------------------
# 参数序列化规则：所有参数都按 UTF-8 字符串，以 NULL 结尾
# ------------------------------------------
def serialize_item(item: str):
    item = item.strip()
    return item.encode("utf-8") + b"\x00"   # 以 NULL 结尾更有利于 fuzz

# ------------------------------------------
# 解析一行输入
# ------------------------------------------
def build_payload(op_name, args):
    op_id = OP_MAP[op_name]

    if op_name == "create":
        # DomainCreate: [arg_count(1字节)] + [arg1\x00] + [arg2\x00] + ...
        arg_count = len(args)
        if arg_count > 255:
            arg_count = 255

        payload = bytes([arg_count])

        for item in args:
            payload += serialize_item(item)

    elif op_name in ["destroy", "start", "undefine"]:
        # DomainDestroy/Start/Undefine: [domain_name\x00] + [flags(4字节)] + [is_only_tsb(1字节)]
        if len(args) >= 3:
            domain_name = args[0]
            flags = int(args[1]) if args[1].isdigit() or (args[1].startswith("0x")) else 0
            is_only_tsb = 1 if args[2].lower() == "true" else 0

            payload = domain_name.encode("utf-8") + b"\x00"
            payload += flags.to_bytes(4, byteorder='little')
            payload += bytes([is_only_tsb])
        else:
            # 默认值
            payload = "test-domain\x00" + (0).to_bytes(4, byteorder='little') + bytes([0])

    elif op_name == "list":
        # DomainList: [flags(4字节)] + [print_err_to_cli(1字节)]
        if len(args) >= 2:
            flags = int(args[0]) if args[0].isdigit() or (args[0].startswith("0x")) else 0
            print_err = 1 if args[1].lower() == "true" else 0

            payload = flags.to_bytes(4, byteorder='little') + bytes([print_err])
        else:
            payload = (0).to_bytes(4, byteorder='little') + bytes([0])

    elif op_name == "migrate":
        # DomainMigrate: [domain_name\x00] + [dest_uri\x00]
        if len(args) >= 2:
            domain_name = args[0]
            dest_uri = args[1]
            flags = int(args[2]) if len(args) > 2 and (args[2].isdigit() or args[2].startswith("0x")) else 0

            payload = domain_name.encode("utf-8") + b"\x00"
            payload += dest_uri.encode("utf-8") + b"\x00"
            payload += flags.to_bytes(4, byteorder='little')
        else:
            payload = "test-domain\x00qemu+tls://localhost:16509/system\x00" + (0).to_bytes(4, byteorder='little')
    else:
        # 默认处理
        payload = b"\x00"

    # pad 至最小长度
    min_len = OP_MIN_SIZE[op_id]
    if len(payload) < min_len:
        payload += b"\x00" * (min_len - len(payload))

    # 最终 seed = [op_id(1字节)] + payload
    return bytes([op_id]) + payload

# ------------------------------------------
# 主程序：读取输入文件并生成 corpus
# ------------------------------------------
def main():
    with open(INPUT_FILE, "r", encoding="utf-8") as f:
        idx = 0
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            parts = [x.strip() for x in line.split(",")]
            op = parts[0].lower()

            if op not in OP_MAP:
                print(f"[WARN] Unknown op: {op}")
                continue

            args = parts[1:]
            seed = build_payload(op, args)

            out_path = os.path.join(OUTPUT_DIR, f"{op}_{idx}")
            with open(out_path, "wb") as out:
                out.write(seed)

            print(f"[+] Generated {out_path} (len={len(seed)})")
            idx += 1

    print("\nDone.")

if __name__ == "__main__":
    main()
