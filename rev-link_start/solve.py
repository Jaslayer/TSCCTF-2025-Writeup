rst =[0x3B, 0x73, 0x44, 0x73, 0x1F, 0x10, 0x49, 0x45, 0x1F, 0x72, 
        0x24, 0x55, 0x71, 0x7F, 0x71, 0x7C, 0x24, 0x6B, 0x7E, 0x03, 
        0x75, 0x6C, 0x4F, 0x79, 0x21, 0x7F, 0x64, 0x7D, 0x12, 0x74, 
        0x63, 0x55, 0x21, 0x60, 0x4F, 0x5B, 0x0D, 0x6C, 0x4F, 0x7C, 
        0x3D, 0x5E, 0x6E, 0x4E]
flag = []
for i in range(0, len(rst), 4):
    flag.append(rst[i+2] ^ 0x10)
    flag.append(rst[i+1] ^ 0x20)
    flag.append(rst[i+3] ^ 0x30)
    flag.append(rst[i] ^ 0x40)
print(bytes(flag).decode())