import sys
import os
import struct

def decrypt_nscript_dat(data: bytes) -> bytes:
    """
    解密 nscript.dat (模式 1)。
    每个字节与 0x84 进行异或。
    """
    key = 0x84
    return bytearray(b ^ key for b in data)

def decrypt_nscr_sec_dat(data: bytes) -> bytes:
    """
    解密 nscr_sec.dat (模式 2)。
    使用5字节循环密钥进行异或。
    """
    magic_key = [0x79, 0x57, 0x0d, 0x80, 0x04]
    decrypted_data = bytearray()
    for i, byte in enumerate(data):
        decrypted_data.append(byte ^ magic_key[i % 5])
    return decrypted_data

def decrypt_nscript____(data: bytes, key_table_path: str) -> bytes | None:
    """
    解密 nscript.___ (模式 3)。
    需要一个外部的256字节密钥表文件。
    """
    if not key_table_path:
        print("错误：解密 'nscript.___' 格式需要一个密钥表文件。")
        print("请使用 '--key-file <密钥表路径>' 参数指定。")
        return None
    
    try:
        with open(key_table_path, 'rb') as f:
            key_table = f.read()
        if len(key_table) != 256:
            print(f"错误：密钥表文件 '{key_table_path}' 的大小不是256字节。")
            return None

        # 创建逆向查找表
        inv_key_table = [0] * 256
        for i, val in enumerate(key_table):
            inv_key_table[val] = i

        decrypted_data = bytearray()
        key = 0x84
        for byte in data:
            # 解密逻辑: P = inv_T[E ^ 0x84]
            original_char_code = inv_key_table[byte ^ key]
            decrypted_data.append(original_char_code)
        return decrypted_data

    except FileNotFoundError:
        print(f"错误：找不到密钥表文件 '{key_table_path}'。")
        return None
    except Exception as e:
        print(f"处理密钥表时发生错误：{e}")
        return None

def decrypt_onscript_nt2(data: bytes) -> bytes:
    """
    解密 onscript.nt2 (模式 4)。
    解密逻辑: P = ((E + 1) & 0xFF) ^ 0x81
    """
    key = 0x85 & 0x97  # 结果是 0x81
    decrypted_data = bytearray()
    for byte in data:
        # 逆向操作: 先加1, 再异或
        decrypted_byte = ((byte + 1) & 0xFF) ^ key
        decrypted_data.append(decrypted_byte)
    return decrypted_data

def decrypt_onscript_nt3(input_path: str, output_path: str) -> bool:
    """
    解密 onscript.nt3 (模式 5)。
    这是一个有状态的流加密，需要文件头信息。
    """
    HEADER_SIZE = 0x920
    KEY_OFFSET = 0x91C
    MAGIC_CONSTANT = 0x5D588B65

    try:
        with open(input_path, 'rb') as f_in:
            f_in.seek(0, 2)
            file_size = f_in.tell()

            if file_size <= HEADER_SIZE:
                print(f"错误: 文件 '{input_path}' 大小无效。")
                return False

            f_in.seek(KEY_OFFSET)
            key_bytes = f_in.read(4)
            nt3_key, = struct.unpack('<i', key_bytes)

            f_in.seek(HEADER_SIZE)
            encrypted_data = f_in.read()
            data_size = len(encrypted_data)
            decrypted_data = bytearray()
            
            for i, encrypted_byte in enumerate(encrypted_data):
                pos = i + 1
                temp_key = nt3_key ^ encrypted_byte
                countdown = (data_size + 1) - pos
                term = encrypted_byte * countdown + MAGIC_CONSTANT
                temp_key += term
                nt3_key = temp_key & 0xFFFFFFFF
                if nt3_key > 0x7FFFFFFF:
                    nt3_key -= 0x100000000
                decrypted_byte = encrypted_byte ^ (nt3_key & 0xFF)
                decrypted_data.append(decrypted_byte)

        with open(output_path, 'wb') as f_out:
            f_out.write(decrypted_data)
        return True

    except FileNotFoundError:
        print(f"错误：找不到输入文件 '{input_path}'。")
        return False
    except Exception as e:
        print(f"解密 '{input_path}' 时发生意外错误: {e}")
        return False

def main():
    """
    主函数，用于解析参数和分派任务。
    """
    args = sys.argv[1:]
    if len(args) < 2:
        print("用法: python universal_decryptor.py <输入文件> <输出文件> [--key-file <密钥表路径>]")
        print("\n支持的文件名:")
        print("  nscript.dat, nscr_sec.dat, onscript.nt2, onscript.nt3, 0.txt, 00.txt")
        print("  nscript.___ (需要 --key-file 参数)")
        sys.exit(1)

    input_path = args[0]
    output_path = args[1]
    key_file_path = None

    if '--key-file' in args:
        try:
            key_file_index = args.index('--key-file') + 1
            key_file_path = args[key_file_index]
        except (ValueError, IndexError):
            print("错误：'--key-file' 参数后需要提供一个文件路径。")
            sys.exit(1)

    filename = os.path.basename(input_path).lower()
    
    print(f"正在处理文件: {input_path}")
    print(f"尝试根据文件名 '{filename}' 自动检测格式...")

    decrypted_data = None
    success = False

    # 根据文件名分派任务
    if filename in ["0.txt", "00.txt"]:
        print("检测到格式：明文 (模式 0)")
        with open(input_path, 'rb') as f:
            decrypted_data = f.read()
        success = True
    elif filename == "nscript.dat":
        print("检测到格式: nscript.dat (模式 1)")
        with open(input_path, 'rb') as f:
            decrypted_data = decrypt_nscript_dat(f.read())
        success = True
    elif filename == "nscr_sec.dat":
        print("检测到格式: nscr_sec.dat (模式 2)")
        with open(input_path, 'rb') as f:
            decrypted_data = decrypt_nscr_sec_dat(f.read())
        success = True
    elif filename == "nscript.___":
        print("检测到格式: nscript.___ (模式 3)")
        with open(input_path, 'rb') as f:
            decrypted_data = decrypt_nscript____(f.read(), key_file_path)
        if decrypted_data:
            success = True
    elif filename == "onscript.nt2":
        print("检测到格式: onscript.nt2 (模式 4)")
        with open(input_path, 'rb') as f:
            decrypted_data = decrypt_onscript_nt2(f.read())
        success = True
    elif filename == "onscript.nt3":
        print("检测到格式: onscript.nt3 (模式 5)")
        success = decrypt_onscript_nt3(input_path, output_path)
    else:
        print(f"错误：无法识别的文件名 '{filename}'。无法确定加密格式。")
        sys.exit(1)

    # 写入文件 (nt3模式除外，因为它自己处理写入)
    if decrypted_data is not None and filename != "onscript.nt3":
        with open(output_path, 'wb') as f_out:
            f_out.write(decrypted_data)
    
    if success:
        print(f"✅ 解密成功！输出文件已保存为 '{output_path}'。")
    else:
        print("❌ 解密失败。")

if __name__ == '__main__':
    main()