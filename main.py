from argparse import ArgumentParser, FileType


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
            # print(hexCode)
            hexCode = hexCode.replace('0x', '')
            # print(hexCode)
            if len(hexCode) == 1:
                hexCode = '0' + hexCode
            hexCode = r'\x'+hexCode  # \x UTF-8 编码
            shellcode_confused += hexCode
            #print(shellcode_confused)
            shellcode_size += 1
            src.close()
            out.write(shellcode_confused)
            out.close()
    except Exception as e:
        print(e)
    return shellcode_size


def main():
    parser = ArgumentParser(description="混淆CS生成的Raw Shellcode")
    # 输入.bin文件，输出混淆后的shellcode
    # python main.py -s raw.bin -o output_shell
    parser.add_argument('-s', '--src', help="raw shellcode,.bin file", type=FileType('rb'), required=True)
    parser.add_argument('-o', '--output', help='out put confused shellcode', type=FileType('w+'), required=True)
    parser.add_argument('-n', '--num', help='number of shellcode be confused', type=int, default=50)
    args = parser.parse_args()
    shellcode_size = process_confused(args.src, args.num, args.output)
    print("[+]Shellcode 混淆完成, Shellcode Size:{}".format(shellcode_size))


if __name__ == '__main__':
    main()
