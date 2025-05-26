#!/usr/bin/python3

from sys import argv
from os import chmod, path
from re import findall

from ae_funcs import find_arg

class HexDump:
    def __init__(self, file, size=0, h2b=False,
        outf=None, outa=False, outs=False, buff=16, offset=0, addrsz=8,):
        
        '''
        file  : objfile or hexfile
        buff  : buffer ( 16 bytes for each line)
        offset: offset (start address)
        addsz : address size (8 byte)
        size  : size  (n bytes to display) # hex format 
        outf  : out filename
        h2b   : hex to bin  (need hex file)
        outa  : out address (display addresses size)
        outs  : out string  (dispaly ascii string)
        '''

        self.file       = file
        self._buffer    = buff
        self._offset    = int(str(offset), 16)
        self._addr_size = addrsz
        self._size      = int(str(size), 16)
        self._out_file  = outf
        self._out_addr  = outa
        self._out_ascii = outs        
        self._h2b       = h2b
        
        self._address   = 0

        self.check_file()
        print()

    def check_file(self, file=None):
        file = self.file or file
        
        if  path.isfile(file):
            self._out_file = self._out_file or (file + '.bin')
        
        else:
            print(f'file not exists "{file}"')
            self.hlp()

    def print_addr(self, zero='.'):
        if  not self._out_addr:
            return

        if  len(hex(self._address)) > self._addr_size:
            print('Warning: Overflow address!!')
            exit()
        
        addr = hex(self._address)[2:]
        zero = zero * (self._addr_size - len(addr))
        print(zero + addr, end='|  ')
        
    def bytes_to_hexs(self):
        zeros = 0
        with open(self.file, 'rb') as fo:
            while '!EOF':
                bytes_16 = fo.read(self._buffer)    # default:16-bytes
                bytes_sz = len(bytes_16)

                if  not bytes_16 or (self._size and self._size <= self._address):
                    if  zeros:
                        print(f'[ {hex(zeros)[2:]} ]')
                    print('stop')
                    break             
                  
                if  self._address < self._offset:
                    self._address += bytes_sz
                    continue

                if  bytes_16 == self._buffer * b'\x00':
                    zeros += 1
                    continue
                
                if  zeros:
                    if  zeros > 1:
                        print(f'[ {hex(zeros)[2:]} ]')
                    else:
                        self.print_addr()
                        print('.. ' * self._buffer, end='')
                        self.bytes_to_str(str_16='.' * 16)

                    self._address += zeros * self._buffer
                    if  self._size and self._size <= self._address:
                        break
                    zeros = 0

                self.print_addr()
                self._address += self._buffer

                for byte in bytes_16:
                    print(hex(byte)[2:].rjust(2, '0').replace('0', '.'), end=' ')
                
                if  bytes_sz < self._buffer:
                    print('   ' * (self._buffer - bytes_sz), end='')
                
                self.bytes_to_str(bytes_16)

    def bytes_to_str(self, bytes_16='', str_16=''):
        if  self._out_ascii:
            print(' | ', end='')
            if  str_16:
                print(str_16, end='')
            else:
                [print(chr(byte) if  31 < byte < 127 else '.', end='') for byte in bytes_16]
        print()

    def hexs_to_bytes(self):
        bytes = ''
        fo    = open(self.file)
        while '!EOF':
            hexs = fo.readline()
            if  not hexs:
                fo.close()
                with open(self._out_file, 'wb') as fo:
                    fo.write(bytes.encode('latin'))
                chmod(self._out_file, 509)
                print(f'"{self._out_file}" generated.')
                break
                
            hexs = hexs.strip()
                
            if  hexs.startswith((';', '#', '//')):
                print('skip comment;')
                continue

            if  hexs.startswith('['):
                nzw = hexs.strip(' []')
                if  '=' in nzw:
                    nzw = int(nzw.strip('='), 16)
                else:
                    nzw = int(nzw, 16) * self._buffer
                bytes += '\x00' * nzw
                continue
                
            elif '|' in hexs:
                Id = 0
                if  hexs.index('|') < self._addr_size+2:
                    Id += 1
                hexs = hexs.split('|')[Id]
                    
            for hexnum in hexs.split()[:16]:
                hexnum = hexnum.strip().replace('.', '0')
                hexnum = int(hexnum, 16)
                if  hexnum > 255:
                    print(f'Error: {hexnum} not in range.')
                    exit()
                bytes += chr(hexnum)

    def hlp(self):
        exit('''
        \r ae_hexdump : Convert binary_code <=> hex_code.

        \r 1- Binary to hexadecimal.       
        \r $ ae_hexdump [opt] file    
        \r [opt]:
        \r    -addr      : display addresses        # objfile
        \r    -ascii     : display ascii string
        \r    -size      : length of bytes in hex
        \r    -out       : save filename
        \r    -offset    : address start from in hex

        \r    -h2b       : hex to binary            # hexfile

        \r    -h  --help : show this help. 
        ''')


if  __name__ == '__main__':
    outaddr = find_arg('-addr')
    outstr  = find_arg('-ascii')
    size    = find_arg('-size', val=True, default=0)
    offset  = find_arg('-offset', val=True, default=0)
    name    = find_arg('-out', val=True)
    h2b     = find_arg('-h2b')

    files = find_arg('')

    if  not files or find_arg(['-h', '--help']):
        HexDump.hlp(HexDump)

    hexdump = HexDump(files[0], size, h2b, name, outaddr, outstr, offset=offset)

    if  h2b:
        hexdump.hexs_to_bytes()
    else:
        hexdump.bytes_to_hexs()

