#!/usr/bin/env python3

import pprint
import sys
import io

pp = pprint.PrettyPrinter()

CONSTANT_Class              = 7
CONSTANT_Fieldref           = 9
CONSTANT_Methodref          = 10
CONSTANT_InterfaceMethodref = 11
CONSTANT_String             = 8
CONSTANT_Integer            = 3
CONSTANT_Float              = 4
CONSTANT_Long               = 5
CONSTANT_Double             = 6
CONSTANT_NameAndType        = 12
CONSTANT_Utf8               = 1
CONSTANT_MethodHandle       = 15
CONSTANT_MethodType         = 16
CONSTANT_InvokeDynamic      = 18

class_access_flags = [
    ("ACC_PUBLIC"     , 0x0001),
    ("ACC_FINAL"      , 0x0010),
    ("ACC_SUPER"      , 0x0020),
    ("ACC_INTERFACE"  , 0x0200),
    ("ACC_ABSTRACT"   , 0x0400),
    ("ACC_SYNTHETIC"  , 0x1000),
    ("ACC_ANNOTATION" , 0x2000),
    ("ACC_ENUM"       , 0x4000)
]

method_access_flags = [
    ("ACC_PUBLIC", 0x0001),
    ("ACC_PRIVATE", 0x0002),
    ("ACC_PROTECTED", 0x0004),
    ("ACC_STATIC", 0x0008),
    ("ACC_FINAL", 0x0010),
    ("ACC_SYNCHRONIZED", 0x0020),
    ("ACC_BRIDGE", 0x0040),
    ("ACC_VARARGS", 0x0080),
    ("ACC_NATIVE", 0x0100),
    ("ACC_ABSTRACT", 0x0400),
    ("ACC_STRICT", 0x0800),
    ("ACC_SYNTHETIC", 0x1000),
]

def parse_flags(value: int, flags: list[tuple[str, int]]) -> list[str]:
    return [name for (name, mask) in flags if (value & mask) != 0]

def parse_u1(f: io.BufferedReader | io.BytesIO): return int.from_bytes(f.read(1), 'big')
def parse_u2(f: io.BufferedReader | io.BytesIO): return int.from_bytes(f.read(2), 'big')
def parse_u4(f: io.BufferedReader | io.BytesIO): return int.from_bytes(f.read(4), 'big')

def parse_attributes(f, count):
    attributes = []
    for j in range(count):
        # attribute_info {
        #     u2 attribute_name_index;
        #     u4 attribute_length;
        #     u1 info[attribute_length];
        # }
        attribute = {}
        attribute['attribute_name_index'] = parse_u2(f)
        attribute_length = parse_u4(f)
        attribute['info'] = f.read(attribute_length)
        attributes.append(attribute)
    return attributes

def bytes_to_float(bits) -> float:
    if bits == 0x7f800000:
        return float('inf')
    elif bits == 0xff800000:
        return -float('inf')
    elif 0x7f800001 <= bits <= 0x7fffffff or 0xff800001 <= bits <= 0xffffffff:
        return None
    else:
        s = 1 if ((bits >> 31) == 0) else -1
        e = ((bits >> 23) & 0xff)
        m = (bits & 0x7fffff) << 1 if (e == 0) else (bits & 0x7fffff) | 0x800000
        # TODO fix this
        return s * m * 2 ** (e - 150)

def bytes_to_long(high_bytes, low_bytes) -> int:
    return (high_bytes << 32) + low_bytes

def parse_class_file(file_path):
    with open(file_path, "rb") as f:
        clazz = {}
        clazz['magic'] = hex(parse_u4(f))
        clazz['minor'] = parse_u2(f)
        clazz['major'] = parse_u2(f)
        constant_pool_count = parse_u2(f)
        constant_pool = []
        n = 1
        # constant_pool table is indexed from 1 to constant_pool_count - 1
        while n < constant_pool_count:
            cp_info = {}
            tag = parse_u1(f)
            if tag == CONSTANT_Methodref:
                cp_info['tag'] = 'CONSTANT_Methodref'
                cp_info['class_index'] = parse_u2(f)
                cp_info['name_and_type_index'] = parse_u2(f)
            elif tag == CONSTANT_Class:
                cp_info['tag'] = 'CONSTANT_Class'
                cp_info['name_index'] = parse_u2(f)
            elif tag == CONSTANT_NameAndType:
                cp_info['tag'] = 'CONSTANT_NameAndType'
                cp_info['name_index'] = parse_u2(f)
                cp_info['descriptor_index'] = parse_u2(f)
            elif tag == CONSTANT_Utf8:
                cp_info['tag'] = 'CONSTANT_Utf8'
                length = parse_u2(f)
                cp_info['bytes'] = f.read(length)
            elif tag == CONSTANT_Fieldref:
                cp_info['tag'] = 'CONSTANT_Fieldref'
                cp_info['class_index'] = parse_u2(f)
                cp_info['name_and_type_index'] = parse_u2(f)
            elif tag == CONSTANT_String:
                # https://docs.oracle.com/javase/specs/jvms/se7/html/jvms-4.html#jvms-4.4.3
                cp_info['tag'] = 'CONSTANT_String'
                cp_info['string_index'] = parse_u2(f)
            elif tag == CONSTANT_Integer:
                cp_info['tag'] = 'CONSTANT_Integer'
                cp_info['bytes'] = parse_u4(f)
            elif tag == CONSTANT_Float:
                # https://docs.oracle.com/javase/specs/jvms/se7/html/jvms-4.html#jvms-4.4.5
                cp_info['tag'] = 'CONSTANT_Float'
                cp_info['bytes'] = parse_u4(f)
            # constant_pool index (n + 1) must be valid but is considered unusable
            # In retrospect, making 8-byte constants take two constant pool entries was a poor choice.
            elif tag == CONSTANT_Long:
                cp_info['tag'] = 'CONSTANT_Long'
                cp_info['high_bytes'] = parse_u4(f)
                cp_info['low_bytes'] = parse_u4(f)
                n += 1
                constant_pool.append(None)
            elif tag == CONSTANT_Double:
                cp_info['tag'] = 'CONSTANT_Double'
                cp_info['high_bytes'] = parse_u4(f)
                cp_info['low_bytes'] = parse_u4(f)
                n += 1
                constant_pool.append(None)
            else:
                raise NotImplementedError(f"Unexpected constant tag {tag} in class file {file_path}")
            constant_pool.append(cp_info)
            n += 1
        # print('\n'.join(str(cp) for cp in constant_pool))
        clazz['constant_pool'] = constant_pool
        clazz['access_flags'] = parse_flags(parse_u2(f), class_access_flags)
        clazz['this_class'] = parse_u2(f)
        clazz['super_class'] = parse_u2(f)
        interfaces_count = parse_u2(f)
        interfaces = []
        for i in range(interfaces_count):
            # https://docs.oracle.com/javase/specs/jvms/se7/html/jvms-4.html#jvms-4.4.1
            interface = {}
            interface['tag'] = parse_u1(f)
            interface['name_index'] = parse_u2(f)
            interfaces.append(interface)
        # print(interfaces)
            raise NotImplementedError("We don't support interfaces")

        clazz['interfaces'] = interfaces
        fields_count = parse_u2(f)
        fields = []
        for i in range(fields_count):
            raise NotImplementedError("We don't support fields")
        clazz['fields'] = fields
        methods_count = parse_u2(f)
        methods = []
        for i in range(methods_count):
            # u2             access_flags;
            # u2             name_index;
            # u2             descriptor_index;
            # u2             attributes_count;
            # attribute_info attributes[attributes_count];
            method = {}
            method['access_flags'] = parse_flags(parse_u2(f), method_access_flags)
            method['name_index'] = parse_u2(f)
            method['descriptor_index'] = parse_u2(f)
            attributes_count = parse_u2(f)
            method['attributes'] = parse_attributes(f, attributes_count)
            methods.append(method)
        clazz['methods'] = methods
        attributes_count = parse_u2(f)
        clazz['attributes'] = parse_attributes(f, attributes_count)
        return clazz

def find_methods_by_name(clazz, name: bytes):
    return [method
            for method in clazz['methods']
            if clazz['constant_pool'][method['name_index'] - 1]['bytes'] == name]

def find_attributes_by_name(clazz, attributes, name: bytes):
    return [attr
            for attr in attributes
            if clazz['constant_pool'][attr['attribute_name_index'] - 1]['bytes'] == name]

def parse_code_info(info: bytes):
    code = {}
    with io.BytesIO(info) as f:
        # Code_attribute {
        #     u2 attribute_name_index;
        #     u4 attribute_length;
        #     u2 max_stack;
        #     u2 max_locals;
        #     u4 code_length;
        #     u1 code[code_length];
        #     u2 exception_table_length;
        #     {   u2 start_pc;
        #         u2 end_pc;
        #         u2 handler_pc;
        #         u2 catch_type;
        #     } exception_table[exception_table_length];
        #     u2 attributes_count;
        #     attribute_info attributes[attributes_count];
        # }
        code['max_stack'] = parse_u2(f)
        code['max_locals'] = parse_u2(f)
        code_length = parse_u4(f)
        code['code'] = f.read(code_length)
        exception_table_length = parse_u2(f)
        # NOTE: parsing the code attribute is not finished
        return code

iconst_m1 = 0x2
iconst_0 = 0x3
iconst_1 = 0x4
iconst_2 = 0x5
iconst_3 = 0x6
iconst_4 = 0x7
iconst_5 = 0x8

getstatic = 0xb2
ldc = 0x12
invokevirtual = 0xb6
return_ = 0xb1
bipush = 0x10
fconst_0 = 0xb
fconst_1 = 0xc
fconst_2 = 0xd
sipush = 0x11
lconst_0 = 0x9
lconst_1 = 0xa
ldc2_w = 0x14

def get_name_of_class(clazz, class_index: int) -> str:
    return clazz['constant_pool'][clazz['constant_pool'][class_index - 1]['name_index'] - 1]['bytes'].decode('utf-8')

def get_name_of_member(clazz, name_and_type_index: int) -> str:
    return clazz['constant_pool'][clazz['constant_pool'][name_and_type_index - 1]['name_index'] - 1]['bytes'].decode('utf-8')

def execute_code(clazz, code: bytes):
    stack: list[dict] = []
    with io.BytesIO(code) as f:
        while f.tell() < len(code):
            opcode = parse_u1(f)
            if opcode == getstatic:
                index = parse_u2(f)
                fieldref = clazz['constant_pool'][index - 1]
                name_of_class = get_name_of_class(clazz, fieldref['class_index'])
                name_of_member = get_name_of_member(clazz, fieldref['name_and_type_index'])
                if name_of_class == 'java/lang/System' and name_of_member == 'out':
                    stack.append({'type': 'FakePrintStream'})
                else:
                    raise NotImplementedError(f"Unsupported member {name_of_class}/{name_of_member} in getstatic instruction")
            elif opcode == ldc:
                index = parse_u1(f)
                stack.append({'type': 'Constant', 'const': clazz['constant_pool'][index - 1]})
            elif opcode == invokevirtual:
                index = parse_u2(f)
                methodref = clazz['constant_pool'][index - 1]
                name_of_class = get_name_of_class(clazz, methodref['class_index'])
                name_of_member = get_name_of_member(clazz, methodref['name_and_type_index'])
                if name_of_class == 'java/io/PrintStream' and name_of_member == 'println':
                    stack_len = len(stack)
                    if stack_len < 2:
                        raise RuntimeError(f'{name_of_class}/{name_of_member} expects 2 arguments, but provided {stack_len}')
                    obj = stack[stack_len - 2]
                    if obj['type'] != 'FakePrintStream':
                        raise NotImplementedError(f"Unsupported stream type {obj['type']}")
                    arg = stack[stack_len - 1]
                    if arg['type'] == 'Constant':
                        if arg['const']['tag'] == 'CONSTANT_String':
                            # index_to_string_in_constant_pool = arg['const']['string_index'] - 1
                            print(clazz['constant_pool'][arg['const']['string_index'] - 1]['bytes'].decode('utf-8'))
                        elif arg['const']['tag'] == 'CONSTANT_Integer':
                            print(arg['const']['bytes'])
                        elif arg['const']['tag'] == 'CONSTANT_Float':
                            print(bytes_to_float(arg['const']['bytes']))
                        elif arg['const']['tag'] == 'CONSTANT_Long':
                            arg['const']
                            print(bytes_to_long(
                                arg['const']['high_bytes'],
                                arg['const']['low_bytes']
                            ))
                        # elif arg['const']['tag'] == 'CONSTANT_Double':
                        #     print(clazz['constant_pool'][arg['const']['string_index'] - 1]['bytes'].decode('utf-8'))
                        else:
                            raise NotImplementedError(f"println for {arg['const']['tag']} is not implemented")
                    elif arg['type'] == 'Integer' or arg['type'] == 'Short':
                        print(arg['value'])
                    elif arg['type'] == 'Float':
                        # TODO print with precision?
                        print(arg['value'])
                    elif arg['type'] == 'Long':
                        # for lconst
                        print(arg['value'])
                    else:
                        raise NotImplementedError(f"Support for {arg['type']} is not implemented")
                else:
                    raise NotImplementedError(f"Unknown method {name_of_class}/{name_of_member} in invokevirtual instruction")
            elif opcode == return_:
                # TODOO ??
                return
            elif opcode == bipush:
                byte = parse_u1(f)
                stack.append({'type': 'Integer', 'value': byte})
            elif opcode == iconst_m1:
                stack.append({'type': 'Integer', 'value': -1})
            elif opcode == iconst_0:
                stack.append({'type': 'Integer', 'value': 0})
            elif opcode == iconst_1:
                stack.append({'type': 'Integer', 'value': 1})
            elif opcode == iconst_2:
                stack.append({'type': 'Integer', 'value': 2})
            elif opcode == iconst_3:
                stack.append({'type': 'Integer', 'value': 3})
            elif opcode == iconst_4:
                stack.append({'type': 'Integer', 'value': 4})
            elif opcode == iconst_5:
                stack.append({'type': 'Integer', 'value': 5})
            elif opcode == fconst_0:
                stack.append({'type': 'Float', 'value': 0.0})
            elif opcode == fconst_1:
                stack.append({'type': 'Float', 'value': 1.0})
            elif opcode == fconst_2:
                stack.append({'type': 'Float', 'value': 2.0})
            elif opcode == sipush:
                byte1 = parse_u1(f)
                byte2 = parse_u1(f)
                # TODO check if Int
                stack.append({'type': 'Short', 'value': byte1 << 8 | byte2})
            elif opcode == lconst_0:
                stack.append({'type': 'Long', 'value': 0})
            elif opcode == lconst_1:
                stack.append({'type': 'Long', 'value': 1})
            elif opcode == ldc2_w:
                indexbyte1 = parse_u1(f)
                indexbyte2 = parse_u1(f)
                index = (indexbyte1 << 8) | indexbyte2
                stack.append({'type': 'Constant', 'const': clazz['constant_pool'][index]})
            else:
                raise NotImplementedError(f"Unknown opcode {hex(opcode)}")

if __name__ == '__main__':
    program, *args = sys.argv
    if len(args) == 0:
        print(f"Usage: {program} <path/to/Main.class>")
        print(f"ERROR: no path to Main.class was provided")
        exit(1)
    file_path, *args = args
    clazz = parse_class_file(file_path)
    [main] = find_methods_by_name(clazz, b'main')
    [code] = find_attributes_by_name(clazz, main['attributes'], b'Code')
    code_attrib = parse_code_info(code['info'])
    execute_code(clazz, code_attrib['code'])
