from typing import *
import re
import json
import os


class ClassLayout(Dict):
    class_size: int
    # layout : [ (offset_in_class, member_name, member_type),... ]
    # member_type is the hash of the class or struct of the member
    layout: List[Tuple[int, str, str]]


# {
#  class_hash: {
#               'class_size': int,
#               'layout': [ (offset: int, member_name, member_type) ]
#              }
# }
class_layouts: Dict[str, ClassLayout] = dict()


def is_primitive_type(type: str) -> bool:
    return type.startswith('uint') or type.startswith('void*') or type == 'class'


def is_blacklisted_class(class_name: str) -> bool:
    # Some classes have dynamic and\or ambigious definitions emmited by the compiler for different contextes.
    return "__vc_attributes" in class_name or "lambda" in class_name or not class_name


def is_blacklisted_line(line: str) -> bool:
    return line.strip().endswith(f'+---') or line.strip().endswith('| e)') or "| &" in line


def start_of_class_definition(line: str):
    # #print(f'start_of_class_definition: Parsing line - {line}')
    return (line.startswith(f'  class') or line.startswith(f'  struct')) and line.endswith(f'):\n') and 'size(' in line


def get_class_info(line: str) -> Tuple[str, int]:
    initial_split: list[str] = line.split('size(')
    # print(f'get_class_info: initial_split - {initial_split}')
    try:
        class_size: int = int(initial_split[1].split('):')[0])
    except ValueError as e:
        # print(f'get_class_info: Class size is not an integer - {line}, aborting class definition.')
        return "", 0

    if initial_split[0].startswith(f'  class '):
        # #print(f'get_class_info: Getting class name for {line}')
        class_name: str = initial_split[0].rsplit(f'  class ', 1)[1].strip()
    elif initial_split[0].startswith(f'  struct '):
        # #print(f'get_class_info: Getting struct name for {line}')
        class_name: str = initial_split[0].rsplit(f'  struct ', 1)[1].strip()
    else:
        # print(f'get_class_info: Unknown line format - {line}')
        class_name: str = str()
    return class_name.strip(), class_size


def get_layout_member_offset(line: str) -> int:
    return int(re.search(f'\d+', line).group())


def get_hierarchy_level(line: str) -> int:
    return line.count(f'|')


def get_member_class_name(line: str) -> str:
    return line.split(f'base class')[1].split(f')')[0].strip()


def get_data_member_info(line: str) -> Tuple[str, str]:
    if f'<alignment member>' in line:
        return f'alignment_member', re.search(f'\d+', line).group()
    else:
        processed_line = line.split(f'|')[1].split()
        if len(processed_line) == 2:
            return processed_line[1], processed_line[0]
        elif len(processed_line) == 1:
            return processed_line[0], ""
        else:
            # print(f'get_data_member_info: Unable to parse data member - {processed_line}')
            return "", ""


# {
#  class_name: {
#               'class_size': int,
#               'layout': [ (offset: int, member_name, member_type) ]
#              }
# }
def populate_class_layout(class_name: str,
                          class_size: int,
                          member_offset: int = 0,
                          member_type: str = "",
                          member_name: str = "") -> bool:
    if class_layouts.get(class_name):
        # Class was already defined.
        if class_layouts[class_name]['class_size'] == class_size:
            # The defined class has the same size as the one we are defining here, meaning it is probably
            # correctly defined and we can safely add the member.
            if member_offset:

                if member_offset > class_size:
                    print(f'member_offset {member_offset} , class_size {class_size}')
                    # The compiler emits errors in the form of class members that are at an offset
                    # higher then the class size - usually the correct class definition will just apear
                    # later in the compiler output.
                    print(f'Popping out class {class_name}')
                    class_layouts.pop(class_name)
                    return False
                else:
                    class_layouts[class_name]['layout'].append((member_offset, member_name, member_type))
                    return True
            else:
                # If we got here it means the class is of size 1 and has no members (probably an interface).
                return True
        else:
            # Size mismatch, we have conflicting definition of the class.
            # print(f'populate_class_layout: ERROR! Size mismatch between defined class and current class!')
            return False
    else:
        class_layouts.update({class_name: {
            'class_size': class_size,
            'layout': [
                (member_offset, member_name, member_type)
            ]
        }})
        return True


def build_class_layout(class_layout_lines: List[str], class_name: str, class_size: int):
    if class_layout_lines and class_size > 1:
        # TODO: Handle classes with size 1 better
        resolved_offsets: List[int] = list()
        for line in class_layout_lines:
            if get_hierarchy_level(line) == 1:
                if is_blacklisted_line(line):
                    pass
                else:
                    # We are only interested in first class members and directly inherited classes,
                    # not the classes inherited by the directly inherited classes.
                    member_offset: int = get_layout_member_offset(line)
                    if member_offset in resolved_offsets:
                        pass
                    else:
                        if '+---' in line:
                            # We have a nested struct\class here.
                            member_name = get_member_class_name(line)
                            member_type = "class"
                        else:
                            # We have a data member of the class
                            member_name, member_type = get_data_member_info(line)
                        if populate_class_layout(class_name, class_size, member_offset, member_type, member_name):
                            resolved_offsets.append(member_offset)
                        else:
                            break
    else:
        populate_class_layout(class_name, class_size)


def standardize_int_size(size: int) -> str:
    # TODO: change this to a switch case once python 10 is adopted
    # Byte = 8 bits
    standard_size: int = size * 8
    if standard_size in [8, 16, 32, 64, 128]:
        return f'uint{standard_size}_t'
    else:
        return f'uint8_t[{size}]'


def fixup_member_types():
    """
    For each class parsed from the layout file, if a member has no type defined then define the type
    as the member size in bytes.
    :return:
    """
    for class_name, class_info in class_layouts.items():
        class_size: int = class_info['class_size']
        fixed_members_layout = list()
        if class_size > 1:
            class_offset: int = class_size
            members_layout: List[Tuple[int, str, str]] = class_info['layout']
            members_layout.reverse()
            for member in members_layout:
                member_offset: int = member[0]
                member_name: str = member[1]
                member_type: str = member[2]
                if member_type:
                    if member_name == 'alignment_member':
                        member_type = standardize_int_size(member_offset)
                        member_offset = class_offset - member_offset
                    else:
                        # Type is already defined
                        pass
                else:
                    if member_name == '{vfptr}':
                        member_name = f'virtual_function_table;'
                        member_type = f'void*'
                    elif member_name == '{vbptr}':
                        member_name = f'virtual_base_class_table;'
                        member_type = f'void*'
                    else:
                        member_type = standardize_int_size(class_offset - member_offset)
                fixed_members_layout.append((member_offset, member_name, member_type))
                class_offset = member_offset
        if fixed_members_layout:
            fixed_members_layout.reverse()
            class_layouts[class_name]['layout'] = fixed_members_layout


def verify_member_types() -> bool:
    """
    After parsing all class layouts, we now need to check that the type field of the class members
    is well defined within the DB, otherwise we need to assign an int type that represents the size
    of the member.
    :return:
    """
    for class_name, class_info in class_layouts.items():
        speculative_namespace: str = class_name.split(f"::{class_name}")[0]
        class_size = class_info.get('class_size')
        fixed_members_layout = list()
        if class_size > 1:
            class_offset: int = class_size
            members_layout: List[Tuple[int, str, str]] = class_info['layout']
            members_layout.reverse()
            for member in members_layout:
                member_offset: int = member[0]
                member_name: str = member[1]
                member_type: str = member[2]
                if member_type:
                    if class_layouts.get(member_type):
                        continue
                    elif is_primitive_type(member_type):
                        continue
                    elif class_layouts.get(member_type):
                        continue
                    elif class_layouts.get(speculative_namespace):
                        continue
                    else:
                        member_type = standardize_int_size(class_offset - member_offset)
                    fixed_members_layout.append((member_offset, member_name, member_type))
                    class_offset = member_offset
                else:
                    print(f'verify_member_types: ERRROR! No type found for {class_name} :: {member_name}')
                    return False
        if fixed_members_layout:
            fixed_members_layout.reverse()
            class_layouts[class_name]['layout'] = fixed_members_layout
        else:
            class_layouts[class_name]['layout'].reverse()


def parse_layout_file(file_path: str):
    with open(file_path, "r") as layout_file:
        while line := layout_file.readline():
            if start_of_class_definition(line):
                class_name, class_size = get_class_info(line)
                if is_blacklisted_class(class_name) or class_layouts.get(class_name):
                    pass
                else:
                    layout_file.readline()
                    class_layout_lines: List[str] = list()
                    while (class_line := layout_file.readline()).strip() != f'+---':
                        if '| &' in class_line:
                            pass
                        else:
                            class_layout_lines.append(class_line)
                    try:
                        build_class_layout(class_layout_lines, class_name, class_size)
                    except Exception as e:
                        # Unfortunately there are many bugs in the class layout output of MSVC which
                        # cause the output to not make sense.
                        # instead of trying to deal with every case, we just catch the exception and delete
                        # the class if it was created in the global list.
                        if class_layouts.get(class_name):
                            class_layouts.pop(class_name)


if __name__ == "__main__":
    import Config

    for filename in os.listdir(Config.PATH_TO_LAYOUT_FOLDER):
        if filename.startswith('layout_'):
            print(f'Parsing file {filename}')
            parse_layout_file(f'{Config.PATH_TO_LAYOUT_FOLDER}{filename}')

    fixup_member_types()
    verify_member_types()

    with open(f'{Config.PATH_TO_CLASS_LAYOUTS_FILE}', "w") as f:
        f.write(json.dumps(class_layouts, indent=4))
else:
    from ... import Config
