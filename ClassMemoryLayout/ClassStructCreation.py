import binaryninja as bn
from . import LayoutLoader
from typing import *


def CreateClass(bv: bn.binaryview, class_name: str) -> Optional[str]:
    """
    !!!THIS FUNCTION SHOULD BE CALLED ONLY FROM THE ClassHierarchy PACKAGE!!!
    :param bv: BinaryView to define this class struct in.
    :param class_name:
    :return: If class was not succesfully created return None, otherwise return the class name as it appears in
             the binary view types db.
    """
    std_class_name, class_info = LayoutLoader.get_class_layout(class_name)

    if std_class_name:
        speculative_namespace: str = std_class_name.split("::")[0]
        print(f'CreateClass: Processing class {std_class_name} - {class_info["layout"]}')
        class_size = class_info['class_size']
        class_layout = class_info['layout']
        class_members = list()
        if class_size > 1:
            for (member_offset, member_name, member_type) in class_layout:
                print(f'CreateClass: Processing member {member_type} {member_name}')
                if member_type == 'class':
                    if t := bv.get_type_by_name(member_name):
                        name = member_name
                    elif name := CreateClass(bv, member_name):
                        t = bv.get_type_by_name(name)
                    else:
                        print(f'CreateClass: ERROR! Unable to find type definition for {member_type}')
                        return ""
                else:
                    if t := bv.get_type_by_name(member_name):
                        name = member_name
                    else:
                        try:
                            print(f'CreateClass: parse_type_string({member_type})')
                            t, _ = bv.parse_type_string(member_type)
                            name = member_name
                        except Exception as e:
                            print(f'CreateClass: CreateClass(bv, {member_type})')
                            if name := CreateClass(bv, member_type):
                                t = bv.get_type_by_name(name)
                            else:
                                if name := CreateClass(bv, f'{speculative_namespace}::{member_type}'):
                                    t = bv.get_type_by_name(name)
                                else:
                                    print(f'CreateClass: ERROR! Unable to find type definition for {member_type}')
                                    return ""
                class_members.append((t, name))

        bv.define_user_type(std_class_name,
                            bn.types.Type.structure(members=class_members))
        print(f'CreateClass: Successfully define class {std_class_name} - {class_members} ')

    else:
        print(f'CreateClass: ERROR! Unable to create class {class_name}')

    return std_class_name
