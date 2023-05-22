import binaryninja as bn
from . import LayoutLoader
from ...Common import Utils
from typing import *


def CreateClass(bv: bn.BinaryView, class_name: str) -> Optional[str]:
    """
    :param bv: BinaryView to define this class struct in.
    :param class_name: The format of the Class name *** MUST BE *** the format extracted using the demangler in the
                        "Common" package.
    :return: If class was not succesfully created return None, otherwise return the class name as it appears in
             the binary view types db.
    """
    std_class_name, class_info = LayoutLoader.get_class_layout(class_name)

    if std_class_name:
        speculative_namespace: str = std_class_name.split("::")[0]
        Utils.LogToFile(f'CreateClass: Processing class {std_class_name} - {class_info["layout"]}')
        class_size = class_info['class_size']
        class_layout = class_info['layout']
        class_members = list()
        if class_size > 1:
            for (member_offset, member_name, member_type) in class_layout:
                Utils.LogToFile(f'CreateClass: Processing member {member_type} {member_name}')
                if member_type == 'class':
                    if t := bv.get_type_by_name(member_name):
                        name = member_name
                    elif name := CreateClass(bv, member_name):
                        t = bv.get_type_by_name(name)
                    else:
                        Utils.LogToFile(f'CreateClass: ERROR! Unable to find type definition for {member_type}')
                        return ""
                else:
                    if t := bv.get_type_by_name(member_name):
                        name = member_name
                    else:
                        try:
                            Utils.LogToFile(f'CreateClass: parse_type_string({member_type})')
                            t, _ = bv.parse_type_string(member_type)
                            name = member_name
                        except Exception as e:
                            Utils.LogToFile(f'CreateClass: CreateClass(bv, {member_type})')
                            if name := CreateClass(bv, member_type):
                                t = bv.get_type_by_name(name)
                            else:
                                if name := CreateClass(bv, f'{speculative_namespace}::{member_type}'):
                                    t = bv.get_type_by_name(name)
                                else:
                                    Utils.LogToFile(f'CreateClass: ERROR! Unable to find type definition for {member_type}')
                                    return ""
                class_members.append((t, name))

        bv.define_user_type(std_class_name,
                            bn.types.Type.structure(members=class_members))
        Utils.LogToFile(f'CreateClass: Successfully define class {std_class_name} - {class_members} ')

    else:
        Utils.LogToFile(f'CreateClass: Unable to find class definition in DB for class {class_name}')

    return std_class_name
