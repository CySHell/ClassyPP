import os
import json
from .. import Config
from typing import *
from .LayoutParser import ClassLayout


# {
#  class_name: {
#               'class_size': int,
#               'layout': [ (offset: int, member_name, member_type) ]
#              }
# }
def get_db(json_file_path: str) -> Dict[str, ClassLayout]:
    with open(json_file_path, "r") as f:
        return json.loads(f.read())


CLASS_LAYOUT_FILE_NAME = f'class_layouts.txt'
CLASS_LAYOUTS_FILE_PATH = f'{Config.PATH_TO_LAYOUT_FOLDER}{CLASS_LAYOUT_FILE_NAME}'


def convert_name_from_binja_to_db_format(class_name: str) -> str:
    if class_name.startswith('struct'):
        class_name = class_name[7:]
    elif class_name.startswith('class'):
        class_name = class_name[6:]
    else:
        pass
    return class_name.strip().replace(', ', ',').replace('>>>>', '> > > >'). \
        replace('>>>', '> > >').replace('>>', '> >').strip()


def get_class_layout(class_name: str) -> Tuple[Optional[str], Optional[ClassLayout]]:
    layout_db: Dict[str, ClassLayout] = get_db(CLASS_LAYOUTS_FILE_PATH)
    fixedup_class_name: str = convert_name_from_binja_to_db_format(class_name)
    if layout_db.get(fixedup_class_name):
        return fixedup_class_name, layout_db[fixedup_class_name]
    else:
        return None, None


