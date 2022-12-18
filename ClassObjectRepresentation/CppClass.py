from dataclasses import dataclass, field

# {ClassName: ClassyClass}
global_classes: dict = dict()


def GenerateClassNameFromVtableAddr(vTable_addr: int) -> str:
    return f"class_{hex(vTable_addr)}_vfTable"


@dataclass
class ClassyClass:

    def __init__(self, name: str, vfTable_addr: int, constructors: list[int] = None,
                 inherited_classes: list = None, vfTable_functions: list[int] = None, size: int = 0,
                 namespace="", fields=None):

        self.name: str = name
        self.vfTable_addr: int = vfTable_addr
        self.constructors: list[int] = constructors if constructors else list()
        self.namespace: str = namespace
        self.size: int = size
        # fields - {offset: (<binaryninja.types>, <Field name>, Optional(Address in executable pointed to))}
        self.fields: dict = fields if fields else dict()
        # list[ClassyClass]
        self.inherited_classes: list = inherited_classes if inherited_classes else list()
        # vfTable - A list of all function addresses in the table
        self.vfTable_functions: list[int] = vfTable_functions if vfTable_functions else list()

        global_classes.update({self.name: self})
