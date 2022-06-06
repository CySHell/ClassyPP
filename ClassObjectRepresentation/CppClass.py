
class ClassyClass:

    def __init__(self):
        self.name: str = ''
        self.size: int = 0
        # fields - {offset: (<binaryninja.types>, <Field name>, Optional(Address in executable pointed to))}
        self.fields: dict = dict()
        # vfTable - A list of all function addresses in the table
        self.vfTable: list[int] = list()
        self.constructors: list[int] = list()
        self.inherited_classes: list[ClassyClass] = list()
        self.namespace: str = ''