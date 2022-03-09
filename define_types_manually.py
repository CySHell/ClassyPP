
TypeDescriptor = bn.types.Type.structure(
    members=[
        # Field overloaded by RTTI
        (bv.parse_type_string("void*")[0], 'pVFTable'),
        # reserved, possible for RTTI
        (bv.parse_type_string("void*")[0], 'spare'),
        # The decorated name of the type; 0 terminated.
        (bv.parse_type_string("char*")[0], 'name'),
    ],
    type=bn.StructureVariant.StructStructureType
)

bv.define_user_type('TypeDescriptor', TypeDescriptor)

################################
# _RTTI_RELATIVE_TYPEINFO = True
_RTTIBaseClassArray_relative = bn.types.Type.structure(
    members=[
        # Image relative offset of _RTTIBaseClassDescriptor
        (bv.parse_type_string("int[]")[0], 'arrayOfBaseClassDescriptors'),
    ],
    type=bn.StructureVariant.StructStructureType
)

bv.define_user_type('_RTTIBaseClassArray_relative', _RTTIBaseClassArray_relative)

################################
# _RTTI_RELATIVE_TYPEINFO = False

# Forward declaration of _RTTIBaseClassDescriptor
bv.define_user_type("_RTTIBaseClassDescriptor", bv.parse_type_string('void*')[0])

_RTTIBaseClassArray_non_relative = bn.types.Type.structure(
    members=[
        (bv.parse_type_string("_RTTIBaseClassDescriptor*")[0], 'arrayOfBaseClassDescriptors'),
    ],
    type=bn.StructureVariant.StructStructureType
)

################################
# _RTTI_RELATIVE_TYPEINFO = True
_RTTIClassHierarchyDescriptor_relative = bn.types.Type.structure(
    members=[
        (bv.parse_type_string("unsigned int")[0], 'signature'),
        (bv.parse_type_string("unsigned int")[0], 'attributes'),
        (bv.parse_type_string("unsigned int")[0], 'numBaseClasses'),
        # Image relative offset of _RTTIBaseClassArray
        (bv.parse_type_string("int")[0], 'pBaseClassArray'),
    ],
    type=bn.StructureVariant.StructStructureType
)

bv.define_user_type('_RTTIClassHierarchyDescriptor_relative', _RTTIClassHierarchyDescriptor_relative)

################################
# _RTTI_RELATIVE_TYPEINFO = False

# Forward declaration of _RTTIBaseClassArray
bv.define_user_type("_RTTIBaseClassArray", bv.parse_type_string("void*")[0])
_RTTIClassHierarchyDescriptor_non_relative = bn.types.Type.structure(
    members=[
        (bv.parse_type_string("unsigned int")[0], 'signature'),
        (bv.parse_type_string("unsigned int")[0], 'attributes'),
        (bv.parse_type_string("unsigned int")[0], 'numBaseClasses'),
        (bv.parse_type_string("_RTTIBaseClassArray*")[0], 'pBaseClassArray'),
    ],
    type=bn.StructureVariant.StructStructureType
)

bv.define_user_type('_RTTIClassHierarchyDescriptor_non_relative',
                    _RTTIClassHierarchyDescriptor_non_relative)

_PMD = bn.types.Type.structure(
    members=[
        # Offset of intended data within base
        (bv.parse_type_string("int")[0], 'mdisp'),
        # Displacement to virtual base pointer
        (bv.parse_type_string("int")[0], 'pdisp'),
        # Index within vbTable to offset of base
        (bv.parse_type_string("int")[0], 'vdisp')
    ],
    type=bn.StructureVariant.StructStructureType
)

bv.define_user_type('_PMD', _PMD)
_PMD_qualified = bn.types.Type.named_type_from_type(bn.QualifiedName("PMD"), _PMD)

################################
# _RTTI_RELATIVE_TYPEINFO = True

_RTTIBaseClassDescriptor_relative = bn.types.Type.structure(
    members=[
        # Image relative offset of TypeDescriptor
        (bv.parse_type_string("int")[0], 'pTypeDescriptor'),
        (bv.parse_type_string("unsigned int")[0], 'numContainedBases'),
        (_PMD_qualified, 'where'),
        (bv.parse_type_string("unsigned int")[0], 'attributes'),
        # Image relative offset  _RTTIClassHierarchyDescriptor
        (bv.parse_type_string("int")[0], 'pClassDescriptor'),
    ],
    type=bn.StructureVariant.StructStructureType
)

bv.define_user_type('_RTTIBaseClassDescriptor_relative', _RTTIBaseClassDescriptor_relative)

#################################
# _RTTI_RELATIVE_TYPEINFO = False

# Forward declaration of _RTTIClassHierarchyDescriptor
bv.define_user_type('_RTTIClassHierarchyDescriptor', bv.parse_type_string('void*')[0])

_RTTIBaseClassDescriptor_non_relative = bn.types.Type.structure(
    members=[
        (bv.parse_type_string("TypeDescriptor*")[0], 'pTypeDescriptor'),
        (bv.parse_type_string("unsigned int")[0], 'numContainedBases'),
        (_PMD_qualified, 'where'),
        (bv.parse_type_string("unsigned int")[0], 'attributes'),
        (bv.parse_type_string("_RTTIClassHierarchyDescriptor*")[0], 'pClassDescriptor'),
    ],
    type=bn.StructureVariant.StructStructureType
)

bv.define_user_type('_RTTIBaseClassDescriptor_non_relative', _RTTIBaseClassDescriptor_non_relative)

################################
# _RTTI_RELATIVE_TYPEINFO = True

_RTTICompleteObjectLocator_relative = bn.types.Type.structure(
    members=[
        (bv.parse_type_string("unsigned int")[0], 'signature'),
        (bv.parse_type_string("unsigned int")[0], 'offset'),
        (bv.parse_type_string("unsigned int")[0], 'cdOffset'),
        # Image relative offset of TypeDescriptor
        (bv.parse_type_string("int")[0], 'pTypeDescriptor'),
        # Image relative offset of _RTTIClassHierarchyDescriptor
        (bv.parse_type_string("int")[0], 'pClassDescriptor'),
        # Image relative offset of this object
        (bv.parse_type_string("int")[0], 'pSelf'),
    ],
    type=bn.StructureVariant.StructStructureType
)

bv.define_user_type('_RTTICompleteObjectLocator_relative', _RTTICompleteObjectLocator_relative)

################################
# _RTTI_RELATIVE_TYPEINFO = False

# Forward declaration of _RTTICompleteObjectLocator
bv.define_user_type('_RTTICompleteObjectLocator', bv.parse_type_string('void*')[0])

# Forward declaration of _RTTIClassHierarchyDescriptor
bv.define_user_type('_RTTIClassHierarchyDescriptor', bv.parse_type_string('void*')[0])

_RTTICompleteObjectLocator_non_relative = bn.types.Type.structure(
    members=[
        (bv.parse_type_string("unsigned int")[0], 'signature'),
        (bv.parse_type_string("unsigned int")[0], 'offset'),
        (bv.parse_type_string("unsigned int")[0], 'cdOffset'),
        (bv.parse_type_string("TypeDescriptor*")[0], 'pTypeDescriptor'),
        (bv.parse_type_string("_RTTIClassHierarchyDescriptor*")[0], 'pClassDescriptor'),
        (bv.parse_type_string("_RTTICompleteObjectLocator*")[0], 'pSelf'),
    ],
    type=bn.StructureVariant.StructStructureType
)

bv.define_user_type('_RTTICompleteObjectLocator_non_relative', _RTTICompleteObjectLocator_non_relative)



