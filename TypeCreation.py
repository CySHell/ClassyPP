"""
This module is responsible for defining the RTTI types defined in rttidata.h header:

    //
    //	_RTTIBaseClassDescriptor
    //
    typedef const struct	_s_RTTIBaseClassDescriptor	{
    #if _RTTI_RELATIVE_TYPEINFO
        int								pTypeDescriptor;	// Image relative offset of TypeDescriptor
    #else
        TypeDescriptor*					pTypeDescriptor;
    #endif
        unsigned long					numContainedBases;
        PMD								where;
        unsigned long					attributes;
    #if _RTTI_RELATIVE_TYPEINFO
        int								pClassDescriptor;	// Image relative offset of _RTTIClassHierarchyDescriptor
    #else
        _RTTIClassHierarchyDescriptor*	pClassDescriptor;
    #endif
        } _RTTIBaseClassDescriptor;


    typedef struct _PMD
    {
        int	mdisp;	// Offset of intended data within base
        int	pdisp;	// Displacement to virtual base pointer
        int	vdisp;	// Index within vbTable to offset of base
        } PMD;

    //
    //	_RTTIBaseClassArray
    //
    typedef const struct	_s_RTTIBaseClassArray	{
    #if _RTTI_RELATIVE_TYPEINFO
        int							arrayOfBaseClassDescriptors[];  // Image relative offset of _RTTIBaseClassDescriptor
    #else
        _RTTIBaseClassDescriptor*	arrayOfBaseClassDescriptors[];
    #endif
        } _RTTIBaseClassArray;

    //
    //	_RTTIClassHierarchyDescriptor
    //
    typedef const struct	_s_RTTIClassHierarchyDescriptor	{
        unsigned long			signature;
        unsigned long			attributes;
        unsigned long			numBaseClasses;
    #if _RTTI_RELATIVE_TYPEINFO
        int						pBaseClassArray;    // Image relative offset of _RTTIBaseClassArray
    #else
        _RTTIBaseClassArray*	pBaseClassArray;
    #endif
        } _RTTIClassHierarchyDescriptor;


    //
    //	_RTTICompleteObjectLocator
    //
    typedef const struct	_s_RTTICompleteObjectLocator	{
        unsigned long							signature;
        unsigned long							offset;
        unsigned long							cdOffset;
    #if _RTTI_RELATIVE_TYPEINFO
        int										pTypeDescriptor;	// Image relative offset of TypeDescriptor
        int										pClassDescriptor;	// Image relative offset of _RTTIClassHierarchyDescriptor
        int										pSelf;				// Image relative offset of this object
    #else
        TypeDescriptor*							pTypeDescriptor;
        _RTTIClassHierarchyDescriptor*			pClassDescriptor;
     #if VERSP_WIN64 && CC_IA64_SOFT25	// TRANSITION, VSO#515783
        const _s_RTTICompleteObjectLocator* 	pSelf;
     #endif VERSP_WIN64 && CC_IA64_SOFT25
    #endif
        } _RTTICompleteObjectLocator;

    //
    //	TypeDescriptor
    //
    typedef struct _TypeDescriptor
    {
        const void * pVFTable;	// Field overloaded by RTTI
        void *	spare;			// reserved, possible for RTTI
        char			name[];			// The decorated name of the type; 0 terminated.
    } TypeDescriptor;



"""

import binaryninja as bn
from .Common import Utils
import logging

log = logging.getLogger(__name__)


def Define_TypeDescriptor(bv: bn.binaryview, extra_bytes: int = 0) -> bool:
    """
    :param bv:
    :param extra_bytes: This is the size of the char[] in the 'name' parameter of the descriptor.
    :return:
    """
    try:
        TypeDescriptor = bn.types.Type.structure(
            members=[
                # Field overloaded by RTTI
                (bv.parse_type_string("void*")[0], 'pVFTable'),
                # reserved, possible for RTTI
                (bv.parse_type_string("void*")[0], 'spare'),
                # The decorated name of the type; 0 terminated.
                (bv.parse_type_string(f"char[{extra_bytes}]")[0], 'name'),
            ],
            type=bn.StructureVariant.StructStructureType
        )

        bv.define_user_type('_TypeDescriptor', TypeDescriptor)
        bv.define_user_type('TypeDescriptor', bv.parse_type_string("_TypeDescriptor")[0])
        return True

    except Exception as e:
        Utils.LogToFile(f"Define_TypeDescriptor: Failed to define TypeDescriptor - {e}")
        return False


def Define_RTTIClassHierarchyDescriptor(bv: bn.binaryview):
    try:
        if Define_TypeDescriptor(bv):
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
            bv.define_user_type("RTTIClassHierarchyDescriptor",
                                bv.parse_type_string("_RTTIClassHierarchyDescriptor_relative")[0])
            return True
    except Exception as e:
        Utils.LogToFile(f"Define_RTTIClassHierarchyDescriptor: Failed to define ClassHierarchyDescriptor - {e}")
    return False


def Define_RTTIBaseClassDescriptor(bv: bn.binaryview) -> bool:
    try:
        if Define_TypeDescriptor(bv) and Define_RTTIClassHierarchyDescriptor(bv):
            ################################
            # _RTTI_RELATIVE_TYPEINFO = True

            _RTTIBaseClassDescriptor_relative = bn.types.Type.structure(
                members=[
                    # Image relative offset of TypeDescriptor
                    (bv.parse_type_string("int")[0], 'pTypeDescriptor'),
                    (bv.parse_type_string("unsigned int")[0], 'numContainedBases'),
                    (bv.parse_type_string("int")[0], 'where.mdisp'),
                    (bv.parse_type_string("int")[0], 'where.pdisp'),
                    (bv.parse_type_string("int")[0], 'where.vdisp'),
                    (bv.parse_type_string("unsigned int")[0], 'attributes'),
                    # Image relative offset  _RTTIClassHierarchyDescriptor
                    (bv.parse_type_string("int")[0], 'pClassDescriptor'),
                ],
                type=bn.StructureVariant.StructStructureType
            )

            bv.define_user_type('_RTTIBaseClassDescriptor_relative', _RTTIBaseClassDescriptor_relative)
            bv.define_user_type('RTTIBaseClassDescriptor',
                                bv.parse_type_string('_RTTIBaseClassDescriptor_relative')[0])
        return True

    except Exception as e:
        Utils.LogToFile(f"Define_RTTIBaseClassDescriptor: Failed to define BaseClassDescriptor - {e}")
        return False


def Define_RTTICompleteObjectLocator(bv: bn.binaryview):
    try:
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
        bv.define_user_type('RTTICompleteObjectLocator',
                            bv.parse_type_string('_RTTICompleteObjectLocator_relative')[0])

        return True

    except Exception as e:
        Utils.LogToFile(f"Define_RTTICompleteObjectLocator: Failed to define RTTICompleteObjectLocator - {e}")
        return False


def IsDefined(bv: bn.binaryview) -> bool:
    """
    Check if the needed types already defined in the bv.
    :return: True if NOT defined, else False.
    """
    return bv.get_type_by_name("RTTIBaseClassDescriptor") and \
           bv.get_type_by_name("RTTICompleteObjectLocator")


def CreateTypes(bv: bn.binaryview) -> bool:
    if IsDefined(bv):
        Utils.LogToFile(f'CreateTypes: Types already defined in this BinaryView.')
        return True

    else:
        if Define_RTTIBaseClassDescriptor(bv) and Define_RTTICompleteObjectLocator(bv):
            return True
        else:
            Utils.LogToFile(f'CreateTypes: Error defining types.')
            return False
