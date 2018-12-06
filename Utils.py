import re
import idc
import idaapi
import idautils


def find_type_of_meth(imp):
    for xref in idautils.XrefsTo(imp):
        if idc.SegName(xref.frm) == '__objc_const':
            if idc.Qword(xref.frm + 16) == imp:
                type = idc.GetDisasm(idc.Qword(xref.frm + 8))
                m = re.search('DCB (?P<type>.+),0', type)
                if m:
                    return m.group('type')


def find_return_type(imp):
    type = find_type_of_meth(imp)
    if type:
        m = re.search('"(?P<ret>[@\w]).*', type)
        if m:
            return m.group('ret')
    else:
        print 'UNRESOLVED RET TYPE: ', type


def parse_objc_methtype_data(ea):
    """
    Read methtype string from objc_methtype segment. Also applies to the __objc_methname, __objc_classname segments.
    :param ea: ea at objc_methtype segment
    :return: methtype string.
    """
    length = idc.ItemSize(ea)
    return idaapi.get_many_bytes(ea, length)


def parse_cfstring(ea):
    """
    Parse cfstring.
    :param ea: address at __cfstring segment.
    :return: String.
    """
    data = idc.Qword(ea + 0x10)
    length = idc.Qword(ea + 0x18)
    return idaapi.get_many_bytes(data, length)


def slice_analysis_needed(ea):
    """
    Return the complexity of the function where ea lies on.
    :param ea:
    :return:
    """
    f = idaapi.get_func(ea)
    flowchart = idaapi.FlowChart(f)
    blocks = list(flowchart)
    instructions = (f.endEA - f.startEA) / 4
    return blocks, instructions


# funcs = Functions()
# for f in funcs:
#     name = Name(f)
#     end = GetFunctionAttr(f, FUNCATTR_END)
#     locals = GetFunctionAttr(f, FUNCATTR_FRSIZE)
#     frame = GetFrame(f)
#     if frame is None:
#         continue


# for struct in idautils.Structs():
#     index = struct[0]
#     sid = struct[1]
#     name = struct[2]
#     size = idc.GetStrucSize(sid)

# idc.NextNotTail(ea)