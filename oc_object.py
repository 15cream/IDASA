import re

import idc
import idaapi
import idautils


class Object:

    def __init__(self, c, data):

        self.class_name = c
        self.bin_data = data

        self.class_ref = None
        self.occurrences = {'x0': dict(),
                            'ivar': dict(),
                            'ret_or_arg': dict()}

        if self.class_name in self.bin_data['classrefs']:
            self.class_ref = self.bin_data['classrefs'][self.class_name]
        else:
            print 'CANNOT FIND CLASS: ', self.class_name
            return None

    def find_occurrences(self):
        self.as_x0()
        self.as_ivar()
        self.as_ret_or_arg()

    def as_ret_or_arg(self):
        """
        as ret value
        :return:
        """
        for xref in idautils.XrefsTo(self.class_ref):
            if idc.SegName(xref.frm) == '__text':
                if idc.GetMnem(xref.frm) == 'ADRP':
                    pass
                elif 'LDR' in idc.GetMnem(xref.frm):
                    # ctx = CTX(xref.frm, PT(idc.GetOpnd(xref.frm, 0), xref.frm))
                    # if ctx.find_call(rec='x8', sel='alloc'):
                    self.add_occurrences(xref.frm, 'ret_or_arg')

    def as_ivar(self):
        """
        When object was referenced as ivar, whether get or set, load or store, the object must exist in this context.
        :return:
        """
        if self.class_name in self.bin_data['ivars2']:
            for ivar in self.bin_data['ivars2'][self.class_name]:
                for xref in idautils.XrefsTo(ivar):
                    if idc.SegName(xref.frm) == '__text':
                        if idc.GetMnem(xref.frm) == 'ADRP':
                            pass
                        elif 'LDR' in idc.GetMnem(xref.frm):
                            # PT(idc.GetOpnd(xref.frm, 0), xref.frm)
                            # ctx = CTX(xref.frm, PT(idc.GetOpnd(xref.frm, 0), xref.frm))
                            self.add_occurrences(xref.frm, 'ivar')

    def as_x0(self):
        """
        The receiver(X0) of instance methods is always the object.
        :return:
        """
        if idc.SegName(idc.Qword(self.class_ref)) == 'UNDEF':  # IMPORTED CLASS, has no method implementations.
            return
        class_data = idc.Qword(self.class_ref)
        class_data_ro = idc.Qword(class_data + 0x20)
        meths = idc.Qword(class_data_ro + 0x20)
        entrysize = idc.Word(meths)
        count = idc.Word(meths)
        for meth in range(meths + 8, meths + 8 + entrysize * count, entrysize):
            name = idc.Name(idc.Qword(meth)).replace('sel_', '')
            type = idc.GetDisasm(idc.Qword(meth + 8))
            imp = idc.Qword(meth + 0x10)
            self.add_occurrences(imp, 'x0')

    def add_occurrences(self, ea, otype):
        f = idaapi.get_func(ea)
        if f:
            fi = f.startEA
            if fi in self.occurrences[otype]:
                self.occurrences[otype][fi].add(ea)
            else:
                self.occurrences[otype][fi] = set([ea, ])

    def get_union_occurs(self):
        ret = dict()
        for otype in self.occurrences:
            for f in self.occurrences[otype]:
                if f not in ret:
                    ret[f] = self.occurrences[otype][f]
                else:
                    ret[f].update(self.occurrences[otype][f])
        return ret


class IVar:

    def __init__(self, bin_data, ea=None, ivar_type=None):
        self.ea = ea
        self.type = ivar_type
        self.bin_data = bin_data
        self.name = None
        self.instance = None

    def search(self):
        if self.ea:
            self.type = self.bin_data['ivars'][self.ea]
            self.name = idc.Name(self.ea).split('._')[-1]
            self.instance = idc.Name(self.ea).idc.replace('_OBJC_IVAR_$_', '').split('.')[0]
            return self
        elif self.type:
            ret = []
            if self.type in self.bin_data['ivars2']:
                for ivar in self.bin_data['ivars2'][self.type]:
                    iv = IVar(self.bin_data, ea=ivar).search()
                    ret.append(iv)
            return ret

    def find_usage(self):
        functions = set()
        for xref in idautils.XrefsTo(self.ea):
            if idc.SegName(xref.frm) == '__text':
                if idc.GetMnem(xref.frm) == 'ADRP':
                    continue
                elif 'LDR' in idc.GetMnem(xref.frm):
                    functions.add(idaapi.get_func(xref.frm))
                    m = re.search('(?P<def_type>[-+]?)\[(?P<receiver>\S+?) (?P<selector>[\w:]+)\]', idc.GetFunctionName(xref.frm))
                    if m:
                        r = MethodInvoke(receiver=m.group('receiver'), sel=m.group('selector'), data=self.bin_data)
                        r.analyze()





