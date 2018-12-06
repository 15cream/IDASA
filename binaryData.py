import re
import idc
import idaapi
import idautils


class Binary:

    def __init__(self):
        self.parser = {
            '__objc_classrefs': self.parse_classref,
            '__objc_superrefs': self.parse_classref,
            '__objc_selrefs': self.parse_selector,
            '__objc_ivar': self.parse_ivar,
            '__objc_classlist': self.parse_class,
            'UNDEF': self.parse_imports
        }
        self._classrefs = dict()  # name: classref_ea
        self._classlist = dict()  # name: classlist_ea
        self._selrefs = dict()
        self._ivars = dict()  # ivar_ea: type
        self._ivars_2 = dict()  # type:  ivar_ea list
        self._allocs = []
        self._imports = dict()  # symbol_name: ea
        self._functions = dict()  # function_name: startEA
        self.callG = dict()
        self.parse()

    def parse_classref(self, ea):
        classname = idc.Name(ea).replace('classRef_', '')
        self._classrefs[classname] = ea

    def parse_selector(self, ea):
        # m = re.search('[^"]+"(?P<sel>.+)"', idc.GetDisasm(ea))
        # if m:
        #     self._selrefs[m.group('sel')] = ea
        self._selrefs[idc.Name(ea).replace('selRef_', '').replace('_', ':')] = ea

    def parse_ivar(self, ea):
        cmt = idc.GetCommentEx(ea, True)
        if cmt:
            type = cmt.split()[0]
            self._ivars[ea] = type
            if type in self._ivars_2:
                self._ivars_2[type].append(ea)
            else:
                self._ivars_2[type] = [ea, ]
        else:
            print 'CANNOT GET CMT OF IVAR: '.format(hex(ea))

    def parse_class(self, ea):
        classname = idc.GetDisasm(ea).split('_OBJC_CLASS_$_')[-1]
        self._classlist[classname] = ea

    def parse_imports(self, ea):
        self._imports[idc.Name(ea)] = ea

    def parse(self):
        for f in idautils.Functions():
            func_name = idc.GetFunctionName(f)
            self._functions[func_name] = f

        for seg in idautils.Segments():
            segName = idc.SegName(seg)
            if segName in ['__objc_classrefs', '__objc_superrefs', '__objc_selrefs', '__objc_classlist', 'UNDEF']:  # step: 8
                for ea in range(idc.SegStart(seg), idc.SegEnd(seg), 8):
                    self.parser[segName](ea)
            elif segName in ['__objc_ivar']:  # step: 4
                for ea in range(idc.SegStart(seg), idc.SegEnd(seg), 4):
                    self.parser[segName](ea)

    def get_data(self):
        return {
            'classrefs': self._classrefs,
            'classlist': self._classlist,
            'selrefs': self._selrefs,
            'ivars': self._ivars,
            'ivars2': self._ivars_2,
            'allocs': self._allocs,
            'imports': self._imports,
            'functions': self._functions
        }

