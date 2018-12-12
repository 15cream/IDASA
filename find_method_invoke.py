import idc
import idaapi
import idautils
from oc_object import Object


class MethodInvoke:

    def __init__(self, receiver=None, sel=None, data=None):

        self.bin_data = data
        self.selector_str = sel
        self.receiver_str = receiver

        self.receiver_ea = None
        self.selector_ea = None

        self.receiver_ctx = dict()
        self.selector_ctx = dict()

        self.suspected_contexts = []

    def analyze(self):
        """

        :return:
        """
        self.find_sel_ctx()
        self.find_rec_ctx()
        self.suspected_contexts = list(set(self.selector_ctx.keys()) & set(self.receiver_ctx.keys()))

    def find_sel_ctx(self):
        if self.selector_str and not self.selector_ea:
            if self.selector_str in self.bin_data['selrefs']:
                self.selector_ea = self.bin_data['selrefs'][self.selector_str]
            else:
                print 'CANNOT FIND SELECTOR: ', self.selector_str
                return

        for xref in idautils.XrefsTo(self.selector_ea):
            if idc.SegName(xref.frm) == '__text':
                fi = idaapi.get_func(xref.frm).startEA
                if fi not in self.selector_ctx:
                    self.selector_ctx[fi] = set([xref.frm, ])
                else:
                    self.selector_ctx[fi].add(xref.frm)
            else:
                print 'XREF OF {} NOT IN TEXT SEGMENT: {}'.format(self.selector_str, hex(xref.frm))

    def find_rec_ctx(self):
        if self.receiver_str and not self.receiver_ea:
            if self.receiver_str in self.bin_data['classrefs']:
                self.receiver_ea = self.bin_data['classrefs'][self.receiver_str]
            else:
                print 'CANNOT FIND CLASS: ', self.receiver_str
                return
        receiver = Object(self.receiver_str, self.bin_data)
        if receiver:
            receiver.find_occurrences()
            self.receiver_ctx = receiver.get_union_occurs()

    def print_results(self):
        if self.selector_str:
            print 'SELECTOR {} OCCURS IN {} FUNCTIONS. '.format(self.selector_str, len(self.selector_ctx.keys()))
            for ctx in self.selector_ctx:
                print "{}: {}".format(hex(ctx), idc.GetFunctionName(ctx))

        if self.receiver_str:
            print 'RECEIVER OCCURS IN {} FUNCTIONS. '.format(self.receiver_str, len(self.receiver_ctx.keys()))
            for ctx in self.receiver_ctx:
                print "{}: {}".format(hex(ctx), idc.GetFunctionName(ctx))

        intersection_ctx = list(set(self.selector_ctx.keys()) & set(self.receiver_ctx.keys()))
        print '[{} {}] MAY OCCUR IN:'.format(self.receiver_str, self.selector_str)
        for ctx in intersection_ctx:
            print "{}: {}".format(hex(ctx), idc.GetFunctionName(ctx))

