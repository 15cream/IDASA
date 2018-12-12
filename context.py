import idautils
import idaapi
import idc
import copy
import re

from Utils import *


class PT:
    def __init__(self, ea, name):
        self.name = name
        self.ea = ea
        self.ctx_start = idaapi.get_func(ea).startEA
        self.ctx_end = idaapi.get_func(ea).endEA

        self.active_paths = [Path(ea, self)]
        self.dead_paths = []
        self.conf_paths = []

    def forward_analysis(self):
        """
        Start at self.ea, end at all pointers were killed.
        :return:
        """
        self.active_paths = [Path(self.ea, self)]
        while self.active_paths:
            add = []
            remove = []
            for p in self.active_paths:
                ea = p.route[-1]  # the latest step
                while ea != self.ctx_end:
                    ea = idc.NextHead(ea)
                    if idc.GetMnem(ea) in ['CBZ', 'B']:
                        for des in idautils.CodeRefsFrom(ea, 1):
                            if des in p.route:  # avoid loop
                                continue
                            successor_path = copy.deepcopy(p)
                            successor_path.route.append(ea)
                            successor_path.add_step(des)
                            if successor_path.active:
                                add.append(successor_path)
                            else:
                                self.dead_paths.append(successor_path)
                        remove.append(p)  # the path is not dead, just gave path to the successors.
                        break
                    else:
                        p.add_step(ea)
                        if p.active:
                            continue
                        else:
                            remove.append(p)
                            self.dead_paths.append(p)
                            break

            self.active_paths.extend(add)
            for p in remove:
                self.active_paths.remove(p)

    #
    def backward_analysis(self, ):
        """
        Start at self.ea, end at all vars were defined.
        :return:
        """
        vars = set()
        # for p in self.dead_paths:
        #     for i in p.invokes:
        #         vars.add(p.invokes[i]['receiver'])
        #         vars.add(p.invokes[i]['selector'])
        vars.remove('DEF')
        self.active_paths = [BPath(self.ea, self, list(vars))]
        while self.active_paths:
            add = []
            remove = []
            for p in self.active_paths:
                ea = p.route[-1]
                while ea != self.ctx_start - 4:  # context start
                    pre_ea = list(CodeRefsTo(ea, 1))
                    if len(pre_ea) == 1:
                        ea = pre_ea[0]
                        p.add_step(ea)
                        if p.active:
                            continue
                        else:
                            remove.append(p)
                            self.conf_paths.append(p)
                            break
                    elif len(pre_ea) == 2:
                        for ea in pre_ea:
                            if ea in p.route:
                                continue  # loop -> skip
                            predecessor_path = copy.deepcopy(p)
                            predecessor_path.add_step(ea)
                            if predecessor_path.active:
                                add.append(predecessor_path)
                            else:
                                self.conf_paths.append(predecessor_path)
                        remove.append(p)
                        break
                    else:
                        print 'CONTROL_FLOW EXCEPTION.'

            self.active_paths.extend(add)
            for p in remove:
                self.active_paths.remove(p)


class Path:

    def __init__(self, start, pt):
        self.pt = pt
        self.route = [start, ]
        self.defs = []
        self.alias = [pt.name]
        self.invokes = dict()
        self.active = True
        self.ret = False

    def add_step(self, ea):
        ins = idc.GetDisasm(ea)

        if '_objc_msgSend' in ins:
            """
            When path meets megSend call, the watched object could pass as a parameter.
            So we should backtrack the receiver and selector of this call to resolve which function we should dig into.
            """
            self.invokes[ea] = {}

        elif 'RET' in ins and 'X0' in self.alias:
            """
            When path meets ret instruction and is still alive, the watched object would ret.
            Then we should find the code slice calls this method and get the ret object.
            """
            self.ret = True

        else:
            # Definition analysis
            for a in self.alias:
                if a in ins:
                    df = DEF(ea, a, self)
                    if df.def_type:
                        self.defs.append(df)
                        break
        self.route.append(ea)

    def resolve_msgSend(self):
        for i in self.invokes:
            self.invokes[i] = {
                'receiver': self.backtrack(i, 'X0'),
                'selector': self.backtrack(i, 'X1')
            }

    def backtrack(self, ea, reg):
        """
        Path sensitive.
        We've recorded path route, so just step backward until the entry.
        If the value still cannot be determined, find route.
        :param ea:
        :param reg:
        :return:
        """
        step = self.route.index(ea)
        while step:
            ea = self.route[step]
            ins = idc.GetDisasm(ea)
            if reg in ins:
                df = DEF(ea, reg, self)
                if df.def_type == 'DEL':
                    reg = df.src  # change the watched object
            step -= 1
        return reg

    def kill(self):
        self.active = False

    def add_alias(self, a):
        if a not in self.alias:
            self.alias.append(a)

    def remove_alias(self, a):
        self.alias.remove(a)
        if len(self.alias) == 0:
            self.kill()

    def pprint(self):
        print '1. CODE:'
        for ins in self.route:
            print hex(ins), idc.GetDisasm(ins)
        print
        print '2. DEFS:'
        for d in self.defs:
            d.pprint()
        print
        print '3. PROPAGATE AS RET VALUE: {}'.format(self.ret)
        print '4. PROPAGATE AS PARAMETER: {}'.format(True if self.invokes else False)
        for i in self.invokes:
            print hex(i)


class BPath(Path):
    def __init__(self, start, pt, os):
        Path.__init__(self, start, pt)
        self.watched = dict()
        for o in os:
            self.watched[o] = {
                'alias': o,
                'def_ea': None,
                'value': None
            }

    def add_step(self, ea):
        ins = idc.GetDisasm(ea)
        unknown = dict()  # alias, ori_o
        for a in self.watched:
            if not self.watched[a]['value']:
                unknown[self.watched[a]['alias']] = a
        # When paths meets megSend call, be careful that x0 could be changed.
        # If watched objects are affected, regard it as undecidable problem.
        if '_objc_msgSend' in ins:
            if 'X0' in unknown:
                self.watched[unknown['X0']]['value'] = 'undecidable'
                self.watched[unknown['X0']]['def_ea'] = ea
        else:
            for a in unknown:
                if a in ins:
                    df = DEF(ea, a, self)
                    df.trace()
                    if df.def_type == 'DEL':
                        if df.src_type == 1:
                            self.watched[unknown[a]]['alias'] = df.src  # change the watched object
                        else:
                            self.watched[unknown[a]]['value'] = df.src
                            self.watched[unknown[a]]['def_ea'] = ea
                        break
        self.route.append(ea)
        self.check_status()

    def check_status(self):
        for o in self.watched:
            if not self.watched[o]['value']:
                self.active = True
                return
        self.active = False

    def pprint(self):
        for o in self.watched:
            print o, self.watched[o]


class DEF:
    def __init__(self, ea, var, path):
        self.ea = ea
        self.var = var
        self.path = path
        self.src = None
        self.des = None
        self.def_type = None
        self.analysis()

    def analysis(self):
        if idc.GetMnem(self.ea) in ['LDR', 'MOV', 'ADRP']:  # op, des, src
            if self.var in self.operand_at(0):  # des
                self.path.remove_alias(self.var)
                self.src = self.operand_at(1, ret_expr=True)
                self.des = self.var
                self.def_type = 'DEL'

            elif self.var in self.operand_at(1):  # src
                self.des = self.operand_at(0, ret_expr=True)
                self.path.add_alias(self.des)
                self.src = self.var
                self.def_type = 'ADD'

            else:
                self.def_type = False

    # deprecated
    def trace(self):
        if idc.GetMnem(self.ea) in ['LDR', 'MOV', 'ADRP']:  # op, des, src
            if self.var in self.operand_at(0):  # des
                self.src = self.operand_at(1, ret_expr=True)
                self.def_type = 'DEL'

    def operand_at(self, index, ret_expr=False):
        if ret_expr:
            return idc.GetOpnd(self.ea, index)
        ret = []
        operand = ret_operand(self.ea, index)
        if type(operand) == list:
            ret.extend(operand)
        else:
            ret.append(operand)
        return ret

    def pprint(self):
        print hex(self.ea), idc.GetDisasm(self.ea)
        print "{} -> {}, {}".format(self.src, self.des, self.def_type)


pt = PT(0x10060042c, 'X8')
pt.forward_analysis()
# for p in pt.dead_paths:
#     p.resolve_msgSend()
# pt.backward_analysis()






