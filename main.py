import idc
import idaapi
import idautils

from find_method_invoke import MethodInvoke
from binaryData import Binary
from oc_object import IVar

r = MethodInvoke(receiver='DOUAccountInputView', sel='passwordField', data=Binary().get_data())
r.analyze()


ivars = IVar(Binary().get_data(), ivar_type='UITextField')


