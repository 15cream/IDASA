import idc
import idaapi
import idautils

from find_method_invoke import MethodInvoke
from binaryData import Binary

r = MethodInvoke(receiver='BITAuthenticationViewController', sel='setPassword:', data=Binary().get_data())
r.analyze()





