## IDASA

基于IDA的一些静态分析脚本。  


### find_method_invoke.py
给出一个方法调用的receiver和selector（可缺失，但针对Objective-C的方法调用），查找该方法可能被调用的上下文。  
```python
from find_method_invoke import MethodInvoke
from binaryData import Binary

r = MethodInvoke(receiver='BITAuthenticationViewController', sel='setPassword:', data=Binary().get_data())
r.analyze()
```

主要思路是：
1. 解析selector出现的上下文（通常就是function）。  
2. 解析receiver出现的上下文。此处将receiver视作一个对象（类方法另作讨论），因此需要对该对象进行存在性分析。
3. 求上下文的交集。（太过粗略，应该进行切片分析才是。）
关键性代码如下：

```python 
receiver = Object(self.receiver_str, self.bin_data)
if receiver:
    receiver.find_occurrences()
    self.receiver_ctx = receiver.occurrences
```


### from oc_object import Object
class Object
用于查找对象的存在性。  
#### as_x0
实例方法的receiver为目标对象.

#### as_ivar
作为property。（ivar的直接引用，如果是存在于访问器方法，还应该追访问器的调用）

#### as_ret_or_arg
作为返回值或作为传入参数（非x0）。


### context.py

粗略的指针分析。  
指针分析这里主要有三个类，指针PT，路径Path， 定值语句DEF。  

#### from context import PT
```python
    def __init__(self, ea, name):
        self.name = name　　# 变量名
        self.ea = ea　　# 该变量存在的地址
        self.active_paths = [Path(ea, self)]# 初始化一条以当前地址为起点的路径
        self.dead_paths = []　# 分析结束后该变量存在的所有路径
        self.conf_paths = []
        self.ctx_start = idaapi.get_func(ea).startEA
        self.ctx_end = idaapi.get_func(ea).endEA

```

##### forward_analysis()
前向分析，直到当前方法结束或对象（当前函数体内）的所有引用被释放。

##### backward_analysis()
反向分析。

#### from context import Path
```python
    def __init__(self, start, pt):
        self.pt = pt  # 关注的对象
        self.active = True　# 路径是否存活
        self.route = [start, ] # 路径，即走过的每条指令地址
        self.defs = []　# 该路径上的pt相关的定值
        self.alias = [pt.name]　# 指针别名,实时的，根据该路径的步进改变
        self.invokes = dict()　# 该路径上的所有调用
        self.ret = False　#　该对象是否作为返回值
```

##### add_step(self, ea)
对路径上走的一步进行分析：
1. 当为方法调用时，记录在self.invokes里；
2. 当为返回指令时，且所观察对象为x0，则self.ret为True；
3. 当为普通语句时，定值分析；也只有定值分析能改变self.alias以及self.active。

#### backtrack(self, ea, reg)
是对已经成型（分析完毕）的路径进行反向分析。例如，想知道ea处reg的定值在哪儿。

#### from context import DEF
```python
    def __init__(self, ea, var, path):
        self.ea = ea　　# 定值语句所在地址
        self.var = var　# 定值变量
        self.path = path　　# 所在路径
        self.src = None
        self.des = None
        self.def_type = None　# 'DEL', 'ADD', False
        self.analysis()
```
注意这里有一个代理。在进行定值分析时，会对当前path的self.active属性进行修改。杀死路径是在定值分析里，而非路径的处理逻辑，路径只需要看自己是否还活着，活着就走好了。

#### from context import BPath




现在的检测脚本有问题。