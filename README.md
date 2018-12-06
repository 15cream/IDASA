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

