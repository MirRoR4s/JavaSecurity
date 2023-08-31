# RMI

## 源码分析

从源码入手分析 RMI 为什么会产生反序列化漏洞。在实例化远程对象那一行上面打断点进行动态调试。

- 这里注意让 ida 跳过类的加载，可在settings中进行设置

**问：UnicastRemoteObject类是用来做什么的？**

**答：该类用于创建和导出远程对象**



**问：exportObject() 方法是用来做什么的？**

**答：exportObject() 方法用于导出远程对象并使其能够在特定的端口接收远程调用**



**问：UnicastServerRef 类是用来做什么的？**

**答：该类用于构造一个 Unicast 服务端的远程引用，并导出到指定的端口**

注：Unicast是计网中的一个概念，用于描述网络中一对一的通信模式。在这种通信模式中，一个发送者向一个接收者发送数据，就像是电话上的一对一通话。在 RMI 中，Unicast 是一种实现远程对象之间通信的方式。每个远程对象都有一个唯一的标识符，称为远程引用（Remote Reference）。









## RMI攻击手法

## 推荐阅读

1. [Java远程方法调用(RMI) - 知乎 (zhihu.com)](https://zhuanlan.zhihu.com/p/135360489)

虽然啰嗦了一些，但是是对于官方rmi描述的汉化翻译，还是值得一看的。

2. [Java的RMI介绍及使用方法详解 | w3cschool笔记](https://www.w3cschool.cn/article/30445887.html)

这篇我看完了，感觉也挺不错，说的很简单。

3. 最后是 RMI 漏洞成因的[源码分析](https://drun1baby.top/2022/07/19/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E4%B9%8BRMI%E4%B8%93%E9%A2%9801-RMI%E5%9F%BA%E7%A1%80/)



