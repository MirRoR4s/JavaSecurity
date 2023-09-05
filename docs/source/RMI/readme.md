# RMI

## 前言

苦 RMI 久矣，我缺少一篇好的文章全面、细致地为我讲述 RMI，而且我觉得 RMI 这个机制真的很有用。我太爱远程调用某些资源了！

书读百遍，其意自现。纸上得来终觉浅，绝知此事要躬行。所以我的方法论是先看一些 RMI 文章，最后进行实操。

**推荐阅读（按序）**

1. [JAVA RMI 反序列化知识详解 (seebug.org)](https://paper.seebug.org/1194/)

这篇文章从全局的角度说了下RMI，但并不深入，对初学者来说很友好。看完大概知道如何实现一个基本的rmi应用以及如何利用yso官方给的exp进行rmi攻击。

2. https://www.oreilly.com/library/view/learning-java/1565927184/ch11s04.html

来自learning java这本书，里面对rmi进行了详细的描述，不过要注意的是并没有从安全的角度进行分析，而是用文字和一些基本代码阐述rmi的原理等等。

3. [Java 中 RMI、JNDI、LDAP、JRMP、JMX、JMS那些事儿（上） (seebug.org)](https://paper.seebug.org/1091/#java-rmi_3)

rmi的攻击手法汇总。

记录一下关于阅读上述文章的复现

首先是jdk6u29的下载，下完之后记得改系统环境变量里面的path，这一点很重要。详情可以这篇[文章](https://blog.csdn.net/mnorst/article/details/6941194)。

~~之后是 payload 的编译问题，第一个复现我编译了四个类，具体那四个忘记了，反之测一下就明白。当然至关重要的是不要在 payload 同目录下运行 java，这样会提示找不到主类，具体我也不明白为什么，总之需要去到包名那个起始目录。~~

真的难受，无论怎么也找不到 main方法，后面在 vscode 里面编译居然成功了，vscode 永远的神！

**复现结果**

运行客户端、服务端之后成功弹出计算器。



## RMI攻击复现

### 环境搭建

1. 创建两个 idea 项目（不在同目录下），分别对应客户端和服务器
2. 运行服务器
3. 在客户端编写 payload 发送到服务器，这里要利用 maven 引入 CC 包依赖，记得重新构建一下
4. 复现失败，猜测 jdk 版本有问题，原作者没给出他的版本，我真的会谢...

- jdk 版本是 8u65

```xml
    <dependency>
        <groupId>commons-collections</groupId>
        <artifactId>commons-collections</artifactId>
        <version>3.2.1</version>
    </dependency>
```



## 推荐阅读

1. [Java远程方法调用(RMI) - 知乎 (zhihu.com)](https://zhuanlan.zhihu.com/p/135360489)

虽然啰嗦了一些，但是是对于官方rmi描述的汉化翻译，还是值得一看的。

2. [Java的RMI介绍及使用方法详解 | w3cschool笔记](https://www.w3cschool.cn/article/30445887.html)

这篇我看完了，感觉也挺不错，说的很简单。

3. 最后是 RMI 漏洞成因的[源码分析](https://drun1baby.top/2022/07/19/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E4%B9%8BRMI%E4%B8%93%E9%A2%9801-RMI%E5%9F%BA%E7%A1%80/)

4. RMI的攻击方式[看看这个](https://github.com/Maskhe/javasec/blob/master/7.%E6%94%BB%E5%87%BBrmi%E7%9A%84%E6%96%B9%E5%BC%8F.md)
