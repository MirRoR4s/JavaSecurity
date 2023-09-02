###### tags: `JAVA安全`


# JAVA安全


## JAVA反序列化

### 前言

使用IDEA构建项目时，为了方便，建议新建一个名为 CCChain 的项目，然后在该项目下创建各个子模块，分别使用独立的 pom.xml。

### 推荐阅读

1. p 神 java 安全漫谈

通俗易懂，后面才发现的宝藏。不得不说，p 神在文笔这一块是安全圈顶尖的！

2. [ysoserial](https://github.com/frohoff/ysoserial/tree/master/src/main/java/ysoserial/payloads)

看看 yso 是如何编写 payload 的，学习人家的写法。

3. https://paper.seebug.org/1242/

这篇文章是对 CC 链子的一个梳理，逻辑清晰，特别是对 writeObject() 也有涉及，提到了恶意数据序列化时的一些细节。

4. 芜风师傅

我的启蒙，但是现在想来对于新手来说，未免说的太细了，学起来有些不知所措的感觉。

