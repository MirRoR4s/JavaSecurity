# 动态代理

## 一. 前言

**学习目标：**能够编写创建动态代理类的代码。

**前置知识：了解 Java 反射机制。**

Java 的动态代理在实践中有着广泛的使用场景，比如 Spring AOP、Java 注解的获取、日志、用户鉴权等。

>强烈推荐看看这篇[文章](https://juejin.cn/post/6844903744954433544)


## 二. 代理模式

### 2.1 什么是代理模式

无论学习静态代理还是动态代理，我们都要先了解一下代理模式。

**什么是代理模式？**

答：给某个对象提供一种代理以控制这个对象的访问。在某些情况下，一个对象不适合或者不能直接引用另一个对象，而代理对象可以在客户端和被代理对象（目标对象）之间起到中介的作用。

直接看定义可能有些难以理解，我们就以生活中具体的实例来说明一下。我们都去过超市购买过物品，超市从厂商那里购买货物之后出售给我们，我们通常并不知道货物从哪里经过多少流程才到超市。在这个过程中，等于是厂商委托超市出售货物，对我们来说厂商（被代理对象）是不可见的。而超市（代理对象）作为厂商的 “代理者” 来与我们进行交互。同时，超市还可以根据具体的销售情况进行折扣等处理，来丰富被代理对象的功能。

**代理的好处？**

通过代理模式，我们可以做到两点：

1. 隐藏被代理类（委托类）的具体实现。
2. 实现客户与被代理类（委托类）的解耦，在不改变被代理类代码的情况下添加一些额外的功能（日志、权限）等。

### 2.2 代理模式的角色

代理模式角色分为 3 种：

1. `Subject（抽象主题角色）`：定义代理类和真实主题的公共对外方法，也是代理类代理真实主题的方法。
2. `RealSubject（真实主题角色）`：真正实现业务逻辑的类。比如实现了广告、出售等方法的厂家（Vendor）
3. `Proxy（代理主题角色）`：用来代理和封装真实主题。比如，同样实现了广告、出售等方法的超市（Shop）

代理模式的结构比较简单，其核心是代理类，为了让客户端能够一致性地对待真实对象和代理对象，在代理模式中引入了抽象层。

![](https://i.imgur.com/3lIud5K.png)



### 2.2 静态代理实例

静态代理是指`代理类`在程序运行前就已经存在，这种情况下的代理类通常都是我们在 Java 代码中定义的。

下面我们就以具体的实例来演示一下静态代理。

首先定义一组接口 Sell（抽象主题角色），用来提供广告和销售等功能。然后提供 Vendor 类（厂商-真实主题角色）和 Shop 类（超市-代代理主题角色），它们分别实现了 Sell 接口。

Sell 接口定义如下：

```java=
package com.kuang.Proxy;

public interface Sell {
    void sell();
    void ad();

}

```

Vendor 类定义如下：

```java=
package com.kuang.Proxy;

public class Vendor implements Sell{
    @Override
    public void sell(){
        System.out.println("shop sell goods");

    }
    @Override
    public void ad(){
        System.out.println("Shop advert goods");

    }

}
```

Shop 类定义如下：

```java=
package com.kuang.Proxy;

public class Shop implements Sell {

    private final Sell sell; // 被代理的对象

    public Shop(Sell sell){
        this.sell = sell;

    }
    public void sell(){
        System.out.println("代理类Shop，处理sell");
        sell.sell();

    }
    public void ad(){
        System.out.println("代理类Shop，处理ad");
        sell.ad();
    }

}

```

其中代理类 Shop 通过聚合的方式持有了被代理类 Vendor 类的引用，并在对应的方法中调用 Vendor 对应的方法。在 Shop 类中我们可以新增一些额外的处理，比如筛选购买用户、记录日志等操作。

下面看看在客户端中如何使用代理类。

```java=
package com.kuang.Proxy;

public class StaticProxy {
    public static void main(String[] args){
        Vendor vendor = new Vendor();
        // 虽然 Shop 的构造函数接收的是 Sell，但是实际传入的是 Vendor 
        Sell sell = new Shop(vendor);
        sell.ad();
        sell.sell();


        
    }
}

```

#### 2.2.1 静态代理的优点

- 可以使得我们的真实主题角色更加纯粹，不再去关注一些公共的事情。
- 公共业务由代理类-代理主题角色来完成，实现了业务的分工。
- 公共业务发生扩展时变得更加集中和方便。

#### 2.2.2 静态代理的缺点

静态代理实现简单且不入侵源代码，但当场景复杂时，静态代理会有以下缺点：

1. 当需要代理多个类的时候，由于代理对象要实现与被代理对象（目标对象）一致的接口，有两种方式：
   - 只维护一个代理类，由这个代理类统一代理多个类，但这样就需要该代理类实现多个接口，从而导致该代理类过于庞大。
   - 新建多个代理类，每个被代理类（目标对象）对应一个代理类，但是这样会产生过多的代理类
2. 当接口需要增加、删除、修改方法的时候，被代理类与代理类都要同时修改，`不易维护`。

如果我们想要静态代理的优点而又不想要其缺点，那么就需要使用动态代理！

### 2.3 动态代理

动态代理指的是在程序运行时动态地创建代理对象，而非事先定义好。这种情况下，代理类并不是在 Java 代码中定义的，而是在运行时根据 Java 代码中的指示动态生成的。相比于静态代理，动态代理的优势在于可以很方便的对代理类的函数进行统一的处理，而不用修改每个代理类的函数。

**如何实现动态代理？**

**动态代理的实现方式有很多种，这里仅记录基于JDK的原生动态代理实现。**JDK 动态代理主要涉及两个类：

`java.lang.reflect.Proxy` 和 `java.lang.reflect.InvocationHandler`。

#### InvocationHandler

**InvocationHandler是什么？**

答：`InvocationHandler` 是一个接口，通常和代理对象相关联的调用处理器会实现该接口。

以下是这个接口的定义：
```java
package java.lang.reflect;

public interface InvocationHandler {

    public Object invoke(Object proxy, Method method, Object[] args)
        throws Throwable;
}

```
**[Oracle 文档](https://docs.oracle.com/en/java/javase/16/docs/api/java.base/java/lang/reflect/InvocationHandler.html)中对于 InvocationHandler 的描述如下：**

每个代理类对象都有一个相关联的**调用处理器（invocation handler）**。当我们在一个代理类对象上调用某方法时，会将该方法调用进行编码并将其传送到和该代理类对象相关联的调用处理器的 **invoke()** 方法上。

如下是`invoke()`方法的参数描述：

- `proxy` - 调用该方法的代理类实例
- `method` - 与在代理实例上调用的接口方法对应的 Method 实例。 Method 对象的声明类将是声明该方法的接口，该接口可能是代理类通过其继承该方法的代理接口的超接口。
- `args` - 包含在代理实例的方法调用中传递的参数值的对象数组，如果接口方法不带参数，则为 null。原始类型的参数被包装在适当的原始包装器类的实例中，例如 java.lang.Integer 或 java.lang.Boolean。
- 返回值 - 从代理实例上的方法调用返回的值。如果接口方法声明的返回类型是原始类型，则该方法返回的值必须是对应原始包装类的实例；否则，它必须是可分配给声明的返回类型的类型。如果此方法返回的值为 null 且接口方法的返回类型为原始类型，则代理实例上的方法调用将抛出 NullPointerException。如果此方法返回的值与上述接口方法声明的返回类型不兼容，则代理实例上的方法调用将抛出 ClassCastException。

>note：关于为什么会自动调用 invoke 函数，我目前还不知道。

#### Proxy

根据 [Oracle 文档](https://docs.oracle.com/en/java/javase/16/docs/api/java.base/java/lang/reflect/Proxy.html) Proxy 类用于获取指定被代理对象所关联的调用处理器。`Proxy` 提供了创建动态代理类及其实例的静态方法，它也是由该静态方法所创建的所有动态代理类的超类。

`Proxy#newProxyInstance()` 方法会返回指定接口的代理类实例，该实例将会方法调用分派给指定的调用处理程序 invocation handler。


```java
public static Object newProxyInstance(ClassLoader loader,
                                          Class<?>[] interfaces,
                                          InvocationHandler h)
        throws IllegalArgumentException
```


参数：

- `loader` 定义类的加载器

- `interfaces` 要实现的被代理类的接口列表

- `h` 分派方法调用的调用处理程序 invocation handler

  返回值：具有指定调用处理程序的代理类实例，该代理类由指定的类加载器定义并实现了指定的接口。

#### 动态代理的代码实现

要编写动态代理的代码，需要抓牢两个要点

- 我们代理的是接口，而不是单个用户。
- 代理类是动态生成的，而非静态定死。

首先是我们的接口类

`UserService.java`

```java
package src.JdkProxy.DynamicProxy;  
  
  
public interface UserService {  
 public void add();  
 public void delete();  
 public void update();  
 public void query();  
}
```

接着，我们需要用（被代理对象）实体类去实现这个抽象类

`UserServiceImpl.java`

```java
package src.JdkProxy.DynamicProxy;  
  
public class UserServiceImpl implements UserService{  
    @Override  
 public void add() {  
        System.out.println("增加了一个用户");  
 }  
  
    @Override  
 public void delete() {  
        System.out.println("删除了一个用户");  
 }  
  
    @Override  
 public void update() {  
        System.out.println("更新了一个用户");  
 }  
  
    @Override  
 public void query() {  
        System.out.println("查询了一个用户");  
 }  
}
```

接着，是动态代理的实现类，其实就是实现 InvocationHandler 接口

```java
package src.JdkProxy.DynamicProxy;  
  
import java.lang.reflect.InvocationHandler;  
import java.lang.reflect.Method;  
import java.lang.reflect.Proxy;  
  
public class UserProxyInvocationHandler implements InvocationHandler {  
  
    // 被代理的接口 ，这里是传入抽象主题角色，
 private UserService userService;  
  
 public void setUserService(UserService userService) {  
        this.userService = userService;  
 }  
  
    // 动态生成 proxy 类（代理类）实例  
 public Object getProxy(){  
        Object obj = Proxy.newProxyInstance(this.getClass().getClassLoader(), userService.getClass().getInterfaces(), this);  
 return obj;  
 }  
  
    // 处理代理类实例，并返回结果  
 @Override  
 public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {  
        log(method);  
 Object obj = method.invoke(userService, args);  
 return obj;  
 }  
  
    //业务自定义需求  
 public void log(Method method){  
        System.out.println("[Info] " + method.getName() + "方法被调用");  
 }  
}
```

- 最后编写我们的 Client，也就是启动器

`Client.java`

```java=
package src.JdkProxy.DynamicProxy;  
  
import src.JdkProxy.DynamicProxy.UserServiceImpl;  
  
public class Client {  
    public static void main(String[] args) {  
        // 真实角色-被代理对象 
 UserServiceImpl userServiceImpl = new UserServiceImpl();  
        
 // 代理角色，不存在  
 UserProxyInvocationHandler userProxyInvocationHandler = new UserProxyInvocationHandler();  
 userProxyInvocationHandler.setUserService((UserService) userServiceImpl); // 设置要代理的对象  
  
 // 动态生成代理类  
 UserService proxy = (UserService) userProxyInvocationHandler.getProxy();  
  
 proxy.add();  
 proxy.delete();  
 proxy.update();  
 proxy.query();  
 }  
}
```

![](https://i.imgur.com/xTqhoVh.png)

### 2.5 在反序列化中动态代理的作用（待更新）

## 三. 参考链接

https://drun1baby.github.io/2022/06/01/Java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E5%9F%BA%E7%A1%80%E7%AF%87-04-JDK%E5%8A%A8%E6%80%81%E4%BB%A3%E7%90%86/#toc-heading-5

https://www.liaoxuefeng.com/wiki/1252599548343744/1264804593397984

https://juejin.cn/post/6844904098580398088#heading-3
