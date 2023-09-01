# liferay 反序列化rce 分析-CVE 2020 7961

## 漏洞概述

Liferay Portal 7.2.1 CE GA2 之前的版本存在反序列化漏洞，允许攻击者通过 JSON web services 执行任意代码。

当访问 /api/jsonws/* 时就可以调用 json web services

相关的处理类是 `com.liferay.portal.jsonwebservice.JSONWebServiceServlet`。

## api调用流程分析

### 动调环境搭建

参看之前的文章吧，值得注意的是要本地源码和远程源码要一致，最好从虚机里面拷贝出来。我这里是把整个tomcat都添加为库了。

当向 /api/jsonws/* 发起请求时，会触发 JSONWebServicesServlet 的 service 方法，这里以 /api/jsonws/falg 为例进行分析。



