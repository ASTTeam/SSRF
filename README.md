# 深入理解SSRF漏洞

本项目用来收集整理SSRF漏洞的相关内容，包括SSRF的利用方法工具或思路等。作者：[ASTTeam团队](https://github.com/ASTTeam/SSRF)

本项目创建于2020年12月1日，最近的一次更新时间为2022年2月22日。本项目会持续更新，直到海枯石烂！

- [01-SSRF漏洞资源]()
- [02-SSRF漏洞基础]()
- [03-SSRF漏洞工具]()
- [04-SSRF渗透测试]()
- [05-SSRF代码审计]()
- [06-SSRF漏洞赏金]()
- [07-SSRF漏洞修复]()

## 01-SSRF漏洞资源

- https://github.com/topics/ssrf

一、SSRF书籍资源

二、SSRF培训演讲

三、SSRF其他资源
- https://github.com/jdonsec/AllThingsSSRF
- https://github.com/cujanovic/SSRF-Testing
- https://kathan19.gitbook.io/howtohunt/ssrf/ssrf

## 02-SSRF漏洞基础

一、SSRF漏洞概念

- SSRF(Server-Side Request Forgery:服务器端请求伪造) 是一种由攻击者构造形成由服务端发起请求的一个安全漏洞。
- 一般情况下，SSRF攻击的目标是从外网无法访问的内部系统。（因为它是由服务端发起的，所以它能够请求到与它相连而与外网隔离的内网。也就是说可以利用一个网络请求的服务，当作跳板进行攻击）
- SSRF 形成的原因往往是由于服务端提供了从其他服务器应用获取数据的功能且没有对目标地址做过滤与限制。如：从指定URL地址获取网页文本内容，加载指定地址的图片，下载等。利用的就是服务端的请求伪造。ssrf是利用存在缺陷的web应用作为代理攻击远程和本地的服务器。

二、SSRF漏洞原理

三、SSRF漏洞分类

四、SSRF漏洞危害

五、SSRF漏洞思考

## 03-SSRF漏洞工具

一、SSRF主动扫描

- https://github.com/swisskyrepo/SSRFmap

二、SSRF被动扫描

- https://github.com/ethicalhackingplayground/ssrf-king

三、待整理

- https://github.com/teknogeek/ssrf-sheriff
- https://github.com/knassar702/scant3r
- https://github.com/R0X4R/ssrf-tool
- https://github.com/tarunkant/Gopherus
- https://github.com/ksharinarayanan/SSRFire

## 04-SSRF渗透测试

一、SSRF漏洞挖掘

二、SSRF漏洞实战

三、SSRF高级利用

## 05-SSRF代码审计

一、SSRF漏洞靶场

- https://github.com/incredibleindishell/SSRF_Vulnerable_Lab

二、SSRF审计原理

三、SSRF危险函数

四、SSRF漏洞分析

- Redis
- FFmpeg

## 06-SSRF漏洞赏金

- https://github.com/HoneTeam/SSRF

## 07-SSRF漏洞修复

## 08-SSRF参考资源