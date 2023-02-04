# 《深入理解WEB漏洞之SSRF漏洞》

本项目用来收集整理SSRF漏洞的相关内容，包括SSRF的利用方法工具或思路等。也包括SSRF漏洞的挖掘技巧及案例等，站在漏洞利用和漏洞赏金的角度可以更好的理解SSRF！深入理解SSRF，发起悄无声息的渗透！作者：[0e0w](https://github.com/0e0w)

本项目创建于2022年3月3日，最近的一次更新时间为2023年1月29日。本项目会持续更新，直到海枯石烂！

- [01-SSRF漏洞资源]()
- [02-SSRF漏洞基础]()
- [03-SSRF漏洞工具]()
- [04-SSRF渗透测试]()
- [05-SSRF代码审计]()
- [06-SSRF漏洞赏金]()

## 01-SSRF漏洞资源

- https://github.com/topics/ssrf
- https://github.com/search?q=ssrf
- https://github.com/topics/server-side-request-forgery

一、SSRF书籍文章
- [ ] [SSRF安全指北](https://security.tencent.com/index.php/blog/msg/179)@腾讯蓝军 silence

二、SSRF培训演讲

三、SSRF其他资源
- https://kathan19.gitbook.io/howtohunt/ssrf/ssrf
- https://tttang.com/archive/1648
- https://www.freebuf.com/articles/web/258449.html
- https://www.freebuf.com/articles/web/265646.html
- https://github.com/jdonsec/AllThingsSSRF
- https://github.com/cujanovic/SSRF-Testing
- https://github.com/github/securitylab/issues/430

## 02-SSRF漏洞基础

一、SSRF漏洞概念
- SSRF(Server-Side Request Forgery:服务器端请求伪造) 是一种由攻击者构造形成由服务端发起请求的安全漏洞。一般情况下，SSRF攻击的目标是从外网无法访问的内部系统。
- 因为它是由服务端发起的，所以它能够请求到与它相连而与外网隔离的内网。也就是说可以利用一个网络请求的服务，当作跳板进行攻击。
- SSRF 形成的原因往往是由于服务端提供了从其他服务器应用获取数据的功能且没有对目标地址做过滤与限制。如：从指定URL地址获取网页文本内容，加载指定地址的图片，下载等。利用的就是服务端的请求伪造。ssrf是利用存在缺陷的web应用作为代理攻击远程和本地的服务器。

二、SSRF漏洞原理

- SSRF的形成大多是由于服务端提供了从其他服务器应用获取数据的功能且没有对目标地址做过滤与限制。例如，黑客操作服务端从指定URL地址获取网页文本内容，加载指定地址的图片等，利用的是服务端的请求伪造。SSRF利用存在缺陷的Web应用作为代理攻击远程和本地的服务器。

三、SSRF漏洞分类
- 按照是否回显分：
  - **Basic SSRF**：在响应中返回结果。如传送一个网址，会返回这个网址的界面或对应的 html 代码。
  - **Blind SSRF**：响应中不返回服务器中的任何信息。
  - **Semi SSRF**：响应中不返回请求结果的所有详细信息，但是会暴露一些数据信息。
- 按照程序语言分类：
  - [PHP SSRF](https://github.com/FuckPHP/SSRF)
  - [Java SSRF](https://github.com/HackJava/SSRF)
  - [ASPX SSRF](https://github.com/Hackaspx/SSRF)
  - Python SSRF
  - Golang SSRF

四、SSRF Parameter

- share、wap、、url、link、src、source、target、u、3g、display、sourceURl、imageURL、domain......

五、SSRF Payloads

- https://github.com/tarunkant/Gopherus
- https://github.com/1ndianl33t/Gf-Patterns

六、SSRF Bypass

- 姿势一

  ```
  http://127.1:80
  ```

- 十进制
  ```
  http://2130706433/ = http://127.0.0.1
  http://3232235521/ = http://192.168.0.1
  http://3232235777/ = http://192.168.1.1
  http://2852039166/ = http://169.254.169.254
  ```
  
- DNS解析
  
  ```
  http://customer1.app.my.company.127.0.0.1.nip.io = 127.0.0.1
  ```
  
- 其他
  ```
  http://169。254。169。254/
  http://169｡254｡169｡254/
  http://⑯⑨。②⑤④。⑯⑨｡②⑤④/
  http://⓪ⓧⓐ⑨｡⓪ⓧⓕⓔ｡⓪ⓧⓐ⑨｡⓪ⓧⓕⓔ:80/
  http://⓪ⓧⓐ⑨ⓕⓔⓐ⑨ⓕⓔ:80/
  http://②⑧⑤②⓪③⑨①⑥⑥:80/
  http://④②⑤｡⑤①⓪｡④②⑤｡⑤①⓪:80/
  http://⓪②⑤①。⓪③⑦⑥。⓪②⑤①。⓪③⑦⑥:80/
  http://⓪⓪②⑤①｡⓪⓪⓪③⑦⑥｡⓪⓪⓪⓪②⑤①｡⓪⓪⓪⓪⓪③⑦⑥:80/
  http://[::①⑥⑨｡②⑤④｡⑯⑨｡②⑤④]:80/
  http://[::ⓕⓕⓕⓕ:①⑥⑨。②⑤④。⑯⑨。②⑤④]:80/
  http://⓪ⓧⓐ⑨。⓪③⑦⑥。④③⑤①⑧:80/
  http://⓪ⓧⓐ⑨｡⑯⑥⑧⑨⑥⑥②:80/
  http://⓪⓪②⑤①。⑯⑥⑧⑨⑥⑥②:80/
  http://⓪⓪②⑤①｡⓪ⓧⓕⓔ｡④③⑤①⑧:80/
  ```

七、SSRF漏洞危害

- 读取或更新内部资源，造成本地文件泄露
- 将含有漏洞防主机用作代理/跳板攻击内网主机，绕过防火墙等
- 可以对外网、服务器所在内网、本地进行端口扫描，获取一些服务的banner 信息
- 对内网 WEB 应用进行指纹识别，通过访问默认文件实现(如：readme文件)
- 攻击内外网的 web 应用，主要是使用 GET 参数就可以实现的攻击(如：Struts2，sqli)

八、SSRF漏洞修复

- 限制请求的端口只能为Web端口，只允许访问HTTP和HTTPS的请求。
- 限制不能访问内网的IP，以防止对内网进行攻击。
- 屏蔽返回的详细信息。

九、SSRF漏洞思考

## 03-SSRF漏洞工具

- 如何开发一个SSRF漏洞的渗透测试和代码审计工具？

一、SSRF主动扫描
- https://github.com/swisskyrepo/SSRFmap
- https://github.com/hupe1980/gopherfy
- https://github.com/ryandamour/ssrfuzz

二、SSRF被动扫描
- https://github.com/ethicalhackingplayground/ssrf-king

三、SSRF Automation

- https://github.com/ksharinarayanan/SSRFire

四、待整理工具
- https://github.com/teknogeek/ssrf-sheriff
- https://github.com/knassar702/scant3r
- https://github.com/R0X4R/ssrf-tool
- https://github.com/In3tinct/See-SURF
- https://github.com/bcoles/ssrf_proxy
- https://github.com/pikpikcu/XRCross
- https://github.com/0xAwali/Blind-SSRF
- https://github.com/arkadiyt/ssrf_filter
- https://github.com/dreadlocked/SSRFmap
- https://github.com/Th0h0/autossrf
- https://github.com/h4fan/ssrfscan
- https://github.com/junnlikestea/bulkssrf
- https://github.com/grayddq/SSRF_payload
- https://github.com/Kevin-sa/SSRF_ex
- https://github.com/akincibor/SSRFexploit
- https://github.com/medbsq/ssrf
- https://github.com/ackerleytng/ssrf-clojure-talk-gowherene
- https://github.com/redfr0g/ssrfuzzer
- https://github.com/0xWise64/SSRF_Listener
- https://github.com/alyrezo/ssrf-bypass
- https://github.com/grampae/ssrfscan
- https://github.com/paulveillard/cybersecurity-ssrf

## 04-SSRF渗透测试

一、SSRF漏洞挖掘
- 漏洞产生场景
  - 能够对外发起网络请求的地方，就可能存在 SSRF 漏洞
  - 从远程服务器请求资源（Upload from URL，Import & Export RSS Feed）
  - 数据库内置功能（Oracle、MongoDB、MSSQL、Postgres、CouchDB）
  - Webmail 收取其他邮箱邮件（POP3、IMAP、SMTP）
  - 文件处理、编码处理、属性信息处理（ffmpeg、ImageMagic、DOCX、PDF、XML）

二、SSRF漏洞实战

三、SSRF利用协议

- PHP
  - http、https、ftp、gopher、telnet、dict、file 、ldap、php、local_file、local-file
- Java

四、SSRF攻击内网
- 攻击内网应用
  - redis
  - FastCGI
  - mysql
  - postgresql
  - zabbix
  - pymemcache
  - smtp
- SSRF Canary
  - https://github.com/assetnote/blind-ssrf-chains
- 攻击内网案例
  - https://www.sqlsec.com/2021/05/ssrf.html

五、SSRF高级利用
- 利用file协议读取本地文件。
- 对外网、服务器所在内网及本地系统进行端口扫描。
- 攻击运行在内网或本地的应用程序。
- 对内网Web应用进行指纹识别，获取企业单位内部的资产信息。
- 通过HTTPGET的请求方式来攻击内外网的Web应用。
- DoS攻击（请求大文件，始终保持连接keep-alive always）。

## 05-SSRF代码审计

一、SSRF漏洞靶场
- https://github.com/incredibleindishell/SSRF_Vulnerable_Lab
- https://github.com/sqlsec/ssrf-vuls
- https://github.com/Captain-K-101/Ssrf-labs
- https://github.com/adeadfed/simple-ssrf-app
- https://github.com/m6a-UdS/ssrf-lab

二、SSRF审计原理

三、SSRF危险函数
- PHP
  - file_get_contents()
  - fsockopen()
  - curl_exec()
  - fopen()
  - fopen()
  - curl()
- Java
- ASPX
- Python
  - urllib、urllib2、requests
- Golang

四、SSRF漏洞分析
- Redis
- FFmpeg

## 06-SSRF漏洞赏金

- https://github.com/HoneTeam/SSRF
