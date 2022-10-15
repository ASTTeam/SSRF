# 《深入理解WEB漏洞之SSRF漏洞》

本项目用来收集整理SSRF漏洞的相关内容，包括SSRF的利用方法工具或思路等。作者：[0e0w](https://github.com/0e0w)

本项目创建于2022年3月3日，最近的一次更新时间为2022年7月10日。本项目会持续更新，直到海枯石烂！

- [01-SSRF漏洞资源]()
- [02-SSRF漏洞基础]()
- [03-SSRF漏洞工具]()
- [04-SSRF渗透测试]()
- [05-SSRF代码审计]()
- [06-SSRF漏洞赏金]()
- [07-SSRF漏洞修复]()
- [08-SSRF参考资源]()

## 01-SSRF漏洞资源

- https://github.com/topics/ssrf

一、SSRF书籍资源

二、SSRF培训演讲

三、SSRF其他资源
- https://github.com/jdonsec/AllThingsSSRF
- https://github.com/cujanovic/SSRF-Testing
- https://kathan19.gitbook.io/howtohunt/ssrf/ssrf
- https://tttang.com/archive/1648

## 02-SSRF漏洞基础

一、SSRF漏洞概念

- SSRF(Server-Side Request Forgery:服务器端请求伪造) 是一种由攻击者构造形成由服务端发起请求的一个安全漏洞。
- 一般情况下，SSRF攻击的目标是从外网无法访问的内部系统。（因为它是由服务端发起的，所以它能够请求到与它相连而与外网隔离的内网。也就是说可以利用一个网络请求的服务，当作跳板进行攻击）
- SSRF 形成的原因往往是由于服务端提供了从其他服务器应用获取数据的功能且没有对目标地址做过滤与限制。如：从指定URL地址获取网页文本内容，加载指定地址的图片，下载等。利用的就是服务端的请求伪造。ssrf是利用存在缺陷的web应用作为代理攻击远程和本地的服务器。

二、SSRF漏洞原理

三、SSRF漏洞分类

- PHP SSRF
- Java SSR

四、SSRF漏洞危害

五、SSRF漏洞思考

## 03-SSRF漏洞工具

- 如何开发一个SSRF的渗透测试和代码审计工具？

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
- https://github.com/In3tinct/See-SURF

## 04-SSRF渗透测试

一、SSRF漏洞挖掘

二、SSRF漏洞实战

三、SSRF高级利用

## 05-SSRF代码审计

一、SSRF漏洞靶场
- https://github.com/incredibleindishell/SSRF_Vulnerable_Lab
- https://github.com/sqlsec/ssrf-vuls

二、SSRF审计原理

三、SSRF危险函数

四、SSRF漏洞分析

- Redis
- FFmpeg

## 06-SSRF漏洞赏金

一、挖掘技巧

二、公开报告
- [SSRF报告](https://github.com/reddelexc/hackerone-reports/blob/master/tops_by_bug_type/TOPSSRF.md)
- [ ] [My Expense Report resulted in a Server-Side Request Forgery (SSRF) on Lyft](https://hackerone.com/reports/885975) to Lyft - 587 upvotes, $0
- [ ] [SSRF in Exchange leads to ROOT access in all instances](https://hackerone.com/reports/341876) to Shopify - 507 upvotes, $25000
- [ ] [Server Side Request Forgery (SSRF) at app.hellosign.com leads to AWS private keys disclosure](https://hackerone.com/reports/923132) to Dropbox - 357 upvotes, $4913
- [ ] [Server-Side Request Forgery using Javascript allows to exfill data from Google Metadata](https://hackerone.com/reports/530974) to Snapchat - 344 upvotes, $4000
- [ ] [SSRF & LFR via on city-mobil.ru](https://hackerone.com/reports/748123) to Mail.ru - 338 upvotes, $6000
- [ ] [SSRF on project import via the remote_attachment_url on a Note](https://hackerone.com/reports/826361) to GitLab - 337 upvotes, $10000
- [ ] [Server Side Request Forgery mitigation bypass](https://hackerone.com/reports/632101) to GitLab - 330 upvotes, $3500
- [ ] [SSRF on fleet.city-mobil.ru leads to local file read](https://hackerone.com/reports/748069) to Mail.ru - 272 upvotes, $6000
- [ ] [SSRF leaking internal google cloud data through upload function [SSH Keys, etc..\]](https://hackerone.com/reports/549882) to Vimeo - 244 upvotes, $5000
- [ ] [SSRF & LFR on city-mobil.ru](https://hackerone.com/reports/748128) to Mail.ru - 237 upvotes, $6000
- [ ] [Unsafe charts embedding implementation leads to cross-account stored XSS and SSRF](https://hackerone.com/reports/708589) to New Relic - 222 upvotes, $2500
- [ ] [Full Response SSRF via Google Drive](https://hackerone.com/reports/1406938) to Dropbox - 220 upvotes, $17576
- [ ] [Full read SSRF in www.evernote.com that can leak aws metadata and local file inclusion](https://hackerone.com/reports/1189367) to Evernote - 217 upvotes, $5000
- [ ] [Unauthenticated blind SSRF in OAuth Jira authorization controller](https://hackerone.com/reports/398799) to GitLab - 216 upvotes, $4000
- [ ] [Unauthenticated SSRF in jira.tochka.com leading to RCE in confluence.bank24.int](https://hackerone.com/reports/713900) to QIWI - 213 upvotes, $1000
- [ ] [Full Read SSRF on Gitlab's Internal Grafana](https://hackerone.com/reports/878779) to GitLab - 200 upvotes, $12000
- [ ] [SSRF in webhooks leads to AWS private keys disclosure](https://hackerone.com/reports/508459) to Omise - 190 upvotes, $700
- [ ] [Stored XSS & SSRF in Lark Docs](https://hackerone.com/reports/892049) to Lark Technologies - 168 upvotes, $3000
- [ ] [SSRF on duckduckgo.com/iu/](https://hackerone.com/reports/398641) to DuckDuckGo - 155 upvotes, $0
- [ ] [Server Side Request Forgery](https://hackerone.com/reports/644238) to Lark Technologies - 153 upvotes, $1500
- [ ] [External SSRF and Local File Read via video upload due to vulnerable FFmpeg HLS processing](https://hackerone.com/reports/1062888) to TikTok - 137 upvotes, $2727
- [ ] [SSRF in clients.city-mobil.ru](https://hackerone.com/reports/712103) to Mail.ru - 132 upvotes, $1500
- [ ] [SSRF chained to hit internal host leading to another SSRF which allows to read internal images.](https://hackerone.com/reports/826097) to PlayStation - 131 upvotes, $1000
- [ ] [Blind SSRF on errors.hackerone.net due to Sentry misconfiguration](https://hackerone.com/reports/374737) to HackerOne - 130 upvotes, $3500
- [ ] [SSRF in filtering on relap.io](https://hackerone.com/reports/739962) to Mail.ru - 129 upvotes, $1700
- [ ] [SSRF on music.line.me through getXML.php](https://hackerone.com/reports/746024) to LINE - 128 upvotes, $4500
- [ ] [SSRF In Get Video Contents](https://hackerone.com/reports/643622) to Semrush - 114 upvotes, $500
- [ ] [XXE Injection through SVG image upload leads to SSRF](https://hackerone.com/reports/897244) to Zivver - 110 upvotes, $0
- [ ] [Full read SSRF via Lark Docs `import as docs` feature ](https://hackerone.com/reports/1409727)to Lark Technologies - 95 upvotes, $5000
- [ ] [[city-mobil.ru\] SSRF & limited LFR on /taxiserv/photoeditor/save endpoint via base64 POST parameter](https://hackerone.com/reports/853068) to Mail.ru - 94 upvotes, $6000
- [ ] [SSRF on image renderer](https://hackerone.com/reports/811136) to PlayStation - 93 upvotes, $1000
- [ ] [Blind SSRF in horizon-heat](https://hackerone.com/reports/893856) to Mail.ru - 91 upvotes, $2500
- [ ] [SSRF in api.slack.com, using slash commands and bypassing the protections.](https://hackerone.com/reports/381129) to Slack - 78 upvotes, $500
- [ ] [SSRF and LFI in site-audit tool](https://hackerone.com/reports/794099) to Semrush - 77 upvotes, $2000
- [ ] [SSRF на https://qiwi.com с помощью "Prerender HAR Capturer"](https://hackerone.com/reports/1153862) to QIWI - 76 upvotes, $1500
- [ ] [Blind SSRF in emblem editor (2)](https://hackerone.com/reports/265050) to Rockstar Games - 72 upvotes, $1500
- [ ] [SSRF in CI after first run](https://hackerone.com/reports/369451) to GitLab - 69 upvotes, $3000
- [ ] [LFI and SSRF via XXE in emblem editor](https://hackerone.com/reports/347139) to Rockstar Games - 68 upvotes, $1500
- [ ] [Sending Emails from DNSDumpster - Server-Side Request Forgery to Internal SMTP Access](https://hackerone.com/reports/392859) to Hacker Target - 68 upvotes, $0
- [ ] [SVG Server Side Request Forgery (SSRF)](https://hackerone.com/reports/223203) to Shopify - 65 upvotes, $500
- [ ] [Blind SSRF on debug.nordvpn.com due to misconfigured sentry instance](https://hackerone.com/reports/756149) to Nord Security - 63 upvotes, $100
- [ ] [GitLab::UrlBlocker validation bypass leading to full Server Side Request Forgery](https://hackerone.com/reports/541169) to GitLab - 62 upvotes, $5000
- [ ] [[SSRF\] Server-Side Request Forgery at https://sea-web.gold.razer.com/dev/simulator via notify_url Parameter](https://hackerone.com/reports/777664) to Razer - 60 upvotes, $2000
- [ ] [SSRF and local file disclosure by video upload on https://www.redtube.com/upload](https://hackerone.com/reports/570537) to Redtube - 60 upvotes, $500
- [ ] [Blind SSRF on https://labs.data.gov/dashboard/Campaign/json_status/ Endpoint](https://hackerone.com/reports/895696) to GSA Bounty - 58 upvotes, $300
- [ ] [SSRF with information disclosure](https://hackerone.com/reports/810401) to Lark Technologies - 57 upvotes, $550
- [ ] [SSRF and local file disclosure in https://wordpress.com/media/videos/ via FFmpeg HLS processing](https://hackerone.com/reports/237381) to Automattic - 56 upvotes, $800
- [ ] [Blind SSRF in magnum upgrade_params](https://hackerone.com/reports/907819) to Mail.ru - 54 upvotes, $2500
- [ ] [[tanks.mail.ru\] SSRF + Кража cookie ](https://hackerone.com/reports/1166943)to Mail.ru - 54 upvotes, $750
- [ ] [SSRF and local file disclosure by video upload on https://www.tube8.com/](https://hackerone.com/reports/574133) to Tube8 - 53 upvotes, $500
- [ ] [Get-based SSRF limited to HTTP protocol on https://resizer.line-apps.com/form](https://hackerone.com/reports/707014) to LINE - 50 upvotes, $1350
- [ ] [FogBugz import attachment full SSRF requiring vulnerability in *.fogbugz.com](https://hackerone.com/reports/1092230) to GitLab - 49 upvotes, $6000
- [ ] [SSRF - Unchecked Snippet IDs for distributed files](https://hackerone.com/reports/997926) to Open-Xchange - 49 upvotes, $1500
- [ ] [BLIND SSRF ON http://jsgames.mail.ru via avaOp parameter ](https://hackerone.com/reports/1043801)to Mail.ru - 49 upvotes, $1200
- [ ] [SSRF in VCARD photo upload functionality](https://hackerone.com/reports/296045) to Open-Xchange - 49 upvotes, $850
- [ ] [SSRF in hatchful.shopify.com](https://hackerone.com/reports/409701) to Shopify - 49 upvotes, $500
- [ ] [Blind SSRF at https://chaturbate.com/notifications/update_push/](https://hackerone.com/reports/411865) to Chaturbate - 48 upvotes, $1250
- [ ] [SMB SSRF in emblem editor exposes taketwo domain credentials, may lead to RCE](https://hackerone.com/reports/288353) to Rockstar Games - 46 upvotes, $1500
- [ ] [Internal SSRF bypass using slash commands at api.slack.com](https://hackerone.com/reports/356765) to Slack - 46 upvotes, $500
- [ ] [SSRF in https://imgur.com/vidgif/url](https://hackerone.com/reports/115748) to Imgur - 45 upvotes, $2000
- [ ] [SSRF By adding a custom integration on console.helium.com](https://hackerone.com/reports/1055823) to Helium - 45 upvotes, $500
- [ ] [Bypass of the SSRF protection in Event Subscriptions parameter.](https://hackerone.com/reports/386292) to Slack - 44 upvotes, $500
- [ ] [SSRF](https://hackerone.com/reports/522203) to Mail.ru - 44 upvotes, $500
- [ ] [SSRF - Blacklist bypass for mail account addition](https://hackerone.com/reports/303378) to Open-Xchange - 43 upvotes, $500
- [ ] [SSRF in the application's image export functionality](https://hackerone.com/reports/816848) to Visma Public - 42 upvotes, $250
- [ ] [SSRF - Image Sources in HTML Snippets - 727234 bypass](https://hackerone.com/reports/737163) to Open-Xchange - 41 upvotes, $400
- [ ] [SSRF - Office Documents - Image URL](https://hackerone.com/reports/738015) to Open-Xchange - 37 upvotes, $450
- [ ] [SSRF in alerts.newrelic.com exposes entire internal network](https://hackerone.com/reports/198690) to New Relic - 37 upvotes, $0
- [ ] [Server-Side Request Forgery (SSRF) in Ghost CMS ](https://hackerone.com/reports/793704)to Node.js third-party modules - 37 upvotes, $0
- [ ] [Blind SSRF на calendar.mail.ru при импорте календаря](https://hackerone.com/reports/758948) to Mail.ru - 36 upvotes, $5000
- [ ] [SSRF - URL Attachments - 725307 bypass](https://hackerone.com/reports/737161) to Open-Xchange - 36 upvotes, $400
- [ ] [SSRF and local file disclosure by video upload on http://www.youporn.com/](https://hackerone.com/reports/574134) to YouPorn - 35 upvotes, $500
- [ ] [MCS Graphite SSRF: internal network access](https://hackerone.com/reports/818109) to Mail.ru - 34 upvotes, $2500
- [ ] [Grafana SSRF in grafana.instamart.ru](https://hackerone.com/reports/895551) to Mail.ru - 34 upvotes, $1200
- [ ] [Injection of `http.\.*` git config settings leading to SSRF](https://hackerone.com/reports/855276) to GitLab - 33 upvotes, $3000
- [ ] [SSRF at jira.plazius.ru - CVE-2019-8451](https://hackerone.com/reports/900618) to Mail.ru - 33 upvotes, $1200
- [ ] [Blind SSRF on [relap.io\]](https://hackerone.com/reports/785384) to Mail.ru - 33 upvotes, $1000
- [ ] [SSRF - RSS feed, blacklist bypass (301 re-direct)](https://hackerone.com/reports/299135) to Open-Xchange - 33 upvotes, $850
- [ ] [SSRF - RSS feed, blacklist bypass (IP Formatting)](https://hackerone.com/reports/299130) to Open-Xchange - 32 upvotes, $850
- [ ] [SSRF in https://www.zomato.com████ allows reading local files and website source code](https://hackerone.com/reports/271224) to Zomato - 31 upvotes, $1000
- [ ] [SSRF in Search.gov via ?url= parameter](https://hackerone.com/reports/514224) to GSA Bounty - 30 upvotes, $150
- [ ] [SSRF & Blind XSS in Gravatar email ](https://hackerone.com/reports/1100096)to Automattic - 29 upvotes, $750
- [ ] [SSRF allows reading AWS EC2 metadata using "readapi" variable in Streamlabs Cloudbot](https://hackerone.com/reports/1108418) to Logitech - 28 upvotes, $200
- [ ] [Blind SSRF in "Integrations" by abusing a bug in Ruby's native resolver.](https://hackerone.com/reports/287245) to HackerOne - 28 upvotes, $0
- [ ] [Open redirect bypass & SSRF Security Vulnerability](https://hackerone.com/reports/771465) to Smule - 28 upvotes, $0
- [ ] [SSRF at ideas.starbucks.com](https://hackerone.com/reports/500468) to Starbucks - 27 upvotes, $1000
- [ ] [SSRF in upload IMG through URL](https://hackerone.com/reports/228377) to Discourse - 26 upvotes, $64
- [ ] [SSRF vulnerability on ██████████ leaks internal IP and various sensitive information](https://hackerone.com/reports/310036) to U.S. Dept Of Defense - 26 upvotes, $0
- [ ] [SSRF in notifications.server configuration](https://hackerone.com/reports/850114) to Phabricator - 25 upvotes, $300
- [ ] [Blind SSRF [ Sentry Misconfiguraton \]](https://hackerone.com/reports/587012) to Mail.ru - 25 upvotes, $250
- [ ] [GitLab's GitHub integration is vulnerable to SSRF vulnerability](https://hackerone.com/reports/446593) to GitLab - 24 upvotes, $2000
- [ ] [Bypass for blind SSRF #281950 and #287496](https://hackerone.com/reports/642675) to Infogram - 24 upvotes, $0
- [ ] [[Plazius\] SSRF через некорректно сконфигурированный Fiddler 46.148.201.206:10121](https://hackerone.com/reports/1125389) to Mail.ru - 23 upvotes, $1200
- [ ] [SSRF in imgur video GIF conversion](https://hackerone.com/reports/247680) to Imgur - 23 upvotes, $1000
- [ ] [Non-production Open Database In Combination With XXE Leads To SSRF](https://hackerone.com/reports/742808) to Evernote - 23 upvotes, $0
- [ ] [SSRF ](https://hackerone.com/reports/253558)to Cloudflare Vulnerability Disclosure - 22 upvotes, $0
- [ ] [[Uppy\] Internal Server side request forgery (bypass of #786956)](https://hackerone.com/reports/891270) to Node.js third-party modules - 22 upvotes, $0
- [ ] [ssrf xspa [https://prt.mail.ru/\] 2](https://hackerone.com/reports/216533) to Mail.ru - 21 upvotes, $150
- [ ] [SSRF vulnerability on proxy.duckduckgo.com (access to metadata server on AWS)](https://hackerone.com/reports/395521) to DuckDuckGo - 21 upvotes, $0
- [ ] [SSRF & unrestricted file upload on https://my.stripo.email/](https://hackerone.com/reports/771382) to Stripo Inc - 21 upvotes, $0
- [ ] [SSRF for kube-apiserver cloudprovider scene](https://hackerone.com/reports/941178) to Kubernetes - 20 upvotes, $1000
- [ ] [SSRF in /appsuite/api/autoconfig ](https://hackerone.com/reports/293847)to Open-Xchange - 20 upvotes, $850
- [ ] [Wordpress 4.7 - CSRF -> HTTP SSRF any private ip:port and basic-auth](https://hackerone.com/reports/187520) to WordPress - 20 upvotes, $750
- [ ] [SSRF on jira.mariadb.org](https://hackerone.com/reports/397402) to MariaDB - 20 upvotes, $0
- [ ] [SSRF on █████████ Allowing internal server data access](https://hackerone.com/reports/326040) to U.S. Dept Of Defense - 20 upvotes, $0
- [ ] [Server Side Request Forgery in Uppy npm module](https://hackerone.com/reports/786956) to Node.js third-party modules - 20 upvotes, $0
- [ ] [Half-Blind SSRF found in kube/cloud-controller-manager can be upgraded to complete SSRF (fully crafted HTTP requests) in vendor managed k8s service.](https://hackerone.com/reports/776017) to Kubernetes - 19 upvotes, $5000
- [ ] [Infrastructure - Photon - SSRF](https://hackerone.com/reports/204513) to WordPress - 19 upvotes, $350
- [ ] [Blind SSRF in ads.tiktok.com](https://hackerone.com/reports/1006599) to TikTok - 19 upvotes, $150
- [ ] [SSRF at iris.lystit.com](https://hackerone.com/reports/206894) to Lyst - 19 upvotes, $100
- [ ] [Server side request forgery on image upload for lists](https://hackerone.com/reports/158016) to Instacart - 19 upvotes, $50
- [ ] [Blind HTTP GET SSRF via website icon fetch (bypass of pull#812)](https://hackerone.com/reports/925527) to Bitwarden - 19 upvotes, $0
- [ ] [Server side request forgery (SSRF) on nextcloud implementation.](https://hackerone.com/reports/145524) to Nextcloud - 18 upvotes, $0
- [ ] [Additional bypass allows SSRF for internal netblocks](https://hackerone.com/reports/288950) to HackerOne - 18 upvotes, $0
- [ ] [CRLF injection & SSRF in git:// protocal lead to arbitrary code execution](https://hackerone.com/reports/441090) to GitLab - 18 upvotes, $0
- [ ] [SSRF to AWS file read](https://hackerone.com/reports/978823) to Topcoder - 18 upvotes, $0
- [ ] [SSRF On [ allods.mail.ru \]](https://hackerone.com/reports/602498) to Mail.ru - 17 upvotes, $750
- [ ] [SSRF protection bypass](https://hackerone.com/reports/736867) to Nextcloud - 17 upvotes, $100
- [ ] [SSRF thru File Replace](https://hackerone.com/reports/243865) to Concrete CMS - 17 upvotes, $0
- [ ] [SSRF external interaction](https://hackerone.com/reports/1023920) to Stripo Inc - 17 upvotes, $0
- [ ] [[la.mail.ru\] - SSRF + кража cookie](https://hackerone.com/reports/1166977) to Mail.ru - 16 upvotes, $750
- [ ] [Blind SSRF on sentry.dev-my.com due to Sentry misconfiguration](https://hackerone.com/reports/686363) to Mail.ru - 16 upvotes, $500
- [ ] [SSRF in https://cards-dev.twitter.com/validator](https://hackerone.com/reports/178184) to Twitter - 16 upvotes, $280
- [ ] [SSRF vulnerability in gitlab.com via project import.](https://hackerone.com/reports/215105) to GitLab - 16 upvotes, $0
- [ ] [SSRF in img.lemlist.com that leads to Localhost Port Scanning](https://hackerone.com/reports/783392) to lemlist - 16 upvotes, $0
- [ ] [Bypassing HTML filter in "Packing Slip Template" Lead to SSRF to Internal Kubernetes Endpoints](https://hackerone.com/reports/1115139) to Shopify - 15 upvotes, $500
- [ ] [SSRF allows access to internal services like Ganglia](https://hackerone.com/reports/151086) to Dropbox - 14 upvotes, $729
- [ ] [Potential SSRF in sales.mail.ru](https://hackerone.com/reports/97395) to Mail.ru - 14 upvotes, $300
- [ ] [SSRF via webhook](https://hackerone.com/reports/243277) to Mixmax - 14 upvotes, $0
- [ ] [SSRF in proxy.duckduckgo.com via the image_host parameter](https://hackerone.com/reports/358119) to DuckDuckGo - 14 upvotes, $0
- [ ] [Blind SSRF in Ticketing Integrations Jira webhooks leading to internal network enumeration and blind HTTP requests](https://hackerone.com/reports/344032) to New Relic - 14 upvotes, $0
- [ ] [SSRF на https://target.my.com/](https://hackerone.com/reports/200224) to Mail.ru - 13 upvotes, $800
- [ ] [SSRF issue in "URL target" allows [REDACTED\]](https://hackerone.com/reports/58897) to Zendesk - 13 upvotes, $100
- [ ] [Blind SSRF on synthetics.newrelic.com](https://hackerone.com/reports/141304) to New Relic - 13 upvotes, $0
- [ ] [Internal Ports Scanning via Blind SSRF](https://hackerone.com/reports/263169) to New Relic - 13 upvotes, $0
- [ ] [Golang : Improvements to Golang SSRF query](https://hackerone.com/reports/956296) to GitHub Security Lab - 12 upvotes, $1800
- [ ] [SSRF protection bypass in /appsuite/api/oxodocumentfilter addfile action](https://hackerone.com/reports/863553) to Open-Xchange - 12 upvotes, $550
- [ ] [SSRF In plantuml (on plantuml.pre.gitlab.com)](https://hackerone.com/reports/689245) to GitLab - 12 upvotes, $100
- [ ] [SSRF on testing endpoint](https://hackerone.com/reports/128685) to APITest.IO - 12 upvotes, $0
- [ ] [SSRF and local file read in video to gif converter](https://hackerone.com/reports/115857) to Imgur - 11 upvotes, $800
- [ ] [[et.mail.ru\] ssrf 2](https://hackerone.com/reports/258237) to Mail.ru - 11 upvotes, $150
- [ ] [Bypass of the SSRF protection (Slack commands, Phabricator integration)](https://hackerone.com/reports/61312) to Slack - 11 upvotes, $100
- [ ] [Blind SSRF on velodrome.canary.k8s.io](https://hackerone.com/reports/808169) to Kubernetes - 11 upvotes, $100
- [ ] [Internal Ports Scanning via Blind SSRF](https://hackerone.com/reports/281950) to Infogram - 11 upvotes, $0
- [ ] [SSRF when importing a project from a git repo by URL](https://hackerone.com/reports/135937) to GitLab - 11 upvotes, $0
- [ ] [H1514 Shopify API ruby SDK session setup lacks input validation, resulting in SSRF and leakage of client secret](https://hackerone.com/reports/423437) to Shopify - 11 upvotes, $0
- [ ] [SSRF in Export template to ActiveCampaign](https://hackerone.com/reports/754025) to Stripo Inc - 11 upvotes, $0
- [ ] [Server-Side Request Forgery in "icons.bitwarden.net"](https://hackerone.com/reports/913276) to Bitwarden - 11 upvotes, $0
- [ ] [SSRF bypass](https://hackerone.com/reports/863221) to Concrete CMS - 11 upvotes, $0
- [ ] [Blind SSRF in /appsuite/api/oxodocumentfilter&action=addfile](https://hackerone.com/reports/865652) to Open-Xchange - 10 upvotes, $550
- [ ] [SSRF на api.icq.net](https://hackerone.com/reports/432277) to Mail.ru - 10 upvotes, $500
- [ ] [Server side request forgery](https://hackerone.com/reports/427227) to Mail.ru - 10 upvotes, $300
- [ ] [[h1-415 2020\] SSRF in a headless chrome with remote debugging leads to sensible information leak](https://hackerone.com/reports/781295) to h1-ctf - 10 upvotes, $0
- [ ] [SSRF into Shared Runner, by replacing dockerd with malicious server in Executor](https://hackerone.com/reports/809248) to GitLab - 9 upvotes, $2000
- [ ] [Blind SSRF on image proxy camo.stream.highwebmedia.com](https://hackerone.com/reports/385178) to Chaturbate - 9 upvotes, $800
- [ ] [SSRF (open) - via GET request](https://hackerone.com/reports/180527) to VK.com - 9 upvotes, $300
- [ ] [Internal Ports Scanning via Blind SSRF (URL Redirection to beat filter)](https://hackerone.com/reports/287496) to Infogram - 9 upvotes, $0
- [ ] [Server Side Request Forgery on JSON Feed](https://hackerone.com/reports/280511) to Infogram - 9 upvotes, $0
- [ ] [SSRF vulnerability in gitlab.com webhook](https://hackerone.com/reports/301924) to GitLab - 9 upvotes, $0
- [ ] [SSRF vulnerablity in app webhooks](https://hackerone.com/reports/56828) to Dropbox - 8 upvotes, $512
- [ ] [Blind SSRF on http://info.ucs.ru/settings/check/](https://hackerone.com/reports/901050) to Mail.ru - 8 upvotes, $250
- [ ] [Server-Side request forgery in New-Subscription feature of the calendar app](https://hackerone.com/reports/427835) to Nextcloud - 8 upvotes, $100
- [ ] [SSRF on infawiki.informatica.com and infawikitest.informatica.com](https://hackerone.com/reports/327480) to Informatica - 8 upvotes, $0
- [ ] [SSRF in ███████](https://hackerone.com/reports/207477) to U.S. Dept Of Defense - 8 upvotes, $0
- [ ] [Server-Side Request Forgery (SSRF)](https://hackerone.com/reports/382048) to U.S. Dept Of Defense - 8 upvotes, $0
- [ ] [SSRF in /cabinet/stripeapi/v1/siteInfoLookup?url=XXX](https://hackerone.com/reports/738553) to Stripo Inc - 8 upvotes, $0
- [ ] [Server Side Request Forgery in 'Jabber settings' in Admin Control Panel](https://hackerone.com/reports/1018568) to phpBB - 8 upvotes, $0
- [ ] [Server Side Request Forgery In Video to GIF Functionality](https://hackerone.com/reports/91816) to Imgur - 7 upvotes, $1600
- [ ] [SSRF / Local file enumeration / DoS due to improper handling of certain file formats by ffmpeg](https://hackerone.com/reports/115978) to Imgur - 7 upvotes, $1000
- [ ] [[usuppliers.uber.com\] - Server Side Request Forgery via XXE OOB](https://hackerone.com/reports/448598) to Uber - 7 upvotes, $500
- [ ] [SSRF in www.ucs.ru](https://hackerone.com/reports/906890) to Mail.ru - 7 upvotes, $250
- [ ] [SSRF on synthetics.newrelic.com permitting access to sensitive data](https://hackerone.com/reports/141682) to New Relic - 7 upvotes, $0
- [ ] [Potential SSRF and disclosure of sensitive site on *shopifycloud.com](https://hackerone.com/reports/382612) to Shopify - 7 upvotes, $0
- [ ] [GET /api/v2/url_info endpoint is vulnerable to Blind SSRF](https://hackerone.com/reports/1057531) to Automattic - 7 upvotes, $0
- [ ] [SSRF due to CVE-2021-26855 on ████████](https://hackerone.com/reports/1119224) to U.S. Dept Of Defense - 7 upvotes, $0
- [ ] [SSRF in the Connector Designer (REST and Elastic Search)](https://hackerone.com/reports/112156) to Bime - 6 upvotes, $1000
- [ ] [SSRF & XSS (W3 Total Cache)](https://hackerone.com/reports/138721) to Pornhub - 6 upvotes, $1000
- [ ] [[Java\] CWE-918: Added URLClassLoader and WebClient SSRF sinks](https://hackerone.com/reports/1250305) to GitHub Security Lab - 6 upvotes, $1000
- [ ] [Server Side Request Forgery](https://hackerone.com/reports/659565) to Lark Technologies - 6 upvotes, $100
- [ ] [Blind SSRF due to img tag injection in career form](https://hackerone.com/reports/236301) to Mixmax - 6 upvotes, $0
- [ ] [Potensial SSRF via Git repository URL ](https://hackerone.com/reports/359288)to GitLab - 6 upvotes, $0
- [ ] [SSRF on ████████](https://hackerone.com/reports/406387) to U.S. Dept Of Defense - 6 upvotes, $0
- [ ] [Blind SSRF at https://chat.makerdao.com/account/profile](https://hackerone.com/reports/846184) to BlockDev Sp. Z o.o - 6 upvotes, $0
- [ ] [C# : Add query to detect Server Side Request Forgery](https://hackerone.com/reports/1389905) to GitHub Security Lab - 5 upvotes, $1800
- [ ] [Dropbox apps Server side request forgery](https://hackerone.com/reports/137229) to Dropbox - 5 upvotes, $0
- [ ] [Server Side Request Forgery (SSRF) vulnerability in a DoD website](https://hackerone.com/reports/189648) to U.S. Dept Of Defense - 5 upvotes, $0
- [ ] [Possible SSRF at URL Parameter while creating a new package repository](https://hackerone.com/reports/151680) to GoCD - 5 upvotes, $0
- [ ] [SSRF on local storage of iOS mobile](https://hackerone.com/reports/746541) to Nextcloud - 5 upvotes, $0
- [ ] [Blind SSRF while Creating Templates](https://hackerone.com/reports/800909) to Stripo Inc - 5 upvotes, $0
- [ ] [Bypass of SSRF Vulnerability](https://hackerone.com/reports/879803) to Node.js third-party modules - 5 upvotes, $0
- [ ] [Java: Add SSRF query for Java](https://hackerone.com/reports/1061010) to GitHub Security Lab - 4 upvotes, $1800
- [ ] [SSRF via 'Add Image from URL' feature](https://hackerone.com/reports/67377) to Shopify - 4 upvotes, $500
- [ ] [SSRF - Guard - Unchecked HKP servers](https://hackerone.com/reports/792953) to Open-Xchange - 4 upvotes, $400
- [ ] [SSRF - Guard - Unchecked WKS servers](https://hackerone.com/reports/792960) to Open-Xchange - 4 upvotes, $400
- [ ] [SSRF issue](https://hackerone.com/reports/120219) to Bime - 4 upvotes, $250
- [ ] [WebLogic Server Side Request Forgery](https://hackerone.com/reports/300513) to U.S. Dept Of Defense - 4 upvotes, $0
- [ ] [[Limited bypass of #793704\] Blind SSRF in Ghost CMS](https://hackerone.com/reports/815084) to Node.js third-party modules - 4 upvotes, $0
- [ ] [SSRF in my.stripo.email](https://hackerone.com/reports/852413) to Stripo Inc - 4 upvotes, $0
- [ ] [SSRF via Export Service in ActiveCampaign](https://hackerone.com/reports/847101) to Stripo Inc - 4 upvotes, $0
- [ ] [SSRF via maliciously crafted URL due to host confusion](https://hackerone.com/reports/704621) to curl - 4 upvotes, $0
- [ ] [CVE-2021-26855 on ████████ resulting in SSRF](https://hackerone.com/reports/1119228) to U.S. Dept Of Defense - 4 upvotes, $0
- [ ] [Blind SSRF on infodesk.engelvoelkers.com via proxy.php](https://hackerone.com/reports/1051431) to Engel & Völkers Technology GmbH - 4 upvotes, $0
- [ ] [XXE and SSRF on webmaster.mail.ru](https://hackerone.com/reports/12583) to Mail.ru - 3 upvotes, $700
- [ ] [SSRF via 'Insert Image' feature of Products/Collections/Frontpage](https://hackerone.com/reports/67389) to Shopify - 3 upvotes, $500
- [ ] [Yet another SSRF query for Go](https://hackerone.com/reports/1391771) to GitHub Security Lab - 3 upvotes, $450
- [ ] [SSRF on https://whitehataudit.slack.com/account/photo](https://hackerone.com/reports/14127) to Slack - 3 upvotes, $300
- [ ] [SSRF через Share-ботов](https://hackerone.com/reports/197365) to VK.com - 3 upvotes, $300
- [ ] [Internal GET SSRF via CSRF with Press This scan feature](https://hackerone.com/reports/110801) to Automattic - 3 upvotes, $250
- [ ] [SSRF at apps.nextcloud.com/developer/apps/releases/new](https://hackerone.com/reports/213358) to Nextcloud - 3 upvotes, $0
- [ ] [https://████████ Impacted by DNN ImageHandler SSRF](https://hackerone.com/reports/482634) to U.S. Dept Of Defense - 3 upvotes, $0
- [ ] [Yet another SSRF query for Go](https://hackerone.com/reports/1391772) to GitHub Security Lab - 2 upvotes, $450
- [ ] [Yet another SSRF query for Go](https://hackerone.com/reports/1391729) to GitHub Security Lab - 2 upvotes, $450
- [ ] [Yet another SSRF query for Go](https://hackerone.com/reports/1391725) to GitHub Security Lab - 2 upvotes, $450
- [ ] [SSRF vulnerability (access to metadata server on EC2 and OpenStack)](https://hackerone.com/reports/53088) to Phabricator - 2 upvotes, $300
- [ ] [connect.mail.ru: SSRF](https://hackerone.com/reports/14033) to Mail.ru - 2 upvotes, $300
- [ ] [Yet another SSRF query for Javascript](https://hackerone.com/reports/1391728) to GitHub Security Lab - 2 upvotes, $250
- [ ] [Yet another SSRF query for Javascript](https://hackerone.com/reports/1391727) to GitHub Security Lab - 2 upvotes, $250
- [ ] [Yet another SSRF query for Javascript](https://hackerone.com/reports/1391726) to GitHub Security Lab - 2 upvotes, $250
- [ ] [Yet another SSRF query for Javascript](https://hackerone.com/reports/1391724) to GitHub Security Lab - 2 upvotes, $250
- [ ] [ssrf xspa [https://prt.mail.ru/\]](https://hackerone.com/reports/191543) to Mail.ru - 2 upvotes, $150
- [ ] [Bypass of anti-SSRF defenses in YahooCacheSystem (affecting at least YQL and Pipes)](https://hackerone.com/reports/1066) to Yahoo! - 2 upvotes, $0
- [ ] [SSRF via git Repo by URL Abuse](https://hackerone.com/reports/191216) to GitLab - 2 upvotes, $0
- [ ] [SSRF in rompager-check](https://hackerone.com/reports/374818) to Hanno's projects - 2 upvotes, $0
- [ ] [SSRF Possible through /wordpress/xmlrpc.php](https://hackerone.com/reports/1004847) to Ian Dunn - 2 upvotes, $0
- [ ] [Server Side Request Forgery](https://hackerone.com/reports/4461) to Yahoo! - 1 upvotes, $500
- [ ] [CodeQL query to detect SSRF in Python](https://hackerone.com/reports/872094) to GitHub Security Lab - 1 upvotes, $500
- [ ] [SSRF (Portscan) via Register Function (Custom Server)](https://hackerone.com/reports/16571) to RelateIQ - 1 upvotes, $250
- [ ] [SSRF на element.mail.ru](https://hackerone.com/reports/117158) to Mail.ru - 1 upvotes, $250
- [ ] [Java: CWE-918 - Server Side Request Forgery (SSRF)](https://hackerone.com/reports/1008846) to GitHub Security Lab - 1 upvotes, $250
- [ ] [Server Side Request Forgery in macro creation](https://hackerone.com/reports/50537) to Phabricator - 1 upvotes, $0
- [ ] [Possible SSRF in email server settings(SMTP mode)](https://hackerone.com/reports/222667) to Nextcloud - 1 upvotes, $0
- [ ] [SSRF leads to internal port scan](https://hackerone.com/reports/764517) to Stripo Inc - 1 upvotes, $0
- [ ] [allods.my.com\] SSRF / XSPA](https://hackerone.com/reports/111950) to Mail.ru - 0 upvotes, $150
- [ ] [SSRF in login page using fetch API exposes victims IP address to attacker controled server](https://hackerone.com/reports/996273) to U.S. Dept Of Defense - 0 upvotes, $0
- [ ] [Reverse Proxy misroute leading to steal X-Shopify-Access-Token header](https://hackerone.com/reports/429617) to Shopify $1,000

三、赏金猎人
- https://hackerone.com/0xacb
- https://twitter.com/thedawgyg

## 07-SSRF漏洞修复

## 08-SSRF参考资源