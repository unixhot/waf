# WAF 

- 使用Nginx+Lua实现自定义WAF（Web application firewall）
- 最近发现使用的人越来越多了，计划开始维护和增加新功能 2020.7.29 赵班长

## 项目背景介绍

### 需求产生

由于原生态的Nginx的一些安全防护功能有限，就研究能不能自己编写一个WAF，参考Kindle大神的ngx_lua_waf，自己尝试写一个了，使用两天时间，边学Lua，边写。不过不是安全专业，只实现了一些比较简单的功能：

### 功能列表：

1.	支持IP白名单和黑名单功能，直接将黑名单的IP访问拒绝。
2.	支持URL白名单，将不需要过滤的URL进行定义。
3.	支持User-Agent的过滤，匹配自定义规则中的条目，然后进行处理（返回403）。
4.	支持CC攻击防护，单个URL指定时间的访问次数，超过设定值，直接返回403。
5.	支持Cookie过滤，匹配自定义规则中的条目，然后进行处理（返回403）。
6.	支持URL过滤，匹配自定义规则中的条目，如果用户请求的URL包含这些，返回403。
7.	支持URL参数过滤，原理同上。
8.	支持日志记录，将所有拒绝的操作，记录到日志中去。
9.	日志记录为JSON格式，便于日志分析，例如使用ELK进行攻击日志收集、存储、搜索和展示。

### WAF实现

WAF一句话描述，就是解析HTTP请求（协议解析模块），规则检测（规则模块），做不同的防御动作（动作模块），并将防御过程（日志模块）记录下来。所以本文中的WAF的实现由五个模块(配置模块、协议解析模块、规则模块、动作模块、错误处理模块）组成。

## 安装部署

以下方案选择其中之一即可：

- 选择1: 可以选择使用原生的Nginx，增加Lua模块实现部署。
- 选择2: 直接使用OpenResty

### OpenResty安装

1 Yum安装OpenResty（推荐）

源码安装和Yum安装选择其一即可，默认均安装在/usr/local/openresty目录下。

```
[root@opsany ~]# wget https://openresty.org/package/centos/openresty.repo
[root@opsany ~]# sudo mv openresty.repo /etc/yum.repos.d/
[root@opsany ~]# sudo yum install -y openresty
```

2. 测试OpenResty和运行Lua

```
[root@opsany ~]# vim /usr/local/openresty/nginx/conf/nginx.conf
#在默认的server配置中增加
        location /hello {
            default_type text/html;
            content_by_lua_block {
                ngx.say("<p>hello, world</p>")
            }
        }
[root@opsany ~]# /usr/local/openresty/nginx/sbin/nginx -t
nginx: the configuration file /usr/local/openresty-1.17.8.2/nginx/conf/nginx.conf syntax is ok
nginx: configuration file /usr/local/openresty-1.17.8.2/nginx/conf/nginx.conf test is successful
[root@opsany ~]# /usr/local/openresty/nginx/sbin/nginx
```

3. 测试访问

```
[root@opsany ~]# curl http://127.0.0.1/hello
<p>hello, world</p>
```

### WAF部署

```
[root@opsany ~]# git clone https://github.com/unixhot/waf.git
[root@opsany ~]# cp -r ./waf/waf /usr/local/openresty/nginx/conf/
[root@opsany ~]# vim /usr/local/openresty/nginx/conf/nginx.conf
#在http{}中增加，注意路径，同时WAF日志默认存放在/tmp/日期_waf.log
#WAF
    lua_shared_dict limit 50m;
    lua_package_path "/usr/local/openresty/nginx/conf/waf/?.lua";
    init_by_lua_file "/usr/local/openresty/nginx/conf/waf/init.lua";
    access_by_lua_file "/usr/local/openresty/nginx/conf/waf/access.lua";
[root@opsany ~]# ln -s /usr/local/openresty/lualib/resty/ /usr/local/openresty/nginx/conf/waf/resty
[root@opsany ~]# /usr/local/openresty/nginx/sbin/nginx -t
[root@opsany ~]# /usr/local/openresty/nginx/sbin/nginx -s reload
```

# 附录

## Nginx + Lua源码编译部署(不推荐)

1. Nginx安装必备的Nginx和PCRE软件包。

```
[root@nginx-lua ~]# cd /usr/local/src
[root@nginx-lua src]# wget http://nginx.org/download/nginx-1.12.1.tar.gz
[root@nginx-lua src]# wget https://nchc.dl.sourceforge.net/project/pcre/pcre/8.41/pcre-8.41.tar.gz
#其次，下载当前最新的luajit和ngx_devel_kit (NDK)，以及春哥（章）编写的lua-nginx-module
[root@nginx-lua src]# wget http://luajit.org/download/LuaJIT-2.0.5.tar.gz
[root@nginx-lua src]# wget https://github.com/simpl/ngx_devel_kit/archive/v0.3.0.tar.gz
[root@nginx-lua src]# wget wget https://github.com/chaoslawful/lua-nginx-module/archive/v0.10.10.zip
```

2. 最后，创建Nginx运行的普通用户

```
[root@nginx-lua src]# useradd -s /sbin/nologin -M www
```

3. 解压NDK和lua-nginx-module
```
[root@openstack-compute-node5 src]# tar zxvf v0.3.0.tar.gz
[root@openstack-compute-node5 src]# unzip -q v0.10.10.zip
```

4. 安装LuaJIT
Luajit是Lua即时编译器。
```
[root@webs-ebt src]# tar zxvf LuaJIT-2.0.5.tar.gz 
[root@webs-ebt src]# cd LuaJIT-2.0.5
[root@webs-ebt LuaJIT-2.0.5]# make && make install
```

5. 安装Nginx并加载模块
```
[root@webs-ebt src]# tar zxf nginx-1.12.1.tar.gz
[root@webs-ebt src]# tar zxvf pcre-8.41.tar.gz 
[root@webs-ebt src]# cd nginx-1.12.1
[root@webs-ebt nginx-1.12.1]# export LUAJIT_LIB=/usr/local/lib
[root@webs-ebt nginx-1.12.1]# export LUAJIT_INC=/usr/local/include/luajit-2.0
[root@webs-ebt nginx-1.12.1]#./configure --user=www --group=www --prefix=/usr/local/nginx-1.12.1/ --with-pcre=/usr/local/src/pcre-8.41 --with-http_stub_status_module --with-http_sub_module --with-http_gzip_static_module --without-mail_pop3_module --without-mail_imap_module --without-mail_smtp_module  --add-module=../ngx_devel_kit-0.3.0/ --add-module=../lua-nginx-module-0.10.10/
[root@webs-ebt nginx-1.12.1]# make -j2 && make install
[root@webs-ebt nginx-1.12.1]# ln -s /usr/local/nginx-1.12.1 /usr/local/nginx
[root@webs-ebt nginx-1.12.1]# ln -s /usr/local/lib/libluajit-5.1.so.2 /lib64/libluajit-5.1.so.2
```

> 如果不创建符号链接，可能出现以下异常：
```
error while loading shared libraries: libluajit-5.1.so.2: cannot open shared object file: No such file or directory
```

6. 测试安装

安装完毕后，下面可以测试安装了，修改nginx.conf 增加第一个配置。

```
        location /hello {
                default_type 'text/plain';
                content_by_lua 'ngx.say("hello,lua")';
        }
 
[root@webs-ebt src]# /usr/local/nginx/sbin/nginx -t
[root@webs-ebt src]# /usr/local/nginx/sbin/nginx -t
```

然后访问http://xxx.xxx.xxx.xxx/hello 如果出现hello,lua。表示安装完成,然后就可以。


### OpenResty源码编译部署（不推荐）

1. 安装依赖软件包

```
[root@opsany ~]# yum install -y readline-devel pcre-devel openssl-devel
```

2. 安装OpenResty


2.1 下载并编译安装OpenResty

```
[root@opsany ~]# cd /usr/local/src
[root@opsany src]# wget https://openresty.org/download/openresty-1.17.8.2.tar.gz
[root@opsany src]# tar zxf openresty-1.17.8.2.tar.gz
[root@opsany src]# cd openresty-1.17.8.2
[root@opsany openresty-1.17.8.2]# ./configure --prefix=/usr/local/openresty-1.17.8.2 \
--with-luajit --with-http_stub_status_module \
--with-pcre --with-pcre-jit \
--with-file-aio --with-threads
[root@opsany openresty-1.17.8.2]# gmake && gmake install
[root@opsany openresty-1.17.8.2]# cd
[root@opsany ~]# ln -s /usr/local/openresty-1.17.8.2/ /usr/local/openresty
```
