
这是一套由客户端和服务器组成的可靠UDP测试程序


服务器环境需求：centos7 x64

服务器启动:
nohup ./roger_server.x68_64_release ip port wcp > /dev/null &

ip: 0.0.0.0 [wildcard]
port: (1024---65535]

example:
nohup ./roger_server.x68_64_release 0.0.0.0 13625 wcp > /dev/null &

客户端启动: 
1, 编辑start_roger_wcp.bat
	ip：填写服务器IP (服务器上 可访问&Linsten 的IP)
	port: 填写服务器监听端口 (服务器上配置的port)

2, 双击 start_roger_wcp.bat

客户端启动成功后，会创建以下代理服务
socks4, socks5, http, https

代理服务器的地址为：当前机器的IP:12122

客户端启动成功后，还会启动一个http server (为proxy.pac服务）


支持的浏览器：
IE,EDGE,FIREFOX,360,CHROME，等所有支持socks4,socks5,http中任意一种代理的浏览器

配置的方案：

1，智能区分国内国外域名或IP方案,填写：http://127.0.0.1:8088/proxy.pac
2, 强制代理，直接填当前机器的IP:12122,然后选择代理类型。

ps: 理论上，能访问当前机器的地址都可以使用当前启动的代理，因此ios,android相应设置代理地方设置成功后，ios,android也能）


