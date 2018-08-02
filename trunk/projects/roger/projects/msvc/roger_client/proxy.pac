  "zannel.com": 1, 
  "zaobao.com": 1, 
  "zaobao.com.sg": 1, 
  "zaozon.com": 1, 
  "zarias.com": 1, 
  "zattoo.com": 1, 
  "zengjinyan.org": 1, 
  "zeutch.com": 1, 
  "zfreet.com": 1, 
  "zgzcjj.net": 1, 
  "zhanbin.net": 1, 
  "zhe.la": 1, 
  "zhenghui.org": 1, 
  "zhenlibu.info": 1, 
  "zhinengluyou.com": 1, 
  "zhong.pp.ru": 1, 
  "zhongguotese.net": 1, 
  "zhongmeng.org": 1, 
  "zhreader.com": 1, 
  "zhuichaguoji.org": 1, 
  "ziddu.com": 1, 
  "zillionk.com": 1, 
  "zinio.com": 1, 
  "ziplib.com": 1, 
  "zkaip.com": 1, 
  "zlib.net": 1, 
  "zmw.cn": 1, 
  "zoho.com": 1, 
  "zomobo.net": 1, 
  "zonaeuropa.com": 1, 
  "zonble.net": 1, 
  "zootool.com": 1, 
  "zoozle.net": 1, 
  "zozotown.com": 1, 
  "zshare.net": 1, 
  "zsrhao.com": 1, 
  "zuo.la": 1, 
  "zuobiao.me": 1, 
  "zuola.com": 1, 
  "zvereff.com": 1, 
  "zyzc9.com": 1
};

var proxy = "PROXY_TYPE ROGER_HTTP_SERVER_ADDR:12122";
var direct = 'DIRECT;';

var hasOwnProperty = Object.hasOwnProperty;

var ipRegExp = new RegExp(/^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$/);

function convertAddress(ipchars) {
    var bytes = ipchars.split('.');
    var result = ((bytes[0] & 0xff) << 24) |
                 ((bytes[1] & 0xff) << 16) |
                 ((bytes[2] & 0xff) <<  8) |
                  (bytes[3] & 0xff);
    return result;
}

function match(ip) {
    var left = 0, right = cnips.length;
    do {
        var mid = Math.floor((left + right) / 2),
            ipf = (ip & cnips[mid][1]) >>> 0,
            m   = (cnips[mid][0] & cnips[mid][1]) >>> 0;
        if (ipf == m) {
            return true;
        } else if (ipf > m) {
            left  = mid + 1;
        } else {
            right = mid;
        }
    } while (left + 1 <= right)
    return false;
}

function testDomain(target, domains, cnRootIncluded) {
    var idxA = target.lastIndexOf('.');
    var idxB = target.lastIndexOf('.', idxA - 1);
    var hasOwnProperty = Object.hasOwnProperty;
    var suffix = cnRootIncluded ? target.substring(idxA + 1) : '';
    if (suffix === 'cn') {
        return true;
    }
    while (true) {
        if (idxB === -1) {
            if (hasOwnProperty.call(domains, target)) {
                return true;
            } else {
                return false;
            }
        }
        suffix = target.substring(idxB + 1);
        if (hasOwnProperty.call(domains, suffix)) {
            return true;
        }
        idxB = target.lastIndexOf('.', idxB - 1);
    }
}

function FindProxyForURL(url, host) {
    if (isPlainHostName(host)
     || host === '127.0.0.1'
     || host === 'localhost' 
	 || host === 'ROGER_HTTP_SERVER_ADDR' )
	{
        return direct;
    }

    if (!ipRegExp.test(host)) {
        if (testDomain(host, directDomains, true)) {
            return direct
        }

        if (testDomain(host, domains)) {
            return proxy;
        }
        strIp = dnsResolve(host);
    } else {
        strIp = host
    }

    if (!strIp) {
        return proxy;
    }
    
    intIp = convertAddress(strIp);

    if (match(intIp)) {
        return direct;
    }

    return proxy;
}