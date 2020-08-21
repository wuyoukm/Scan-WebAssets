#@author:Ruzha
#@time:2020/8/10
#@file:icmp_sniffing_web_V1.1.py
import array
import re
import struct
import threading
import time
import gevent
from gevent import monkey
monkey.patch_all(select=False)
from multiprocessing import Process
import requests
import asyncio
import socket
import os
import IPy
import platform
import optparse

class SendPingThr(threading.Thread):
    def __init__(self, ipPool, icmpPacket, icmpSocket, timeout=0.1):
        threading.Thread.__init__(self)
        self.Sock = icmpSocket
        self.ipPool = ipPool
        self.packet = icmpPacket
        self.timeout = timeout
        self.Sock.settimeout(timeout + 0.1)

    def run(self):
        time.sleep(0.01)  # 等待接收线程启动
        for ip in self.ipPool:
            try:
                self.Sock.sendto(self.packet, (ip, 0))
            except socket.timeout:
                break
        time.sleep(self.timeout)

class Nscan:
    def __init__(self, timeout=1, IPv6=False):
        self.timeout = timeout
        self.IPv6 = IPv6

        self.__data = struct.pack('d', time.time())  # 用于ICMP报文的负荷字节（8bit）
        self.__id = os.getpid()  # 构造ICMP报文的ID字段，无实际意义

    @property  # 属性装饰器
    def __icmpSocket(self):
        '''创建ICMP Socket'''
        if not self.IPv6:
            Sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname("icmp"))
        else:
            Sock = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.getprotobyname("ipv6-icmp"))
        return Sock

    def __inCksum(self, packet):
        '''ICMP 报文效验和计算方法'''
        if len(packet) & 1:
            packet = packet + '\0'
        words = array.array('h', packet)
        sum = 0
        for word in words:
            sum += (word & 0xffff)
        sum = (sum >> 16) + (sum & 0xffff)
        sum = sum + (sum >> 16)

        return (~sum) & 0xffff

    @property
    def __icmpPacket(self):
        '''构造 ICMP 报文'''
        if not self.IPv6:
            header = struct.pack('bbHHh', 8, 0, 0, self.__id, 0)  # TYPE、CODE、CHKSUM、ID、SEQ
        else:
            header = struct.pack('BbHHh', 128, 0, 0, self.__id, 0)

        packet = header + self.__data  # packet without checksum
        chkSum = self.__inCksum(packet)  # make checksum

        if not self.IPv6:
            header = struct.pack('bbHHh', 8, 0, chkSum, self.__id, 0)
        else:
            header = struct.pack('BbHHh', 128, 0, chkSum, self.__id, 0)

        return header + self.__data  # packet *with* checksum

    def isUnIP(self, IP):
        '''判断IP是否是一个合法的单播地址'''
        IP = [int(x) for x in IP.split('.') if x.isdigit()]
        if len(IP) == 4:
            if (0 < IP[0] < 223 and IP[0] != 127 and IP[1] < 256 and IP[2] < 256 and 0 < IP[3] < 255):
                return True
        return False

    def makeIpPool(self, startIP, lastIP):
        '''生产 IP 地址池'''
        IPver = 6 if self.IPv6 else 4
        intIP = lambda ip: IPy.IP(ip).int()
        ipPool = {IPy.intToIp(ip, IPver) for ip in range(intIP(startIP), intIP(lastIP) + 1)}

        return {ip for ip in ipPool if self.isUnIP(ip)}

    def mPing(self, ipPool):

        Sock = self.__icmpSocket
        Sock.settimeout(self.timeout)
        packet = self.__icmpPacket
        recvFroms = set()  # 接收线程的来源IP地址容器

        sendThr = SendPingThr(ipPool, packet, Sock, self.timeout)
        sendThr.start()

        while True:
            try:
                recvFroms.add(Sock.recvfrom(1024)[1][0])
            except Exception:
                pass
            finally:
                if not sendThr.isAlive():
                    break
        return recvFroms & ipPool

class Scan(object):
    def __init__(self,ip,ports,thread):
        #定义奇奇怪怪的东西
        if platform.system()=="Windows":
            import ctypes
            if ctypes.windll.shell32.IsUserAnAdmin():
                pass
            else:
                print('[-] Please run with The Administrator permission')
                exit()
            self.commandargs='-n'
        elif platform.system()=="Linux":
            if os.getuid()!=0:
                print('[-] Please run with root permission')
                exit()
            self.commandargs='-c'
        self.iplist=ip
        self.portlist=ports
        self.processlist=[]
        self.gevnetlist=[]
        self.asynciolist=[]
        self.calc=0
        self.calc2=0
        self.starttime = time.time()
        self.list_web = []
        self.sucess=[] #最终结果
        try:
            self.prochread=thread #并发任务数量满足条件
        except:
            print('[-] Concurrent condition settings are wrong, please enter a number')

    async def _asyncstart(self):
        #异步加速
        for ip in self.iplist:
            if self.calc==self.prochread:
                self._processstart(self.asynciolist)
                self.calc=0
                self.asynciolist.clear()
            self.asynciolist.append(ip)
            self.calc+=1

        if len(self.asynciolist)>0:
            self._processstart(self.asynciolist)
            self.calc = 0
            self.asynciolist.clear()

    def _processstart(self,data):
        #多进程提速
        for d in data:
            if self.calc2==self.prochread:
                p=Process(target=self._geventstart,args=(self.processlist,))
                p.start()
                self.processlist.clear()
                self.calc2=0
            self.processlist.append(d)
            self.calc2+=1

        if len(self.processlist)>0:
            p = Process(target=self._geventstart, args=(self.processlist,))
            p.start()
            self.processlist.clear()
            self.calc2 = 0

    def _geventstart(self,data):
        #协程提速
        for d in data:
            self.gevnetlist.append(gevent.spawn(self.Survive,d))
        gevent.joinall(self.gevnetlist)
        self.gevnetlist.clear()
        endtime = time.time()
        print("当前存活{}台主机".format(len(self.iplist)),'一共运行了{0}秒'.format((endtime - self.starttime)),"扫描到{}个WEB服务".format(len(self.list_web)))

    def get_https(self,url):
        requests.packages.urllib3.disable_warnings()
        aa = requests.get(url, verify=False)
        b = aa.content
        html_doc = str(b, 'utf-8')
        c = re.findall("<title(.*)>(.*)</title>", html_doc)[0][1]
        print("[+]", url, " | ", c, " | ", aa.status_code)
        log = ("[+] | " + url + " | " + c + " | " + str(aa.status_code))
        log_file = open('Scan_web_result.log', 'a')
        log_file.write(log + "\r\n")
        log_file.close()
        self.list_web.append(log)
        print("-------------------")

    def host(self,host, port):
        url3 = host + ":" + str(port)
        # print(url3)
        try:
            a = requests.get(url3, timeout=1)
            not_status_code = [404, 502]
            if (a.status_code not in not_status_code):
                b = a.content
                html_doc = str(b, 'utf-8')
                c = re.findall("<title(.*)>(.*)</title>", html_doc)[0][1]
                if "IIS" in c:
                    pass
                else:
                    if "建设中" in c:
                        pass
                    else:
                        if ("400 The plain HTTP request" in c):
                            https_url = "https" + url3[4:]
                            # print(https_url)
                            self.get_https(https_url)
                        else:
                            print("[+]", url3, " | ", c, " | ", a.status_code)
                            log = ("[+] | " + url3 + " | " + c + " | " + str(a.status_code))
                            log_file = open('Scan_web_result.log', 'a')
                            log_file.write(log + "\r\n")
                            log_file.close()
                            self.list_web.append(log)
                            print("<========================>")
        except:
            pass

    def Survive(self,ip):
        #主操作实现
        print("正在扫描{}".format(ip))
        url3 = "http://" + str(ip)
        test=[]
        for port in self.portlist:
            test.append(gevent.spawn(self.host,url3, port))
        gevent.joinall(test)
        test.clear()

if __name__ == '__main__':
    s = Nscan()
    print('''
  _,  _,  _, _, _    _  _ __, __,  _,  _,  _, __, ___  _,
 (_  / ` /_\ |\ |    |  | |_  |_) / \ (_  (_  |_   |  (_ 
 , ) \ , | | | \| ~~ |/\| |   |_) |~| , ) , ) |    |  , )
  ~   ~  ~ ~ ~  ~    ~  ~ ~~~ ~   ~ ~  ~   ~  ~~~  ~   ~                                                                 
          ''')
    parser=optparse.OptionParser()
    parser.add_option('-i',action='store',dest='iplist',help='setting scan ip')
    parser.add_option('-p',action='store',dest='porttype',help='setting porttype 1:1-15000;2:often ports')
    parser.add_option('-t',action='store',dest='processthread',help='Concurrent condition settings')
    option,args=parser.parse_args()
    if option.iplist and option.porttype and option.processthread:
        if "/" in option.iplist:
            host_3 = option.iplist.split("/")[0][:-2]
            host_start = host_3 + ".1"
            host_end = host_3 + ".255"
            ipPool = s.makeIpPool(host_start, host_end)  # 设置扫描存活的地址段
            ips = s.mPing(ipPool)
        else:
            ipip = {option.iplist}
            ips = s.mPing(ipip)
        if len(ips) > 0:
            print("[√]", "已发现{}台存活主机".format(len(ips)))
        else:
            print("[-]", "暂无存活ip")
            exit(0)
        for hosts in ips:
            print("[*]", hosts, "active")
        if int(option.porttype) == 1:
            ports = [x for x in range(15001)]
            obj = Scan(ips, ports, option.processthread)
            loop = asyncio.get_event_loop()
            task = loop.create_task(obj._asyncstart())
            loop.run_until_complete(task)
        elif int(option.porttype) == 2:
            ports = [80, 8080, 443, 1414, 4848, 7001, 7002, 7180, 8069, 8081,
                     8082, 8083, 8084, 8085, 8086, 8087, 8088, 8089, 8090,
                     8161, 9043, 9090, 10000, 10001, 10002, 50070, 61616, 60030]
            obj = Scan(ips, ports, option.processthread)
            loop = asyncio.get_event_loop()
            task = loop.create_task(obj._asyncstart())
            loop.run_until_complete(task)
        else:
            print("error")