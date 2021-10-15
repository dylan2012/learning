# Kubernetes二进制部署多master集群

# 集群架构及功能说明

## Master节点：

Master节点上面主要由四个模块组成，APIServer，schedule,controller-manager,etcd

1. APIServer: APIServer负责对外提供RESTful的kubernetes API的服务，它是系统管理指令的统一接口，任何对资源的增删该查都要交给APIServer处理后再交给etcd，如图，kubectl(kubernetes提供的客户端工具，该工具内部是对kubernetes API的调用）是直接和APIServer交互的。
2. schedule: schedule负责调度Pod到合适的Node上，如果把scheduler看成一个黑匣子，那么它的输入是pod和由多个Node组成的列表，输出是Pod和一个Node的绑定。 kubernetes目前提供了调度算法，同样也保留了接口。用户根据自己的需求定义自己的调度算法。
3. controller manager: 如果APIServer做的是前台的工作的话，那么controller manager就是负责后台的。每一个资源都对应一个控制器。而control manager就是负责管理这些控制器的，比如我们通过APIServer创建了一个Pod，当这个Pod创建成功后，APIServer的任务就算完成了。
4. etcd：etcd是一个高可用的键值存储系统，kubernetes使用它来存储各个资源的状态，从而实现了Restful的API。

## Node节点：

每个Node节点主要由两个模板组成：kublet, kube-proxy

1. kube-proxy: 该模块实现了kubernetes中的服务发现和反向代理功能。kube-proxy支持TCP和UDP连接转发，默认基Round Robin算法将客户端流量转发到与service对应的一组后端pod。服务发现方面，kube-proxy使用etcd的watch机制监控集群中service和endpoint对象数据的动态变化，并且维护一个service到endpoint的映射关系，从而保证了后端pod的IP变化不会对访问者造成影响，另外，kube-proxy还支持session affinity。
2. kublet：kublet是Master在每个Node节点上面的agent，是Node节点上面最重要的模块，它负责维护和管理该Node上的所有容器，但是如果容器不是通过kubernetes创建的，它并不会管理。本质上，它负责使Pod的运行状态与期望的状态一致。

![Kubernetes部署（一）：架构及功能说明_calico](https://s1.51cto.com/images/blog/201812/24/6b461755ea1f5a5e9812858399f82b4c.png?x-oss-process=image/watermark,size_16,text_QDUxQ1RP5Y2a5a6i,color_FFFFFF,t_100,g_se,x_10,y_10,shadow_90,type_ZmFuZ3poZW5naGVpdGk=)

# 系统环境初始化

## 1.目录结构

所有文件均存放在/data/kubernetes目录下

```html
  [root@root@node-01 ~]# tree -L 1 /data/kubernetes/
  /data/kubernetes/
  ├── bin   #二进制文件
  ├── cfg   #配置文件
  ├── log   #日志文件
  └── ssl   #证书文件
```

## 2. 系统架构

![Kubernetes部署（二）：系统环境初始化_docker](https://s1.51cto.com/images/blog/201812/24/33c2d7b2cbf15a8fc88f74dca0cd8f2f.jpg?x-oss-process=image/watermark,size_16,text_QDUxQ1RP5Y2a5a6i,color_FFFFFF,t_100,g_se,x_10,y_10,shadow_90,type_ZmFuZ3poZW5naGVpdGk=)

| 节点名称 | 角色   | IP            | 备注                                                         |
| -------- | ------ | ------------- | ------------------------------------------------------------ |
| 负载VIP  | VIP    | 10.199.10.230 | haproxy、keepalived                                          |
| node-01  | master | 10.199.10.231 | kube-apiserver、kube-controller-manager、kube-scheduler、etcd、docker、flannel、 kube-proxy、haproxy、keepalived |
| node-02  | master | 10.199.10.232 | kube-apiserver、kube-controller-manager、kube-scheduler、etcd、docker、flannel、kube-proxy、haproxy、keepalived |
| node-03  | master | 10.199.10.233 | kube-apiserver、kube-controller-manager、kube-scheduler、etcd、docker、flannel、kube-proxy |
| node-04  | node   | 10.199.10.234 | kube-proxy、kubelet、etcd、docker、flannel                   |
| node-05  | node   | 10.199.10.235 | kube-proxy、kubelet、etcd、docker、flannel                   |
| node-06  | node   | 10.199.10.236 | kube-proxy、kubelet、etcd、docker、flannel                   |

由于服务器不够，把 haproxy、keepalived配置在了node-01和node-02了

## 3.安装前准备

```
1. 所有节点关闭防火墙 
systemctl stop firewalld.service
systemctl disable firewalld.service
2. 所有节关闭SELinux
setenforce 0
vi /etc/selinux/config
改SELINUX=enforcing为SELINUX=disabled
3. 设置免密登录
[root@node-01 ~]# ssh-keygen  -t rsa
[root@node-01 ~]# ssh-copy-id -i .ssh/id_rsa.pub root@10.199.10.232
[root@node-01 ~]# ssh-copy-id -i .ssh/id_rsa.pub root@10.199.10.233
[root@node-01 ~]# ssh-copy-id -i .ssh/id_rsa.pub root@10.199.10.234
[root@node-01 ~]# ssh-copy-id -i .ssh/id_rsa.pub root@10.199.10.235
[root@node-01 ~]# ssh-copy-id -i .ssh/id_rsa.pub root@10.199.10.236
```

```
#开启防火墙如何部署k8s
#你可以不关闭防火墙，只需要开启这些端口就行了
MASTER节点
6443* Kubernetes API server
2379-2380 etcd server client API
10250 Kubelet API
10251 kube-scheduler
10252 kube-controller-manager
10255 Read-only Kubelet API (Heapster)

node节点
10250 Kubelet API
10255 Read-only Kubelet API (Heapster)
30000-32767 Default port range for NodePort Services. Typically, these ports would need to be exposed to external load-balancers, or other external consumers of the application itself.
```

## 4.安装Docker

```
curl -fsSL https://get.docker.com/ | sh
systemctl start docker
systemctl enable docker
```

## 5.准备部署目录

```
mkdir -p /data/kubernetes/{cfg,bin,ssl,log}
```

## 6.准备软件包

```
 # tar zxf kubernetes-server-linux-amd64.tar.gz 
 # tar zxf kubernetes-client-linux-amd64.tar.gz
 # tar zxf kubernetes-node-linux-amd64.tar.gz
```

# 制作CA证书

## 1.安装 CFSSL

```
[root@node-01  ~]# cd /usr/local/src
[root@node-01  src]# wget https://pkg.cfssl.org/R1.2/cfssl_linux-amd64
[root@node-01  src]# wget https://pkg.cfssl.org/R1.2/cfssljson_linux-amd64
[root@node-01  src]# wget https://pkg.cfssl.org/R1.2/cfssl-certinfo_linux-amd64
[root@node-01  src]# chmod +x cfssl*
[root@node-01  src]# mv cfssl-certinfo_linux-amd64 /data/kubernetes/bin/cfssl-certinfo
[root@node-01  src]# mv cfssljson_linux-amd64  /data/kubernetes/bin/cfssljson
[root@node-01  src]# mv cfssl_linux-amd64  /data/kubernetes/bin/cfssl
复制cfssl命令文件拷贝到所有节点
[root@node-01  ~]# scp /data/kubernetes/bin/cfssl* 10.199.10.231: /data/kubernetes/bin
[root@node-01  ~]# scp /data/kubernetes/bin/cfssl* 10.199.10.232: /data/kubernetes/bin
将/data/kubernetes/bin加入环境变量
[root@node-01 ~]# echo 'PATH=/data/kubernetes/bin:$PATH' >>/etc/profile
[root@node-01 ~]# source /etc/profile
```

## 2.初始化cfssl

```
[root@node-01  src]# mkdir ssl && cd ssl
[root@node-01  ssl]# cfssl print-defaults config > config.json
[root@node-01  ssl]# cfssl print-defaults csr > csr.json
```

## 3.创建用来生成 CA 文件的 JSON 配置文件

server auth表示client可以用该ca对server提供的证书进行验证

client auth表示server可以用该ca对client提供的证书进行验证

```
vim ca-config.json{  "signing": {    "default": {      "expiry": "87600h"    },    "profiles": {      "kubernetes": {        "usages": [            "signing",            "key encipherment",            "server auth",            "client auth"        ],        "expiry": "87600h"      }    }  }}
```

## 4.创建用来生成 CA 证书签名请求（CSR）的 JSON 配置文件

```
vim ca-csr.json{  "CN": "kubernetes",  "key": {    "algo": "rsa",    "size": 2048  },  "names": [    {      "C": "CN",      "ST": "BeiJing",      "L": "BeiJing",      "O": "k8s",      "OU": "System"    }  ]}
```

## 5.生成CA证书（ca.pem）和密钥（ca-key.pem）

```
cfssl gencert -initca ca-csr.json | cfssljson -bare cals -l ca*
```

## 6.分发证书

```
cp ca.csr ca.pem ca-key.pem ca-config.json /data/kubernetes/sslfor n in `seq 232 236`;do scp ca.csr ca.pem ca-key.pem ca-config.json root@10.199.10.$n:/data/kubernetes/ssl;done ca.cs
```

# 部署ETCD集群

**配置前3台主机需时间同步。**

## 1.准备etcd软件包

```
[root@node-01 k8s]# wget https://github.com/coreos/etcd/releases/download/v3.2.18/etcd-v3.2.18-linux-amd64.tar.gz[root@node-01 k8s]# tar zxf etcd-v3.2.18-linux-amd64.tar.gz[root@node-01 k8s]# cd etcd-v3.2.18-linux-amd64[root@node-01 etcd-v3.2.18-linux-amd64]# cp etcd etcdctl /data/kubernetes/bin/#拷贝到其他2个master节点[root@node-01 etcd-v3.2.18-linux-amd64]# scp etcd etcdctl 10.199.10.232:/data/kubernetes/bin/[root@node-01 etcd-v3.2.18-linux-amd64]# scp etcd etcdctl 10.199.10.233:/data/kubernetes/bin/
```

## 2.创建 etcd 证书签名请求

**这里需要列出所有需要安装etcd节点的ip，不然会导致后续报错。**

```
vim etcd-csr.json{  "CN": "etcd",  "hosts": [    "127.0.0.1",    "10.199.10.231",    "10.199.10.232",    "10.199.10.233",    "node-01",    "node-02",    "node-03"  ],  "key": {    "algo": "rsa",    "size": 2048  },  "names": [    {      "C": "CN",      "ST": "BeiJing",      "L": "BeiJing",      "O": "k8s",      "OU": "System"    }  ]}
```

## 3.生成 etcd 证书和私钥

```
[root@node-01 ~]# cfssl gencert -ca=/data/kubernetes/ssl/ca.pem \  -ca-key=/data/kubernetes/ssl/ca-key.pem \  -config=/data/kubernetes/ssl/ca-config.json \  -profile=kubernetes etcd-csr.json | cfssljson -bare etcd会生成以下证书文件[root@node-01 ssl]# ls -l etcd*-rw-r--r-- 1 root root 1062 Dec 24 17:33 etcd.csr-rw-r--r-- 1 root root  296 Dec 24 17:32 etcd-csr.json-rw------- 1 root root 1679 Dec 24 17:33 etcd-key.pem-rw-r--r-- 1 root root 1436 Dec 24 17:33 etcd.pem
```

## 4.将证书移动到master节点的/data/kubernetes/ssl目录下

```
[root@node-01 ssl]# cp etcd*.pem /data/kubernetes/ssl/[root@node-01 ssl]# scp etcd*.pem 10.199.10.232:/data/kubernetes/ssl/[root@node-01 ssl]# scp etcd*.pem 10.199.10.233:/data/kubernetes/ssl/[root@node-01 ssl]# rm -f etcd.csr etcd-csr.json 
```

## 5.设置ETCD配置文件

```
[root@node-01 k8s]# vim /data/kubernetes/cfg/etcd.conf#[member]ETCD_NAME="etcd-node1"ETCD_DATA_DIR="/var/lib/etcd/default.etcd"#ETCD_SNAPSHOT_COUNTER="10000"#ETCD_HEARTBEAT_INTERVAL="100"#ETCD_ELECTION_TIMEOUT="1000"ETCD_LISTEN_PEER_URLS="https://10.199.10.231:2380"ETCD_LISTEN_CLIENT_URLS="https://10.199.10.231:2379,https://127.0.0.1:2379"#ETCD_MAX_SNAPSHOTS="5"#ETCD_MAX_WALS="5"#ETCD_CORS=""#[cluster]ETCD_INITIAL_ADVERTISE_PEER_URLS="https://10.199.10.231:2380"# if you use different ETCD_NAME (e.g. test),# set ETCD_INITIAL_CLUSTER value for this name, i.e. "test=http://..."ETCD_INITIAL_CLUSTER="etcd-node1=https://10.199.10.231:2380,etcd-node2=https://10.199.10.232:2380,etcd-node3=https://10.199.10.233:2380"ETCD_INITIAL_CLUSTER_STATE="new"ETCD_INITIAL_CLUSTER_TOKEN="k8s-etcd-cluster"ETCD_ADVERTISE_CLIENT_URLS="https://10.199.10.231:2379"#[security]CLIENT_CERT_AUTH="true"ETCD_TRUSTED_CA_FILE="/data/kubernetes/ssl/ca.pem"ETCD_CERT_FILE="/data/kubernetes/ssl/etcd.pem"ETCD_KEY_FILE="/data/kubernetes/ssl/etcd-key.pem"PEER_CLIENT_CERT_AUTH="true"ETCD_PEER_TRUSTED_CA_FILE="/data/kubernetes/ssl/ca.pem"ETCD_PEER_CERT_FILE="/data/kubernetes/ssl/etcd.pem"ETCD_PEER_KEY_FILE="/data/kubernetes/ssl/etcd-key.pem"
```

## 6.创建ETCD系统服务

```
[root@node-01 k8s]# vim /etc/systemd/system/etcd.service[Unit]Description=Etcd ServerAfter=network.target[Service]Type=simpleWorkingDirectory=/var/lib/etcdEnvironmentFile=-/data/kubernetes/cfg/etcd.conf# set GOMAXPROCS to number of processorsExecStart=/bin/bash -c "GOMAXPROCS=$(nproc) /data/kubernetes/bin/etcd"Type=notify[Install]WantedBy=multi-user.target
```

## 7.重新加载系统服务

```
[root@node-01 k8s]# systemctl daemon-reload[root@node-01 k8s]# systemctl enable etcd[root@node-01 k8s]# scp /data/kubernetes/cfg/etcd.conf 10.199.10.232:/data/kubernetes/cfg/[root@node-01 k8s]# scp /data/kubernetes/cfg/etcd.conf 10.199.10.233:/data/kubernetes/cfg/[root@node-01 k8s]# scp /etc/systemd/system/etcd.service 10.199.10.232:/etc/systemd/system/[root@node-01 k8s]# scp /etc/systemd/system/etcd.service 10.199.10.233:/etc/systemd/system/在所有节点上创建etcd存储目录并启动etcd[root@node-01 ~]# mkdir /var/lib/etcd[root@node-01 ~]# systemctl start etcd[root@node-01 ~]# systemctl status etcd
```

在所有的 etcd 节点重复上面的步骤，并修改对应的配置文件，直到所有机器的 etcd 服务都已启动。

## 8.验证集群

```
etcdctl --endpoints=https://10.199.10.231:2379 \--ca-file=/data/kubernetes/ssl/ca.pem \--cert-file=/data/kubernetes/ssl/etcd.pem \--key-file=/data/kubernetes/ssl/etcd-key.pem cluster-healthmember 6d88194636f8d570 is healthy: got healthy result from https://10.199.10.232:2379member ad9448fdb3b3cd26 is healthy: got healthy result from https://10.199.10.233:2379member fb7fb38e5e81969b is healthy: got healthy result from https://10.199.10.231:2379cluster is healthy新版本：alias etcdssl='etcdctl --endpoints=https://10.199.10.231:2379,https://10.199.10.232:2379,https://10.199.10.233:2379 --cacert=/data/kubernetes/ssl/ca.pem --cert=/data/kubernetes/ssl/etcd.pem --key=/data/kubernetes/ssl/etcd-key.pem'etcdssl endpoint statusetcdssl endpoint healthetcdssl member list
```

# 部署haproxy

### 1. 安装haproxy

```
yum install haproxy -y
```

### 2. 配置内核转发

基于NAT模式的负载均衡器都需要打开系统转发功能

```
cat >>/etc/sysctl.conf<<EOFnet.ipv4.ip_forward = 1net.ipv4.ip_nonlocal_bind = 1EOFsysctl -p
```

### 3. 日志配置

```
cat >>/etc/rsyslog.conf <<EOF#Haproxylocal0.* /var/log/haproxy.logEOFvim /etc/rsyslog.conf +15   #取消配置文件注释$ModLoad imudp$UDPServerRun 514tail -1 /etc/sysconfig/rsyslog SYSLOGD_OPTIONS="-c 2 -m 0 -r -x"#重启rsyslog服务systemctl restart rsyslog
```

在node-01和node-02执行相同操作，注意修改部分配置的ip地址

### 4. haproxy配置

node-01配置和node-2配置一样

```html
vim /etc/haproxy/haproxy.cfgglobal        chroot  /var/lib/haproxy        daemon        group haproxy        user haproxy        log 127.0.0.1:514 local0 warning        pidfile /var/lib/haproxy.pid        maxconn 20000        spread-checks 3        nbproc 8defaults        log     global        mode    tcp        retries 3        option redispatchlisten https-apiserver        bind 10.199.10.230:6443        mode tcp        balance roundrobin        timeout server 15s        timeout connect 15s        server apiserver01 10.199.10.231:6443 check port 6443 inter 5000 fall 5        server apiserver02 10.199.10.232:6443 check port 6443 inter 5000 fall 5        server apiserver03 10.199.10.233:6443 check port 6443 inter 5000 fall 5listen http-apiserver        bind 10.199.10.230:8080        mode tcp        balance roundrobin        timeout server 15s        timeout connect 15s        server apiserver01 10.199.10.231:8080 check port 8080 inter 5000 fall 5        server apiserver02 10.199.10.232:8080 check port 8080 inter 5000 fall 5        server apiserver03 10.199.10.233:8080 check port 8080 inter 5000 fall 5
```

### 5. 启动服务

```html
systemctl start haproxy.servicesystemctl status haproxy.service
```

# 部署Keepalived

### 1. 安装keepalived

```html
yum -y install gcc openssl-devel libnl libnl-devel libnfnetlink-devel net-tools官网下载keepalived安装包：https://www.keepalived.org/download.html此处下载最新版本2.2.4wget https://www.keepalived.org/software/keepalived-2.2.4.tar.gztar zxf keepalived-2.2.4.tar.gz cd keepalived-2.2.4/./configure make -j2 && make installmkdir /etc/keepalivedcp /usr/local/etc/sysconfig/keepalived /etc/sysconfig/cp /usr/local/etc/keepalived/keepalived.conf /etc/keepalived/
```

### 2. 日志配置

```
vim /etc/sysconfig/keepalived KEEPALIVED_OPTIONS="-D -d -S 1"cat >>/etc/rsyslog.conf <<EOF#keepalivedlocal1.* /var/log/keepalived.logEOF#重启rsyslog服务systemctl restart rsyslog
```

### 3. keepalived配置文件

#### node-01配置文件

```html
vim /etc/keepalived/keepalived.conf ! Configuration File for keepalivedglobal_defs {   notification_email {        fengxxxx110498@163.com   }   notification_email_from Alexandre.Cassen@firewall.loc   smtp_server 127.0.0.1   smtp_connect_timeout 30   router_id LVS_1}vrrp_instance VI_1 {    state MASTER    interface eth0    lvs_sync_daemon_inteface eth0    virtual_router_id 50    advert_int 1    priority 100    authentication {        auth_type PASS        auth_pass 1111    }    virtual_ipaddress {      10.199.10.230/24    }}
```

#### node-02配置文件

```html
cat /etc/keepalived/keepalived.conf ! Configuration File for keepalivedglobal_defs {   notification_email {        fengxxxx110498@163.com   }   notification_email_from Alexandre.Cassen@firewall.loc   smtp_server 127.0.0.1   smtp_connect_timeout 30   router_id LVS_2}vrrp_instance VI_1 {    state MASTER    interface eth0    lvs_sync_daemon_inteface eth0    virtual_router_id 50    advert_int 1    priority 90    authentication {        auth_type PASS        auth_pass 1111    }    virtual_ipaddress {      10.199.10.230/24    }}systemctl start keepalived.servicesystemctl status keepalived.service
```

至此haproxy和keepalived部署完成，可以停止其中一台的keepalived服务器，用`ip add show eth0`查看VIP的漂浮状态，如果能正常转移就成功了。

```html
#node-01[root@node-01 ~]# ip add show eth0                2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000    link/ether 00:50:56:82:64:70 brd ff:ff:ff:ff:ff:ff    inet 10.199.10.231/24 brd 10.199.10.255 scope global noprefixroute eth0       valid_lft forever preferred_lft forever    inet 10.199.10.230/24 scope global secondary eth0       valid_lft forever preferred_lft forever    inet6 fe80::250:56ff:fe82:6470/64 scope link noprefixroute        valid_lft forever preferred_lft forever    #node-02[root@node-02 ~]# ip add show eth02: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000    link/ether 00:50:56:82:dd:7d brd ff:ff:ff:ff:ff:ff    inet 10.199.10.232/24 brd 10.199.10.255 scope global noprefixroute eth0       valid_lft forever preferred_lft forever    inet6 fe80::250:56ff:fe82:dd7d/64 scope link noprefixroute        valid_lft forever preferred_lft forever
```

# 部署Master节点

## 1.部署Kubernetes API服务部署

### 0.准备软件包

```html
https://github.com/kubernetes/kubernetes/blob/master/CHANGELOG/CHANGELOG-1.22.md#server-binaries根据版本下载wget https://dl.k8s.io/v1.22.1/kubernetes-node-linux-amd64.tar.gztar xf kubernetes-node-linux-amd64.tar.gzwget https://dl.k8s.io/v1.22.1/kubernetes-server-linux-amd64.tar.gztar xf kubernetes-server-linux-amd64.tar.gzcd kubernetescp server/bin/kube-apiserver /data/kubernetes/bin/cp server/bin/kube-controller-manager /data/kubernetes/bin/cp server/bin/kube-scheduler /data/kubernetes/bin/scp server/bin/kube-apiserver 10.199.10.232:/data/kubernetes/bin/scp server/bin/kube-apiserver 10.199.10.233:/data/kubernetes/bin/scp server/bin/kube-controller-manager 10.199.10.232:/data/kubernetes/bin/scp server/bin/kube-controller-manager 10.199.10.233:/data/kubernetes/bin/scp server/bin/kube-scheduler 10.199.10.232:/data/kubernetes/binscp server/bin/kube-scheduler 10.199.10.233:/data/kubernetes/bin/
```

### 1.创建生成CSR的 JSON 配置文件

```
[root@node-01 src]# vim kubernetes-csr.json{  "CN": "kubernetes",  "hosts": [    "127.0.0.1",    "10.199.10.230",    "10.199.10.231",    "10.199.10.232",    "10.199.10.233",    "10.1.0.1",    "kubernetes",    "kubernetes.default",    "kubernetes.default.svc",    "kubernetes.default.svc.cluster",    "kubernetes.default.svc.cluster.local"  ],  "key": {    "algo": "rsa",    "size": 2048  },  "names": [    {      "C": "CN",      "ST": "BeiJing",      "L": "BeiJing",      "O": "k8s",      "OU": "System"    }  ]}
```

### 2.生成 kubernetes 证书和私钥

```html
[root@node-01 src]# cfssl gencert -ca=/data/kubernetes/ssl/ca.pem \   -ca-key=/data/kubernetes/ssl/ca-key.pem \   -config=/data/kubernetes/ssl/ca-config.json \   -profile=kubernetes kubernetes-csr.json | cfssljson -bare kubernetes[root@node-01 ssl]# cp kubernetes*.pem /data/kubernetes/ssl/[root@node-01 ssl]# scp kubernetes*.pem 10.199.10.232:/data/kubernetes/ssl/[root@node-01 ssl]# scp kubernetes*.pem 10.199.10.233:/data/kubernetes/ssl/
```

### 3.创建 kube-apiserver 使用的客户端 token 文件

```
[root@node-01 ssl]# head -c 16 /dev/urandom | od -An -t x | tr -d ' 'cf25becebf64e3fffd7f3890a60ac16d[root@node-01 ssl]# vim /data/kubernetes/ssl/bootstrap-token.csvcf25becebf64e3fffd7f3890a60ac16d,kubelet-bootstrap,10001,"system:kubelet-bootstrap"[root@node-01 ssl]# scp /data/kubernetes/ssl/bootstrap-token.csv 10.199.10.232:/data/kubernetes/ssl/[root@node-01 ssl]# scp /data/kubernetes/ssl/bootstrap-token.csv 10.199.10.233:/data/kubernetes/ssl/
```

### 4.创建基础用户名/密码认证配置

```html
[root@node-01 ssl]# vim /data/kubernetes/ssl/basic-auth.csvadmin,admin,1readonly,readonly,2[root@node-01 ssl]# scp /data/kubernetes/ssl/basic-auth.csv 10.199.10.232:/data/kubernetes/ssl/[root@node-01 ssl]# scp /data/kubernetes/ssl/basic-auth.csv 10.199.10.233:/data/kubernetes/ssl/
```

### 5.部署Kubernetes API Server

三个master节点都需要部署

```shell
cat > /data/kubernetes/cfg/kube-apiserver.conf << "EOF"KUBE_APISERVER_OPTS="--enable-admission-plugins=NamespaceLifecycle,NodeRestriction,LimitRanger,ServiceAccount,DefaultStorageClass,ResourceQuota \  --anonymous-auth=false \  --bind-address=10.199.10.231 \  --secure-port=6443 \  --advertise-address=10.199.10.231 \  --insecure-port=0 \  --authorization-mode=Node,RBAC \  --runtime-config=api/all=true \  --enable-bootstrap-token-auth \  --service-cluster-ip-range=10.1.0.0/16 \  --token-auth-file=/data/kubernetes/ssl/bootstrap-token.csv \  --service-node-port-range=30000-50000 \  --tls-cert-file=/data/kubernetes/ssl/kubernetes.pem  \  --tls-private-key-file=/data/kubernetes/ssl/kubernetes-key.pem \  --client-ca-file=/data/kubernetes/ssl/ca.pem \  --kubelet-client-certificate=/data/kubernetes/ssl/kubernetes.pem \  --kubelet-client-key=/data/kubernetes/ssl/kubernetes-key.pem \  --service-account-key-file=/data/kubernetes/ssl/ca-key.pem \  --service-account-signing-key-file=/data/kubernetes/ssl/ca-key.pem  \  --service-account-issuer=api \  --etcd-cafile=/data/kubernetes/ssl/ca.pem \  --etcd-certfile=/data/kubernetes/ssl/etcd.pem \  --etcd-keyfile=/data/kubernetes/ssl/etcd-key.pem \  --etcd-servers=https://10.199.10.231:2379,https://10.199.10.232:2379,https://10.199.10.233:2379 \  --enable-swagger-ui=true \  --allow-privileged=true \  --apiserver-count=3 \  --audit-log-maxage=30 \  --audit-log-maxbackup=3 \  --audit-log-maxsize=100 \  --audit-log-path=/var/log/kube-apiserver-audit.log \  --event-ttl=1h \  --alsologtostderr=true \  --logtostderr=false \  --log-dir=/var/log/kubernetes \  --v=4"EOFcat > /usr/lib/systemd/system/kube-apiserver.service << "EOF"[Unit]Description=Kubernetes API ServerDocumentation=https://github.com/kubernetes/kubernetesAfter=etcd.serviceWants=etcd.service[Service]EnvironmentFile=-/data/kubernetes/cfg/kube-apiserver.confExecStart=/data/kubernetes/bin/kube-apiserver $KUBE_APISERVER_OPTSRestart=on-failureRestartSec=5Type=notifyLimitNOFILE=65536[Install]WantedBy=multi-user.targetEOFscp /data/kubernetes/cfg/kube-apiserver.conf 10.199.10.232:/data/kubernetes/cfg/kube-apiserver.confscp /data/kubernetes/cfg/kube-apiserver.conf 10.199.10.233:/data/kubernetes/cfg/kube-apiserver.confscp /usr/lib/systemd/system/kube-apiserver.service 10.199.10.232:/usr/lib/systemd/system/kube-apiserver.servicescp /usr/lib/systemd/system/kube-apiserver.service 10.199.10.233:/usr/lib/systemd/system/kube-apiserver.service#修改IP
```

### 6.启动API Server服务

```shell
systemctl daemon-reloadsystemctl enable kube-apiserversystemctl start kube-apiserver
```

查看API Server服务状态

```shell
systemctl status kube-apiservercurl --insecure https://10.199.10.231:6443/curl --insecure https://10.199.10.232:6443/curl --insecure https://10.199.10.233:6443/curl --insecure https://10.199.10.230:6443/
```

**kubeconfig配置**

kube.config 为 kubectl 的配置文件，包含访问 apiserver 的所有信息，如 apiserver 地址、CA 证书和自身使用的证书

```
kubectl config set-cluster kubernetes --certificate-authority=/data/kubernetes/ssl/ca.pem --embed-certs=true --server=https://10.199.10.230:6443 --kubeconfig=kube.configkubectl config set-credentials admin --client-certificate=/data/kubernetes/ssl/admin.pem --client-key=/data/kubernetes/ssl/admin-key.pem --embed-certs=true --kubeconfig=kube.configkubectl config set-context kubernetes --cluster=kubernetes --user=admin --kubeconfig=kube.configkubectl config use-context kubernetes --kubeconfig=kube.configmkdir ~/.kubecp kube.config ~/.kube/configkubectl create clusterrolebinding kube-apiserver:kubelet-apis --clusterrole=system:kubelet-api-admin --user kubernetes --kubeconfig=/root/.kube/configexport KUBECONFIG=$HOME/.kube/configkubectl cluster-infokubectl get componentstatuseskubectl get all --all-namespaces
```

同步kubectl配置文件到其他节点，配置kubectl子命令补全

```
scp /root/.kube/config  10.199.10.232:/root/.kube/configscp /root/.kube/config  10.199.10.233:/root/.kube/configyum install -y bash-completionsource /usr/share/bash-completion/bash_completionsource <(kubectl completion bash)kubectl completion bash > ~/.kube/completion.bash.incsource '/root/.kube/completion.bash.inc'  source $HOME/.bash_profile
```



## 部署Controller Manager服务

三个master节点都需要部署

```html
cat > /data/kubernetes/ssl/kube-controller-manager-csr.json << "EOF"{    "CN": "system:kube-controller-manager",    "key": {        "algo": "rsa",        "size": 2048    },    "hosts": [      "127.0.0.1",      "10.199.10.231",      "10.199.10.232",      "10.199.10.233"    ],    "names": [      {        "C": "CN",        "ST": "Hubei",        "L": "shiyan",        "O": "system:kube-controller-manager",        "OU": "system"      }    ]}EOF#hosts 列表包含所有 kube-controller-manager 节点 IP；#CN 为 system:kube-controller-manager、O 为 system:kube-controller-manager，kubernetes 内置的 ClusterRoleBindings system:kube-#controller-manager 赋予 kube-controller-manager 工作所需的权限cfssl gencert -ca=ca.pem -ca-key=ca-key.pem -config=ca-config.json -profile=kubernetes kube-controller-manager-csr.json | cfssljson -bare kube-controller-managerls kube-controller-manager*.pemkubectl config set-cluster kubernetes --certificate-authority=/data/kubernetes/ssl/ca.pem --embed-certs=true --server=https://10.199.10.230:6443 --kubeconfig=/data/kubernetes/ssl/kube-controller-manager.kubeconfigkubectl config set-credentials system:kube-controller-manager --client-certificate=/data/kubernetes/ssl/kube-controller-manager.pem --client-key=/data/kubernetes/ssl/kube-controller-manager-key.pem --embed-certs=true --kubeconfig=/data/kubernetes/ssl/kube-controller-manager.kubeconfigkubectl config set-context system:kube-controller-manager --cluster=kubernetes --user=system:kube-controller-manager --kubeconfig=/data/kubernetes/ssl/kube-controller-manager.kubeconfigkubectl config use-context system:kube-controller-manager --kubeconfig=/data/kubernetes/ssl/kube-controller-manager.kubeconfigcat > /data/kubernetes/cfg/kube-controller-manager.conf << "EOF"KUBE_CONTROLLER_MANAGER_OPTS=" \  --secure-port=10257 \  --bind-address=127.0.0.1 \  --kubeconfig=/data/kubernetes/ssl/kube-controller-manager.kubeconfig \  --service-cluster-ip-range=10.1.0.0/16 \  --cluster-name=kubernetes \  --cluster-signing-cert-file=/data/kubernetes/ssl/ca.pem \  --cluster-signing-key-file=/data/kubernetes/ssl/ca-key.pem \  --allocate-node-cidrs=true \  --cluster-cidr=172.168.0.0/16 \  --experimental-cluster-signing-duration=87600h \  --root-ca-file=/data/kubernetes/ssl/ca.pem \  --service-account-private-key-file=/data/kubernetes/ssl/ca-key.pem \  --leader-elect=true \  --feature-gates=RotateKubeletServerCertificate=true \  --controllers=*,bootstrapsigner,tokencleaner \  --tls-cert-file=/data/kubernetes/ssl/kube-controller-manager.pem \  --tls-private-key-file=/data/kubernetes/ssl/kube-controller-manager-key.pem \  --use-service-account-credentials=true \  --alsologtostderr=true \  --logtostderr=false \  --log-dir=/var/log/kubernetes \  --v=2"EOFcat > /usr/lib/systemd/system/kube-controller-manager.service << "EOF"[Unit]Description=Kubernetes Controller ManagerDocumentation=https://github.com/kubernetes/kubernetes[Service]EnvironmentFile=-/data/kubernetes/cfg/kube-controller-manager.confExecStart=/data/kubernetes/bin/kube-controller-manager $KUBE_CONTROLLER_MANAGER_OPTSRestart=on-failureRestartSec=5[Install]WantedBy=multi-user.targetEOF
```

### 3.启动Controller Manager

```shell
systemctl daemon-reloadsystemctl enable kube-controller-managersystemctl start kube-controller-manager
```

## 4.查看服务状态

```html
systemctl status kube-controller-manager# 同步到其它master节点scp /data/kubernetes/ssl/kube-controller-manager*.pem 10.199.10.232:/data/kubernetes/ssl/scp /data/kubernetes/ssl/kube-controller-manager*.pem 10.199.10.233:/data/kubernetes/ssl/scp /data/kubernetes/ssl/kube-controller-manager.kubeconfig 10.199.10.232:/data/kubernetes/ssl/scp /data/kubernetes/ssl/kube-controller-manager.kubeconfig 10.199.10.233:/data/kubernetes/ssl/scp /data/kubernetes/cfg/kube-controller-manager.conf 10.199.10.232:/data/kubernetes/cfg/scp /data/kubernetes/cfg/kube-controller-manager.conf 10.199.10.233:/data/kubernetes/cfg/scp /usr/lib/systemd/system/kube-controller-manager.service 10.199.10.232:/usr/lib/systemd/system/scp /usr/lib/systemd/system/kube-controller-manager.service 10.199.10.233:/usr/lib/systemd/system/
```

## 部署Kubernetes Scheduler

三个master节点都需要部署

```shell
cat > kube-scheduler-csr.json << "EOF"{    "CN": "system:kube-scheduler",    "hosts": [      "127.0.0.1",      "10.199.10.231",      "10.199.10.232",      "10.199.10.233"    ],    "key": {        "algo": "rsa",        "size": 2048    },    "names": [      {        "C": "CN",        "ST": "Hubei",        "L": "shiyan",        "O": "system:kube-scheduler",        "OU": "system"      }    ]}EOFcfssl gencert -ca=ca.pem -ca-key=ca-key.pem -config=ca-config.json -profile=kubernetes kube-scheduler-csr.json | cfssljson -bare kube-schedulerls kube-scheduler*.pem#创建kube-scheduler的kubeconfigkubectl config set-cluster kubernetes --certificate-authority=ca.pem --embed-certs=true --server=https://10.199.10.230:6443 --kubeconfig=kube-scheduler.kubeconfigkubectl config set-credentials system:kube-scheduler --client-certificate=kube-scheduler.pem --client-key=kube-scheduler-key.pem --embed-certs=true --kubeconfig=kube-scheduler.kubeconfigkubectl config set-context system:kube-scheduler --cluster=kubernetes --user=system:kube-scheduler --kubeconfig=kube-scheduler.kubeconfigkubectl config use-context system:kube-scheduler --kubeconfig=kube-scheduler.kubeconfig#创建配置文件cat > /data/kubernetes/cfg/kube-scheduler.conf << "EOF"KUBE_SCHEDULER_OPTS="--address=127.0.0.1 \--kubeconfig=/data/kubernetes/ssl/kube-scheduler.kubeconfig \--leader-elect=true \--alsologtostderr=true \--logtostderr=false \--log-dir=/data/kubernetes/log \--v=2"EOF#创建服务启动文件cat > /usr/lib/systemd/system/kube-scheduler.service << "EOF"[Unit]Description=Kubernetes SchedulerDocumentation=https://github.com/kubernetes/kubernetes[Service]EnvironmentFile=-/data/kubernetes/cfg/kube-scheduler.confExecStart=/data/kubernetes/bin/kube-scheduler $KUBE_SCHEDULER_OPTSRestart=on-failureRestartSec=5[Install]WantedBy=multi-user.targetEOF[root@node-01 ~]# vim /usr/lib/systemd/system/kube-scheduler.service[Unit]Description=Kubernetes SchedulerDocumentation=https://github.com/GoogleCloudPlatform/kubernetes[Service]ExecStart=/data/kubernetes/bin/kube-scheduler \  --address=127.0.0.1 \  --master=http://10.199.10.230:8080 \  --leader-elect=true \  --v=2 \  --logtostderr=false \  --log-dir=/data/kubernetes/logRestart=on-failureRestartSec=5[Install]WantedBy=multi-user.target
```

### 2.部署服务

```html
[root@node-01 ~]# systemctl daemon-reload[root@node-01 ~]# systemctl enable kube-scheduler[root@node-01 ~]# systemctl start kube-scheduler[root@node-01 ~]# systemctl status kube-scheduler# 同步到其它master节点scp /data/kubernetes/ssl/kube-scheduler* 10.199.10.232:/data/kubernetes/ssl/scp /data/kubernetes/ssl/kube-scheduler* 10.199.10.233:/data/kubernetes/ssl/scp /data/kubernetes/cfg/kube-scheduler.conf 10.199.10.232:/data/kubernetes/cfg/scp /data/kubernetes/cfg/kube-scheduler.conf 10.199.10.233:/data/kubernetes/cfg/scp /usr/lib/systemd/system/kube-scheduler.service 10.199.10.232:/usr/lib/systemd/system/scp /usr/lib/systemd/system/kube-scheduler.service 10.199.10.233:/usr/lib/systemd/system/
```

## 部署kubectl 命令行工具

这只需在其中一台部署即可，用来管理k8s集群。

1.准备二进制命令包

```shell
cp node/bin/kubectl /data/kubernetes/bin/
```

2.创建 admin 证书签名请求

```shell
[root@node-01 ~]# cd /usr/local/src/ssl/[root@node-01 ssl]# vim admin-csr.json{  "CN": "admin",  "hosts": [],  "key": {    "algo": "rsa",    "size": 2048  },  "names": [    {      "C": "CN",      "ST": "BeiJing",      "L": "BeiJing",      "O": "system:masters",      "OU": "System"    }  ]}
```

3.生成 admin 证书和私钥：

```shell
[root@node-01 ssl]# cfssl gencert -ca=/data/kubernetes/ssl/ca.pem \   -ca-key=/data/kubernetes/ssl/ca-key.pem \   -config=/data/kubernetes/ssl/ca-config.json \   -profile=kubernetes admin-csr.json | cfssljson -bare admin[root@node-01 ssl]# ls -l admin*-rw-r--r-- 1 root root 1009 Dec 25 11:26 admin.csr-rw-r--r-- 1 root root  229 Dec 25 11:24 admin-csr.json-rw------- 1 root root 1679 Dec 25 11:26 admin-key.pem-rw-r--r-- 1 root root 1399 Dec 25 11:26 admin.pem[root@node-01 ssl]# cp admin*.pem /data/kubernetes/ssl/
```

4.设置集群参数

```html
[root@node-01 src]# kubectl config set-cluster kubernetes \   --certificate-authority=/data/kubernetes/ssl/ca.pem \   --embed-certs=true \   --server=https://10.199.10.230:6443Cluster "kubernetes" set.
```

5.设置客户端认证参数

```
[root@node-01 ssl]# kubectl config set-credentials admin \   --client-certificate=/data/kubernetes/ssl/admin.pem \   --embed-certs=true \   --client-key=/data/kubernetes/ssl/admin-key.pemUser "admin" set.
```

6.设置上下文参数

```html
[root@node-01 ssl]# kubectl config set-context kubernetes \   --cluster=kubernetes \   --user=adminContext "kubernetes" created.
```

7.设置默认上下文

```html
[root@node-01 src]# kubectl config use-context kubernetesSwitched to context "kubernetes".
```

8.使用kubectl工具

```html
[root@node-01 ssl]# kubectl get csNAME                 STATUS    MESSAGE              ERRORscheduler            Healthy   ok                   controller-manager   Healthy   ok                   etcd-1               Healthy   {"health": "true"}   etcd-0               Healthy   {"health": "true"}   etcd-2               Healthy   {"health": "true"}   
```



# 集群Node节点部署

node只需安装kubelet服务，所有节点都需要安装kube-proxy

## 部署kubelet

1.二进制包准备
将软件包从复制到所有node中去。

```shell
[root@node-01 ~]# cd /usr/local/src/kubernetes/server/bin/[root@node-01 bin]# for n in `seq 231 236`;do scp kubelet 10.199.10.$n:/data/kubernetes/bin/ ;done[root@node-01 bin]# for n in `seq 231 236`;do scp  kube-proxy 10.199.10.$n:/data/kubernetes/bin/ ;done
```

2.创建角色绑定

```html
kubectl create clusterrolebinding kubelet-bootstrap --clusterrole=system:node-bootstrapper --user=kubelet-bootstrap
```

3.创建 kubelet bootstrapping kubeconfig 文件

设置集群参数

```html
KUBE_APISERVER="https://10.199.10.230:6443" # apiserver IP:PORTTOKEN="9e4941d5a57004f2c92e40214dc70302" # 与token.csv里保持一致kubectl config set-cluster kubernetes \  --certificate-authority=/data/kubernetes/ssl/ca.pem \  --embed-certs=true \  --server=${KUBE_APISERVER} \  --kubeconfig=bootstrap.kubeconfig
```

设置客户端认证参数,token要使用之前那个

```html
kubectl config set-credentials "kubelet-bootstrap" \  --token=${TOKEN} \  --kubeconfig=bootstrap.kubeconfig
```

设置上下文参数

```html
kubectl config set-context default \  --cluster=kubernetes \  --user="kubelet-bootstrap" \  --kubeconfig=bootstrap.kubeconfig
```

选择默认上下文

```html
kubectl config use-context default --kubeconfig=bootstrap.kubeconfig#拷贝到3个node节点for n in `seq 231 236`;do scp bootstrap.kubeconfig 10.199.10.$n:/data/kubernetes/cfg/;done
```

部署kubelet(node节点)

1.设置CNI支持(所有节点)

```html
mkdir -p /etc/cni/net.dcat >>/etc/cni/net.d/10-default.conf<<EOF{        "name": "flannel",        "type": "flannel",        "delegate": {            "bridge": "docker0",            "isDefaultGateway": true,            "mtu": 1400        }}EOF
```

2.创建kubelet目录

```html
[root@node-04 ~]# mkdir /var/lib/kubelet
```

3.创建kubelet服务配置

```html
cat <<EOF | sudo tee /etc/docker/daemon.json{  "exec-opts": ["native.cgroupdriver=systemd"],  "log-driver": "json-file",  "log-opts": {    "max-size": "100m"  },  "storage-driver": "overlay2",  "storage-opts": [    "overlay2.override_kernel_check=true"  ]}EOFsystemctl restart dockercat > /data/kubernetes/cfg/kubelet.conf << EOFKUBELET_OPTS="--logtostderr=false \\--v=2 \\--log-dir=/data/kubernetes/logs \\--hostname-override=node-01 \\--network-plugin=cni \\--kubeconfig=/data/kubernetes/cfg/kubelet.kubeconfig \\--bootstrap-kubeconfig=/data/kubernetes/cfg/bootstrap.kubeconfig \\--config=/data/kubernetes/cfg/kubelet-config.yml \\--cert-dir=/data/kubernetes/ssl \\--pod-infra-container-image=registry.aliyuncs.com/google_containers/pause:3.2"EOFcat > /data/kubernetes/cfg/kubelet-config.yml << EOFkind: KubeletConfigurationapiVersion: kubelet.config.k8s.io/v1beta1address: 0.0.0.0port: 10250readOnlyPort: 10255cgroupDriver: systemdclusterDNS:- 10.1.0.2clusterDomain: cluster.local failSwapOn: falseauthentication:  anonymous:    enabled: false  webhook:    cacheTTL: 2m0s    enabled: true  x509:    clientCAFile: /data/kubernetes/ssl/ca.pem authorization:  mode: Webhook  webhook:    cacheAuthorizedTTL: 5m0s    cacheUnauthorizedTTL: 30sevictionHard:  imagefs.available: 15%  memory.available: 100Mi  nodefs.available: 10%  nodefs.inodesFree: 5%maxOpenFiles: 1000000maxPods: 110EOFcat > /usr/lib/systemd/system/kubelet.service << EOF[Unit]Description=Kubernetes KubeletAfter=docker.service [Service]EnvironmentFile=/data/kubernetes/cfg/kubelet.confExecStart=/data/kubernetes/bin/kubelet \$KUBELET_OPTSRestart=on-failureLimitNOFILE=65536 [Install]WantedBy=multi-user.targetEOF
```

4.启动Kubelet

```html
systemctl daemon-reloadsystemctl enable kubeletsystemctl start kubelet
```

5.查看服务状态

```html
systemctl status kubelet
```

6.查看csr请求

注意是在linux-node1上执行。

```html
[root@node-01 ssl]# kubectl get csrNAME                                                   AGE       REQUESTOR           CONDITIONnode-csr-NqH7J1OuDM_jGtQM_VuABiBcAqgDlT_MfJiVS_qWCbg   1m        kubelet-bootstrap   Pendingnode-csr-jy10bYvow5hYQ2sKWfCuBlUNIPit54dhQfzRUd5E6dc   4m        kubelet-bootstrap   Pendingnode-csr-zPPE5g4d1PtbKo-lQWNNC0bbngttC2bdZtwqBBvjrVM   1m        kubelet-bootstrap   Pending
```

7.批准kubelet 的 TLS 证书请求

```html
[root@node-01 ~]# kubectl get csr|grep 'Pending' | awk 'NR>0{print $1}'| xargs kubectl certificate approve
```

执行完毕后，查看节点状态已经是Ready的状态了

```html
[root@node-01 ~]# kubectl get csrNAME                                                   AGE       REQUESTOR           CONDITIONnode-csr-NqH7J1OuDM_jGtQM_VuABiBcAqgDlT_MfJiVS_qWCbg   1m        kubelet-bootstrap   Approved,Issuednode-csr-jy10bYvow5hYQ2sKWfCuBlUNIPit54dhQfzRUd5E6dc   5m        kubelet-bootstrap   Approved,Issuednode-csr-zPPE5g4d1PtbKo-lQWNNC0bbngttC2bdZtwqBBvjrVM   2m        kubelet-bootstrap   Approved,Issuedkubectl get nodes
```

## 部署Kubernetes Proxy

kube-proxy master和node节点都安装

1.配置kube-proxy使用LVS

```html
[root@node-01 ~]# yum install -y ipvsadm ipset conntrack
```

2.创建 kube-proxy 证书请求

```html
[root@node-01 ssl]# cd /usr/local/src/ssl/[root@node-01 ssl]# vim kube-proxy-csr.json{  "CN": "system:kube-proxy",  "hosts": [],  "key": {    "algo": "rsa",    "size": 2048  },  "names": [    {      "C": "CN",      "ST": "BeiJing",      "L": "BeiJing",      "O": "k8s",      "OU": "System"    }  ]}
```

3.生成证书

```html
[root@node-01 ssl]# cfssl gencert -ca=/data/kubernetes/ssl/ca.pem \   -ca-key=/data/kubernetes/ssl/ca-key.pem \   -config=/data/kubernetes/ssl/ca-config.json \   -profile=kubernetes  kube-proxy-csr.json | cfssljson -bare kube-proxy
```

4.分发证书到所有node节点

```html
[root@node-01 ssl]# for n in `seq 231 236`;do scp kube-proxy*.pem root@10.199.10.$n:/data/kubernetes/ssl;done
```

5.创建kube-proxy配置文件

```html
kubectl config set-cluster kubernetes \   --certificate-authority=/data/kubernetes/ssl/ca.pem \   --embed-certs=true \   --server=https://10.199.10.230:6443 \   --kubeconfig=kube-proxy.kubeconfigkubectl config set-credentials kube-proxy \   --client-certificate=/data/kubernetes/ssl/kube-proxy.pem \   --client-key=/data/kubernetes/ssl/kube-proxy-key.pem \   --embed-certs=true \   --kubeconfig=kube-proxy.kubeconfigkubectl config set-context default \   --cluster=kubernetes \   --user=kube-proxy \   --kubeconfig=kube-proxy.kubeconfigkubectl config use-context default --kubeconfig=kube-proxy.kubeconfig
```

6.分发kubeconfig配置文件

```html
[root@node-01 ssl]# for n in `seq 231 236 `;do scp kube-proxy.kubeconfig 10.199.10.$n:/data/kubernetes/cfg/;done   
```

7.创建kube-proxy服务配置

```html
cat > /data/kubernetes/cfg/kube-proxy.conf << EOFKUBE_PROXY_OPTS="--logtostderr=false \\--v=2 \\--log-dir=/data/kubernetes/logs \\--config=/data/kubernetes/cfg/kube-proxy-config.yml"EOFcat > /data/kubernetes/cfg/kube-proxy-config.yml << EOFkind: KubeProxyConfigurationapiVersion: kubeproxy.config.k8s.io/v1alpha1bindAddress: 0.0.0.0metricsBindAddress: 0.0.0.0:10249clientConnection:  kubeconfig: /data/kubernetes/cfg/kube-proxy.kubeconfighostnameOverride: node-01clusterCIDR: 10.0.0.0/24EOFcat > /usr/lib/systemd/system/kube-proxy.service << EOF[Unit]Description=Kubernetes ProxyAfter=network.target [Service]EnvironmentFile=/data/kubernetes/cfg/kube-proxy.confExecStart=/data/kubernetes/bin/kube-proxy \$KUBE_PROXY_OPTSRestart=on-failureLimitNOFILE=65536 [Install]WantedBy=multi-user.targetEOF
```

8.启动Kubernetes Proxy

```
systemctl daemon-reloadsystemctl enable kube-proxysystemctl start kube-proxy
```

9.查看服务状态
查看kube-proxy服务状态

```html
systemctl status kube-proxy检查LVS状态[root@node-04 ~]# ipvsadm -L -nIP Virtual Server version 1.2.1 (size=4096)Prot LocalAddress:Port Scheduler Flags  -> RemoteAddress:Port           Forward Weight ActiveConn InActConnTCP  10.1.0.1:443 rr  -> 10.199.10.231:6443            Masq    1      0          0  
```

如果都安装了kubelet和proxy服务，使用下面的命令可以检查状态：

```html
[root@node-01 ~]# kubectl get nodeNAME           STATUS    ROLES     AGE       VERSION10.199.10.234   Ready     <none>    40m       v1.11.510.199.10.235   Ready     <none>    40m       v1.11.510.199.10.236   Ready     <none>    40m       v1.11.5
```

# Flannel网络部署

Flannel 需要在所有的master和node都部署

1.为Flannel生成证书

```html
[root@node-01 ssl]# vim flanneld-csr.json{  "CN": "flanneld",  "hosts": [],  "key": {    "algo": "rsa",    "size": 2048  },  "names": [    {      "C": "CN",      "ST": "BeiJing",      "L": "BeiJing",      "O": "k8s",      "OU": "System"    }  ]}
```

2.生成证书

```html
[root@node-01 ssl]# cfssl gencert -ca=/data/kubernetes/ssl/ca.pem \   -ca-key=/data/kubernetes/ssl/ca-key.pem \   -config=/data/kubernetes/ssl/ca-config.json \   -profile=kubernetes flanneld-csr.json | cfssljson -bare flanneld
```

3.分发证书

```html
[root@node-01 ssl]# for n in `seq 231 236`; do scp flanneld*.pem 10.199.10.$n:/data/kubernetes/ssl/;done
```

4.下载Flannel软件包

```html
[root@node-01 k8s]#wget https://github.com/coreos/flannel/releases/download/v0.10.0/flannel-v0.10.0-linux-amd64.tar.gz[root@node-01 k8s]# tar zxf flannel-v0.10.0-linux-amd64.tar.gz[root@node-01 k8s]# for n in `seq 231 236`;do scp flanneld mk-docker-opts.sh 10.199.10.$n:/data/kubernetes/bin/;done复制对应脚本到/data/kubernetes/bin目录下。vi remove-docker0.sh#!/usr/bin/env bashset -erc=0ip link show docker0 >/dev/null 2>&1 || rc="$?"if [[ "$rc" -eq "0" ]]; then  ip link set dev docker0 down  ip link delete docker0fichmod +x remove-docker0.sh[root@node-01 k8s]# for n in `seq 231 236`;do scp remove-docker0.sh 10.199.10.$n:/data/kubernetes/bin/;done    
```

5.配置Flannel

```html
[root@node-04 ssl]# vim /data/kubernetes/cfg/flannelFLANNEL_ETCD="-etcd-endpoints=https://10.199.10.231:2379,https://10.199.10.232:2379,https://10.199.10.233:2379"FLANNEL_ETCD_KEY="-etcd-prefix=/kubernetes/network"FLANNEL_ETCD_CAFILE="--etcd-cafile=/data/kubernetes/ssl/ca.pem"FLANNEL_ETCD_CERTFILE="--etcd-certfile=/data/kubernetes/ssl/flanneld.pem"FLANNEL_ETCD_KEYFILE="--etcd-keyfile=/data/kubernetes/ssl/flanneld-key.pem"复制配置到其它节点上[root@node-01 ~]# for n in `seq 231 236`;do scp /data/kubernetes/cfg/flannel 10.199.10.$n:/data/kubernetes/cfg/;done
```

6.设置Flannel系统服务

```html
[root@node-01 ~]# vim /usr/lib/systemd/system/flannel.service[Unit]Description=Flanneld overlay address etcd agentAfter=network.targetBefore=docker.service[Service]EnvironmentFile=-/data/kubernetes/cfg/flannelExecStartPre=/data/kubernetes/bin/remove-docker0.shExecStart=/data/kubernetes/bin/flanneld ${FLANNEL_ETCD} ${FLANNEL_ETCD_KEY} ${FLANNEL_ETCD_CAFILE} ${FLANNEL_ETCD_CERTFILE} ${FLANNEL_ETCD_KEYFILE}ExecStartPost=/data/kubernetes/bin/mk-docker-opts.sh -d /run/flannel/dockerType=notify[Install]WantedBy=multi-user.targetRequiredBy=docker.service复制系统服务脚本到其它节点上[root@node-01 k8s]# for n in `seq 231 236`;do scp /usr/lib/systemd/system/flannel.service 10.199.10.$n:/usr/lib/systemd/system/flannel.service;done
```

## Flannel CNI集成

下载CNI插件

```html
[root@node-01 ~]# wget https://github.com/containernetworking/plugins/releases/download/v0.7.1/cni-plugins-amd64-v0.7.1.tgz[root@node-01 ~]# mkdir /data/kubernetes/bin/cni[root@node-01 src]# tar zxf cni-plugins-amd64-v0.7.1.tgz -C /data/kubernetes/bin/cni[root@node-01 k8s]# for n in `seq 231 236`;do scp /data/kubernetes/bin/cni/* 10.199.10.$n:/data/kubernetes/bin/cni/;done     
```

创建Etcd的key

```html
[root@node-01 ~]# /data/kubernetes/bin/etcdctl --ca-file /data/kubernetes/ssl/ca.pem --cert-file /data/kubernetes/ssl/flanneld.pem --key-file /data/kubernetes/ssl/flanneld-key.pem \      --no-sync -C https://10.199.10.231:2379,https://10.199.10.232:2379,https://10.199.10.233:2379 \mk /kubernetes/network/config '{ "Network": "10.1.0.0/16", "Backend": { "Type": "vxlan", "VNI": 1 }}' >/dev/null 2>&1
```

启动flannel

```html
systemctl daemon-reloadsystemctl enable flannelsystemctl restart flannel
```

查看服务状态

```html
systemctl status flannel
```

## 配置Docker使用Flannel

```html
[root@node-01 ~]# vim /usr/lib/systemd/system/docker.service[Unit] #在Unit下面修改After和增加RequiresAfter=network-online.target firewalld.service flannel.serviceWants=network-online.targetRequires=flannel.service[Service] #增加EnvironmentFile=-/run/flannel/dockerType=notifyEnvironmentFile=-/run/flannel/dockerExecStart=/usr/bin/dockerd $DOCKER_OPTS
```

将配置复制到其它所有的node

```html
[root@node-01 k8s]# for n in `seq 231 236`;do scp /usr/lib/systemd/system/docker.service 10.199.10.$n:/usr/lib/systemd/system/docker.service;done
```

重启Docker

```html
systemctl daemon-reloadsystemctl restart docker
```

再查看各个节点会发现docker0网卡和flannel网卡的ip地址都是我们上面配置的网段了。

```html
[root@node-01 k8s]# ifconfig docker0: flags=4099<UP,BROADCAST,MULTICAST>  mtu 1500        inet 10.2.84.1  netmask 255.255.255.0  broadcast 10.2.84.255        ether 02:42:5e:c6:0c:aa  txqueuelen 0  (Ethernet)        RX packets 0  bytes 0 (0.0 B)        RX errors 0  dropped 0  overruns 0  frame 0        TX packets 0  bytes 0 (0.0 B)        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0        flannel.1: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1450        inet 10.2.84.0  netmask 255.255.255.255  broadcast 0.0.0.0        inet6 fe80::8ccc:15ff:fedd:c00d  prefixlen 64  scopeid 0x20<link>        ether 8e:cc:15:dd:c0:0d  txqueuelen 0  (Ethernet)        RX packets 0  bytes 0 (0.0 B)        RX errors 0  dropped 0  overruns 0  frame 0        TX packets 0  bytes 0 (0.0 B)        TX errors 0  dropped 8 overruns 0  carrier 0  collisions 0
```



# CoreDNS、Dashboard、Ingress部署

## 创建CoreDNS

 

- kubernetes内部的服务发现以及pod之间的域名解析服务都是通过dns来实现，所以DNS对kubernets集群来说非常重要。目前dns有2种，一种是kube dns，一种是core dns，本次我们安装的是Coredns。

```
cat >  coredns.yaml << "EOF"apiVersion: v1kind: ServiceAccountmetadata:  name: coredns  namespace: kube-system---apiVersion: rbac.authorization.k8s.io/v1kind: ClusterRolemetadata:  labels:    kubernetes.io/bootstrapping: rbac-defaults  name: system:corednsrules:  - apiGroups:    - ""    resources:    - endpoints    - services    - pods    - namespaces    verbs:    - list    - watch  - apiGroups:    - discovery.k8s.io    resources:    - endpointslices    verbs:    - list    - watch---apiVersion: rbac.authorization.k8s.io/v1kind: ClusterRoleBindingmetadata:  annotations:    rbac.authorization.kubernetes.io/autoupdate: "true"  labels:    kubernetes.io/bootstrapping: rbac-defaults  name: system:corednsroleRef:  apiGroup: rbac.authorization.k8s.io  kind: ClusterRole  name: system:corednssubjects:- kind: ServiceAccount  name: coredns  namespace: kube-system---apiVersion: v1kind: ConfigMapmetadata:  name: coredns  namespace: kube-systemdata:  Corefile: |    .:53 {        errors        health {          lameduck 5s        }        ready        kubernetes cluster.local  in-addr.arpa ip6.arpa {          fallthrough in-addr.arpa ip6.arpa        }        prometheus :9153        forward . /etc/resolv.conf {          max_concurrent 1000        }        cache 30        loop        reload        loadbalance    }---apiVersion: apps/v1kind: Deploymentmetadata:  name: coredns  namespace: kube-system  labels:    k8s-app: kube-dns    kubernetes.io/name: "CoreDNS"spec:  # replicas: not specified here:  # 1. Default is 1.  # 2. Will be tuned in real time if DNS horizontal auto-scaling is turned on.  strategy:    type: RollingUpdate    rollingUpdate:      maxUnavailable: 1  selector:    matchLabels:      k8s-app: kube-dns  template:    metadata:      labels:        k8s-app: kube-dns    spec:      priorityClassName: system-cluster-critical      serviceAccountName: coredns      tolerations:        - key: "CriticalAddonsOnly"          operator: "Exists"      nodeSelector:        kubernetes.io/os: linux      affinity:         podAntiAffinity:           preferredDuringSchedulingIgnoredDuringExecution:           - weight: 100             podAffinityTerm:               labelSelector:                 matchExpressions:                   - key: k8s-app                     operator: In                     values: ["kube-dns"]               topologyKey: kubernetes.io/hostname      containers:      - name: coredns        image: coredns/coredns:1.8.4        imagePullPolicy: IfNotPresent        resources:          limits:            memory: 170Mi          requests:            cpu: 100m            memory: 70Mi        args: [ "-conf", "/etc/coredns/Corefile" ]        volumeMounts:        - name: config-volume          mountPath: /etc/coredns          readOnly: true        ports:        - containerPort: 53          name: dns          protocol: UDP        - containerPort: 53          name: dns-tcp          protocol: TCP        - containerPort: 9153          name: metrics          protocol: TCP        securityContext:          allowPrivilegeEscalation: false          capabilities:            add:            - NET_BIND_SERVICE            drop:            - all          readOnlyRootFilesystem: true        livenessProbe:          httpGet:            path: /health            port: 8080            scheme: HTTP          initialDelaySeconds: 60          timeoutSeconds: 5          successThreshold: 1          failureThreshold: 5        readinessProbe:          httpGet:            path: /ready            port: 8181            scheme: HTTP      dnsPolicy: Default      volumes:        - name: config-volume          configMap:            name: coredns            items:            - key: Corefile              path: Corefile---apiVersion: v1kind: Servicemetadata:  name: kube-dns  namespace: kube-system  annotations:    prometheus.io/port: "9153"    prometheus.io/scrape: "true"  labels:    k8s-app: kube-dns    kubernetes.io/cluster-service: "true"    kubernetes.io/name: "CoreDNS"spec:  selector:    k8s-app: kube-dns  clusterIP: 10.1.0.2  ports:  - name: dns    port: 53    protocol: UDP  - name: dns-tcp    port: 53    protocol: TCP  - name: metrics    port: 9153    protocol: TCP EOF[root@node-01 k8s]# kubectl create -f coredns.yaml serviceaccount/coredns createdclusterrole.rbac.authorization.k8s.io/system:coredns createdclusterrolebinding.rbac.authorization.k8s.io/system:coredns createdconfigmap/coredns createddeployment.extensions/coredns createdservice/coredns created[root@node-01 yaml]# kubectl get pod -n kube-system NAME                       READY     STATUS    RESTARTS   AGEcoredns-5f94b495b5-58t47   1/1       Running   0          6mcoredns-5f94b495b5-wvcsg   1/1       Running   0          6m
```

然后我们就可以随便进入一个pod，去ping域名看dns是否可以正常解析。

```html
cat >  nginx.yaml  << "EOF"---apiVersion: v1kind: ReplicationControllermetadata:  name: nginx-controllerspec:  replicas: 2  selector:    name: nginx  template:    metadata:      labels:        name: nginx    spec:      containers:        - name: nginx          image: nginx:1.19.6          ports:            - containerPort: 80---apiVersion: v1kind: Servicemetadata:  name: nginx-service-nodeportspec:  ports:    - port: 80      targetPort: 80      nodePort: 30001      protocol: TCP  type: NodePort  selector:    name: nginxEOFkubectl apply -f nginx.yamlkubectl get svckubectl get pods -o wide[root@node-01 yaml]# kubectl get podNAME                     READY     STATUS    RESTARTS   AGEtomcat-7666b9764-mfgpb   1/1       Running   0          11h[root@node-01 yaml]# kubectl exec -it tomcat-7666b9764-mfgpb -- /bin/sh# ping baidu.comPING baidu.com (220.181.57.216) 56(84) bytes of data.64 bytes from 220.181.57.216 (220.181.57.216): icmp_seq=1 ttl=54 time=37.2 ms64 bytes from 220.181.57.216 (220.181.57.216): icmp_seq=2 ttl=54 time=37.0 ms64 bytes from 220.181.57.216 (220.181.57.216): icmp_seq=3 ttl=54 time=36.6 ms64 bytes from 220.181.57.216 (220.181.57.216): icmp_seq=4 ttl=54 time=37.9 ms^C--- baidu.com ping statistics ---4 packets transmitted, 4 received, 0% packet loss, time 3000msrtt min/avg/max/mdev = 36.629/37.230/37.958/0.498 ms
```

## 创建Dashboard

```html
wget https://raw.githubusercontent.com/kubernetes/dashboard/v2.0.0-beta8/aio/deploy/recommended.yaml增加 nodePort: 30003  type: NodePortvi recommended.yamlspec:  ports:    - port: 443      targetPort: 8443      nodePort: 30001  type: NodePort  selector:    k8s-app: kubernetes-dashboardkubectl apply -f recommended.yaml[root@node-01 yaml]# kubectl cluster-infoKubernetes master is running at https://10.199.10.230:6443CoreDNS is running at https://10.199.10.230:6443/api/v1/namespaces/kube-system/services/coredns:dns/proxykubernetes-dashboard is running at https://10.199.10.230:6443/api/v1/namespaces/kube-system/services/https:kubernetes-dashboard:/proxyTo further debug and diagnose cluster problems, use 'kubectl cluster-info dump'.
```

## 访问Dashboard

```
https://10.199.10.230:6443/api/v1/namespaces/kube-system/services/https:kubernetes-dashboard:/proxy用户名:admin 密码：admin 选择令牌模式登录。
```

### 获取Token

```html
kubectl -n kube-system describe secret $(kubectl -n kube-system get secret | grep admin-user | awk '{print $1}')
```

操作完以上步骤就可以看到dashboard了。

## Ingress部署

- Kubernetes中，Service资源和Pod资源的IP地址仅能用于集群网络内部的通信，所有的网络流量都无法穿透边界路由器（Edge Router）以实 现集群内外通信。尽管可以为Service使用NodePort或LoadBalancer类型通过节点引入外部流量，但它依然是4层流量转发，可用的负载均衡器也 为传输层负载均衡机制。
- Ingress是Kubernetes API的标准资源类型之一，它其实就是一组基于DNS名称（host）或URL路径把请求转发至指定的Service资源的规则， 用于将集群外部的请求流量转发至集群内部完成服务发布。然而，Ingress资源自身并不能进行“流量穿透”，它仅是一组路由规则的集合，这些 规则要想真正发挥作用还需要其他功能的辅助，如监听某套接字，然后根据这些规则的匹配机制路由请求流量。这种能够为Ingress资源监听套 接字并转发流量的组件称为Ingress控制器（Ingress Controller）。

- Ingress控制器可以由任何具有反向代理（HTTP/HTTPS）功能的服务程序实现，如Nginx、Envoy、HAProxy、Vulcand和Traefik等。Ingress 控制器自身也是运行于集群中的Pod资源对象，它与被代理的运行为Pod资源的应用运行于同一网络中，如上图中ingress-nginx与pod1、pod3等 的关系所示。
- 另一方面，使用Ingress资源进行流量分发时，Ingress控制器可基于某Ingress资源定义的规则将客户端的请求流量直接转发至与Service对应 的后端Pod资源之上，这种转发机制会绕过Service资源，从而省去了由kube-proxy实现的端口代理开销。如上图所示，Ingress规则需要由一个 Service资源对象辅助识别相关的所有Pod对象，但ingress-nginx控制器可经由api.ilinux.io规则的定义直接将请求流量调度至pod3或pod4，而无须 经由Service对象API的再次转发，WAP相关规则的作用方式与此类同。
- **首先需要说明的是此次我们部署的是v0.21.0版本的ingress，在最新的v0.21.0版本历没有了default backend。**

### 创建Ingress Controller

可以下载官方的`mandatory.yaml`到本地安装

```html
[root@node-01 ingress]# kubectl create -f mandatory.yaml 
```

或者

```html
kubectl apply -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/master/deploy/mandatory.yaml
```

由于官方的ingress也只是一个pod并没有对外暴露IP和端口，所以我们需要为ingress创建一个对外暴露的service，暴露nodePort 20080和20443端口。对于想部署在生产环境的，可以单独拿2个node服务器来单独部署ingress controller,然后暴露80和443端口就可以了。

```html
apiVersion: v1kind: Servicemetadata:  name: ingress-nginx  namespace: ingress-nginx  labels:    app.kubernetes.io/name: ingress-nginx    app.kubernetes.io/part-of: ingress-nginxspec:  type: NodePort  ports:    - name: http      nodePort: 20080      port: 80      targetPort: 80      protocol: TCP    - name: https      nodePort: 20443      port: 443      targetPort: 443      protocol: TCP  selector:    app.kubernetes.io/name: ingress-nginx    app.kubernetes.io/part-of: ingress-nginx
```

然后在haproxy的backend中加入3个node 的20080和20443端口，然后将`www.cnlinux.club`的`A记录`解析到10.199.10.230

```html
listen ingress-80        bind 10.199.10.230:80        mode tcp        balance roundrobin        timeout server 15s        timeout connect 15s        server apiserver01 10.199.10.234:20080 check port 20080 inter 5000 fall 5        server apiserver02 10.199.10.235:20080 check port 20080 inter 5000 fall 5        server apiserver03 10.199.10.236:20080 check port 20080 inter 5000 fall 5listen ingress-443        bind 10.199.10.230:443        mode tcp        balance roundrobin        timeout server 15s        timeout connect 15s        server apiserver01 10.199.10.234:20443 check port 20443 inter 5000 fall 5        server apiserver02 10.199.10.235:20443 check port 20443 inter 5000 fall 5        server apiserver03 10.199.10.236:20443 check port 20443 inter 5000 fall 5
```

### 创建测试的tomcat demo

```html
[root@node-01 yaml]# kubectl create -f tomcat-demo.yaml apiVersion: apps/v1kind: Deploymentmetadata:  name: tomcat  labels:    app: tomcatspec:  replicas: 1  selector:    matchLabels:      app: tomcat  template:     metadata:      labels:        app: tomcat    spec:      containers:      - name: tomcat        image: tomcat:latest        ports:        - containerPort: 8080---apiVersion: v1kind: Servicemetadata:  name: tomcatspec:  selector:    app: tomcat  ports:  - name: tomcat    protocol: TCP    port: 8080    targetPort: 8080  type: ClusterIP 
```

### 创建ingress

```html
apiVersion: extensions/v1beta1kind: Ingressmetadata:  name: tomcat  annotations:    nginx.ingress.kubernetes.io/rewrite-target: /    kubernetes.io/ingress.class: nginxspec:  rules:    - host: www.cnlinux.club      http:        paths:          - path:             backend:              serviceName: tomcat              servicePort: 8080
```

至此ingress就已创建完成。在浏览器打开www.cnlinux.club 就可以看到tomcat的页面。



卸载集群

```
systemctl stop kube-proxy && systemctl disable kube-proxysystemctl stop kube-scheduler && systemctl disable kube-schedulersystemctl stop kubelet && systemctl disable kubeletsystemctl stop etcd && systemctl disable etcdsystemctl stop kube-apiserver && systemctl disable kube-apiserversystemctl stop kube-controller-manager && systemctl disable kube-controller-managersystemctl stop kubeletsystemctl stop dockerrm -rf /var/lib/cni/rm -rf /var/lib/kubelet/*rm -rf /etc/cni/# 删除遗留的网络接口ip a | grep -E 'docker|flannel|cni'ip link del docker0ip link del flannel.1ip link del cni0systemctl restart docker
```



