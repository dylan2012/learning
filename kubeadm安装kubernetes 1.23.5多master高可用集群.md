# kubeadm安装kubernetes 1.23.5多master高可用集群

## 1. 简介

Kubernetes v1.13版本发布后，kubeadm才正式进入GA，可以生产使用,用kubeadm部署kubernetes集群也是以后的发展趋势。目前Kubernetes的对应镜像仓库，在国内阿里云也有了镜像站点，使用kubeadm部署Kubernetes集群变得简单并且容易了很多，本文使用kubeadm带领大家快速部署Kubernetes v1.23.5版本。

注意：请不要把目光仅仅放在部署上，如果你是新手，推荐先熟悉用二进制文件部署后，再来学习用kubeadm部署。二进制文件部署请查看我博客的其他文章。

## 2. 架构信息

```html
系统版本：CentOS 7.9 x64
内核：3.10.0-1160.42.2.el7.x86_64
Kubernetes: v1.23.5
Docker-ce: 20.10.8
推荐硬件配置：4核4G

Keepalived保证apiserever服务器的IP高可用
Haproxy实现apiserver的负载均衡
```

为了减少服务器数量，haproxy、keepalived配置在node-01和node-02。

| 节点名称    | 角色   | IP            | 安装软件                                               |
| ----------- | ------ | ------------- | ------------------------------------------------------ |
| 负载VIP     | VIP    | 10.199.10.230 |                                                        |
| node-01     | master | 10.199.10.231 | kubeadm、kubelet、kubectl、docker、haproxy、keepalived |
| node-02     | master | 10.199.10.232 | kubeadm、kubelet、kubectl、docker、haproxy、keepalived |
| node-03     | master | 10.199.10.233 | kubeadm、kubelet、kubectl、docker                      |
| node-04     | node   | 10.199.10.234 | kubeadm、kubelet、kubectl、docker                      |
| node-05     | node   | 10.199.10.235 | kubeadm、kubelet、kubectl、docker                      |
| node-06     | node   | 10.199.10.236 | kubeadm、kubelet、kubectl、docker                      |
| service网段 |        | 10.245.0.0/16 |                                                        |

## 3.部署前准备工作

### 1) 关闭selinux和防火墙

```html
sed -ri 's#(SELINUX=).*#\1disabled#' /etc/selinux/config
setenforce 0
systemctl disable firewalld
systemctl stop firewalld
#安装 iptables
yum install iptables-services -y
#禁用 iptables
service iptables stop && systemctl disable iptables
#清空防火墙规则
iptables -F
```

### 2) 关闭swap

```html
swapoff -a
把关于swap的行前面加#注释掉
vim /etc/fstab
```

### 3) 为每台服务器添加host解析记录

```html
cat >>/etc/hosts<<EOF
10.199.10.230 k8s-vip
10.199.10.231 node-01
10.199.10.232 node-02
10.199.10.233 node-03
10.199.10.234 node-04
10.199.10.235 node-05
10.199.10.236 node-06
EOF
```

### 4) 创建并分发密钥

在node-01创建ssh密钥。

```html
[root@node-01 ~]# ssh-keygen -t rsa
Generating public/private rsa key pair.
Enter file in which to save the key (/root/.ssh/id_rsa): 
Created directory '/root/.ssh'.
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in /root/.ssh/id_rsa.
Your public key has been saved in /root/.ssh/id_rsa.pub.
The key fingerprint is:
SHA256:26z6DcUarn7wP70dqOZA28td+K/erv7NlaJPLVE1BTA root@node-01
The key's randomart image is:
+---[RSA 2048]----+
|            E..o+|
|             .  o|
|               . |
|         .    .  |
|        S o  .   |
|      .o X   oo .|
|       oB +.o+oo.|
|       .o*o+++o+o|
|     .++o+Bo+=B*B|
+----[SHA256]-----+
```

分发node-01的公钥，用于免密登录其他服务器

```html
for n in `seq -w 31 36`;do ssh-copy-id node-$n;done
```

### 5) 配置内核参数

```html
modprobe br_netfilter
echo "modprobe br_netfilter" >> /etc/profile

cat <<EOF >  /etc/sysctl.d/k8s.conf
net.bridge.bridge-nf-call-ip6tables = 1
net.bridge.bridge-nf-call-iptables = 1
net.ipv4.ip_nonlocal_bind = 1
net.ipv4.ip_forward = 1
vm.swappiness=0
EOF

sysctl -p /etc/sysctl.d/k8s.conf
#sysctl --system
```

### 6) 加载ipvs模块

```shell
cat > /etc/sysconfig/modules/ipvs.modules <<EOF
#!/bin/bash
ipvs_modules="ip_vs ip_vs_lc ip_vs_wlc ip_vs_rr ip_vs_wrr ip_vs_lblc ip_vs_lblcr ip_vs_dh ip_vs_sh ip_vs_nq ip_vs_sed ip_vs_ftp nf_conntrack nf_conntrack_ipv4"
for kernel_module in ${ipvs_modules}; do
 /sbin/modinfo -F filename ${kernel_module} > /dev/null 2>&1
 if [ 0 -eq 0 ]; then
 /sbin/modprobe ${kernel_module}
 fi
done
EOF
chmod 755 /etc/sysconfig/modules/ipvs.modules && bash /etc/sysconfig/modules/ipvs.modules && lsmod | grep -e ip_vs -e nf_conntrack_ipv4
```

### 7) 添加yum源

```html
cat << EOF > /etc/yum.repos.d/kubernetes.repo
[kubernetes]
name=Kubernetes
baseurl=https://mirrors.aliyun.com/kubernetes/yum/repos/kubernetes-el7-x86_64/
enabled=1
gpgcheck=1
repo_gpgcheck=1
gpgkey=https://mirrors.aliyun.com/kubernetes/yum/doc/yum-key.gpg https://mirrors.aliyun.com/kubernetes/yum/doc/rpm-package-key.gpg
EOF

wget http://mirrors.aliyun.com/repo/Centos-7.repo -O /etc/yum.repos.d/CentOS-Base.repo
wget http://mirrors.aliyun.com/repo/epel-7.repo -O /etc/yum.repos.d/epel.repo 
wget https://mirrors.aliyun.com/docker-ce/linux/centos/docker-ce.repo -O /etc/yum.repos.d/docker-ce.repo

#时间同步
yum install ntpdate -y
ntpdate cn.pool.ntp.org
#时间同步计划任务
crontab -e
* */1 * * * /usr/sbin/ntpdate cn.pool.ntp.org

service crond restart
#安装基础软件包
yum update -y
yum install -y yum-utils device-mapper-persistent-data lvm2
wget net-tools nfs-utils lrzsz gcc gcc-c++ make cmake libxml2-devel openssl-devel curl
curl-devel unzip sudo ntp libaio-devel wget vim ncurses-devel autoconf automake zlibdevel python-devel epel-release openssh-server socat ipvsadm conntrack ntpdate telnet
ipvsadm
```

## 4. 部署keepalived和haproxy

### 1) 安装keepalived和haproxy

在node-01和node-02安装keepalived和haproxy

```html
yum install -y keepalived haproxy
```

### 2) 修改配置

**keepalived配置**

node-01的`priority`为100，node-02的router_id为LVS_2、state为BACKUP、`priority`为90，其他配置一样。

```html
[root@node-01 ~]# cat /etc/keepalived/keepalived.conf
! Configuration File for keepalived

global_defs {
   notification_email {
        xxxxxx@163.com
   }
   notification_email_from Alexandre.Cassen@firewall.loc
   smtp_server 127.0.0.1
   smtp_connect_timeout 30
   router_id LVS_1
}
                                                     
vrrp_instance VI_1 {
    state MASTER          
    interface eth0
    lvs_sync_daemon_inteface eth0
    virtual_router_id 88
    advert_int 1
    priority 100         
    authentication {
        auth_type PASS
        auth_pass 1111
    }
    virtual_ipaddress {
      10.199.10.230/24
    }
}

```

**haproxy配置**

node-01和node-02的haproxy配置是一样的。此处我们监听的是10.199.10.230的8443端口，因为haproxy是和k8s apiserver是部署在同一台服务器上，都用6443会冲突。

```html
cat /etc/haproxy/haproxy.cfg
global
        chroot  /var/lib/haproxy
        daemon
        group haproxy
        user haproxy
        log 127.0.0.1:514 local0 warning
        pidfile /var/lib/haproxy.pid
        maxconn 20000
        spread-checks 3
        nbproc 8

defaults
        log     global
        mode    tcp
        retries 3
        option redispatch

listen https-apiserver
        bind 10.199.10.230:8443
        mode tcp
        balance roundrobin
        timeout server 900s
        timeout connect 15s

        server apiserver01 10.199.10.231:6443 check port 6443 inter 5000 fall 5
        server apiserver02 10.199.10.232:6443 check port 6443 inter 5000 fall 5
        server apiserver03 10.199.10.233:6443 check port 6443 inter 5000 fall 5
```

### 3) 启动服务

```html
systemctl enable keepalived && systemctl start keepalived 
systemctl enable haproxy && systemctl start haproxy 
```

## 5. 部署kubernetes

### 1) 安装软件

由于kubeadm对Docker的版本是有要求的，需要安装与kubeadm匹配的版本。
由于版本更新频繁，请指定对应的版本号，本文采用1.13.2版本，其它版本未经测试。

```html
yum install -y kubelet-1.23.5 kubeadm-1.23.5 kubectl-1.23.5 ipvsadm ipset docker-ce-20.10.13.ce

#配置 docker 镜像加速器和驱动
vim /etc/docker/daemon.json
{
"registry-mirrors":["https://rsbud4vc.mirror.aliyuncs.com","https://registry.dockercn.com","https://docker.mirrors.ustc.edu.cn","https://dockerhub.azk8s.cn","http://hubmirror.c.163.com","http://qtid6917.mirror.aliyuncs.com",
"https://rncxm540.mirror.aliyuncs.com"],
"exec-opts": ["native.cgroupdriver=systemd"]
}
#修改 docker 文件驱动为 systemd，默认为 cgroupfs， kubelet 默认使用 systemd，两者必须一致才可以。
#启动docker
systemctl daemon-reload
systemctl enable docker && systemctl start docker

#设置kubelet开机自启动
systemctl enable kubelet 
```

### 2) 修改初始化配置

使用kubeadm config print init-defaults > kubeadm-init.yaml 打印出默认配置，然后在根据自己的环境修改配置.

```html
cat <<EOF > ./kubeadm-init.yaml
apiVersion: kubeadm.k8s.io/v1beta2
kind: ClusterConfiguration
kubernetesVersion: v1.23.5
controlPlaneEndpoint: "10.199.10.230:8443"
networking:
  serviceSubnet: "10.96.0.0/16"
  podSubnet: "10.100.0.1/16"
  dnsDomain: "cluster.local"
EOF
```

### 3) 预下载镜像

```html
[root@node-01 ~]# kubeadm config images pull --config kubeadm-init.yaml 
```

### 4) 初始化

```html
[root@node-01 ~]# kubeadm init --config kubeadm-init.yaml --upload-certs
```

**kubeadm init主要执行了以下操作：**

- [init]：指定版本进行初始化操作
- [preflight] ：初始化前的检查和下载所需要的Docker镜像文件
- [kubelet-start] ：生成kubelet的配置文件”/var/lib/kubelet/config.yaml”，没有这个文件kubelet无法启动，所以初始化之前的kubelet实际上启动失败。
- [certificates]：生成Kubernetes使用的证书，存放在/etc/kubernetes/pki目录中。
- [kubeconfig] ：生成 KubeConfig 文件，存放在/etc/kubernetes目录中，组件之间通信需要使用对应文件。
- [control-plane]：使用/etc/kubernetes/manifest目录下的YAML文件，安装 Master 组件。
- [etcd]：使用/etc/kubernetes/manifest/etcd.yaml安装Etcd服务。
- [wait-control-plane]：等待control-plan部署的Master组件启动。
- [apiclient]：检查Master组件服务状态。
- [uploadconfig]：更新配置
- [kubelet]：使用configMap配置kubelet。
- [patchnode]：更新CNI信息到Node上，通过注释的方式记录。
- [mark-control-plane]：为当前节点打标签，打了角色Master，和不可调度标签，这样默认就不会使用Master节点来运行Pod。
- [bootstrap-token]：生成token记录下来，后边使用kubeadm join往集群中添加节点时会用到
- [addons]：安装附加组件CoreDNS和kube-proxy

### 5) 为kubectl准备Kubeconfig文件

kubectl默认会在执行的用户家目录下面的.kube目录下寻找config文件。这里是将在初始化时[kubeconfig]步骤生成的admin.conf拷贝到.kube/config。

```html
mkdir -p $HOME/.kube
cp -i /etc/kubernetes/admin.conf $HOME/.kube/config
chown $(id -u):$(id -g) $HOME/.kube/config
export KUBECONFIG=/etc/kubernetes/admin.conf
```

在该配置文件中，记录了API Server的访问地址，所以后面直接执行kubectl命令就可以正常连接到API Server中。

### 6) 查看节点状态

```html
[root@node-01 ~]# kubectl get node
NAME      STATUS   ROLES    AGE   VERSION
node-01   NotReady    master   14m   v1.13.2
```

目前只有一个节点，角色是Master，状态是NotReady。

### 7) 其他master部署

在node-01将证书文件拷贝至其他master节点

```html
USER=root
CONTROL_PLANE_IPS="node-02 node-03"
for host in ${CONTROL_PLANE_IPS}; do
	ssh "${USER}"@$host "mkdir -p /etc/kubernetes/pki/etcd"
    scp /etc/kubernetes/pki/ca.* "${USER}"@$host:/etc/kubernetes/pki/
    scp /etc/kubernetes/pki/sa.* "${USER}"@$host:/etc/kubernetes/pki/
    scp /etc/kubernetes/pki/front-proxy-ca.* "${USER}"@$host:/etc/kubernetes/pki/
    scp /etc/kubernetes/pki/etcd/ca.* "${USER}"@$host:/etc/kubernetes/pki/etcd/
    #scp /etc/kubernetes/admin.conf "${USER}"@$host:/etc/kubernetes/
done
```

在其他master执行

```html
kubeadm join 10.199.10.230:8443 --token jouv11.4schn7t2u9ug8xe1 \
    --discovery-token-ca-cert-hash sha256:f8964488f74b94a8377915dca61eed724d22be5b85d3cea7c0bf2aeaab5ce479 \
    --control-plane --certificate-key 26162ec1eb3efccbc72d784ff156bd911b30ec3e19ebd31b482f64b7e9e9f1f2
```

> **注意**：token有效期是有限的，如果旧的token过期，可以使用`kubeadm token create --print-join-command`重新创建一条token。

### 8) node部署

在node-04、node-05、node-06执行

```html
kubeadm join 10.199.10.230:8443 --token jouv11.4schn7t2u9ug8xe1 \
    --discovery-token-ca-cert-hash sha256:f8964488f74b94a8377915dca61eed724d22be5b85d3cea7c0bf2aeaab5ce479
```

### 9) 部署网络插件calico

Master节点NotReady的原因就是因为没有使用任何的网络插件，此时Node和Master的连接还不正常。目前最流行的Kubernetes网络插件有Flannel、Calico、Canal、Weave这里选择使用flannel。

```html
wget https://docs.projectcalico.org/manifests/calico.yaml
kubectl apply -f  calico.yaml
```

### 10) 查看节点状态

所有的节点已经处于Ready状态。

```html
[root@node-01 ~]# kubectl get nodes
```

查看pod

```html
[root@node-01 ~]# kubectl get pod -n kube-system
```

查看ipvs的状态

```
[root@node-01 ~]# ipvsadm -L -n
```
测试在 k8s 创建 pod 是否可以正常访问网络
```
kubectl run busybox --image busybox:1.28 --restart=Never --rm
-it busybox -- sh

/ # ping www.baidu.com
测试coredns是否正常
/ # nslookup kubernetes.default.svc.cluster.local
Server: 10.10.0.10
Address 1: 10.10.0.10 kube-dns.kube-system.svc.cluster.local

Name: kubernetes.default.svc.cluster.local
Address 1: 10.10.0.1 kubernetes.default.svc.cluster.local
```

### 11) 安装 Ingress Controller


```sh
kubectl apply -f https://kuboard.cn/install-script/v1.16.2/nginx-ingress.yaml
# 如果打算用于生产环境，请参考 https://github.com/nginxinc/kubernetes-ingress/blob/v1.5.5/docs/installation.md 并根据您自己的情况做进一步定制
```

### 12) 安装 k8s 可视化 UI 界面 dashboard

```sh
#kubectl apply -f https://raw.githubusercontent.com/kubernetes/dashboard/v2.5.0/aio/deploy/recommended.yaml

kubectl apply -f kubernetes-dashboard.yaml
kubectl get pods -n kubernetes-dashboard
kubectl get svc -n kubernetes-dashboard

kubectl edit svc kubernetes-dashboard -n kubernetes-dashboard
把 type: ClusterIP 变成 type: NodePort，保存退出即可。

kubectl get svc -n kubernetes-dashboard

#删除原来的证书并替换成apiserver的证书
kubectl delete secret kubernetes-dashboard-certs -n kubernetes-dashboard
kubectl create secret generic kubernetes-dashboard-certs \
--from-file=/etc/kubernetes/pki/apiserver.key --from-file=/etc/kubernetes/pki/apiserver.crt -n kubernetes-dashboard

kubectl create clusterrolebinding dashboard-cluster-admin --clusterrole=cluster-admin --serviceaccount=kubernetes-dashboard:kubernetes-dashboard

kubectl get secret -n kubernetes-dashboard
#ppc8c是随机，按实际情况查看
kubectl describe secret kubernetes-dashboard-token-ppc8c -n
kubernetes-dashboard
#把token:后面的内容复制填入登陆页面

```

### 13) 安装 metrics-server 组件

metrics-server 是一个集群范围内的资源数据集和工具，同样的， metrics-server 也只是显示数
据，并不提供数据存储服务，主要关注的是资源度量 API 的实现，比如 CPU、文件描述符、内存、请求延
时等指标， metric-server 收集数据给 k8s 集群内使用，如 kubectl,hpa,scheduler 等

部署 metrics-server 组件服务
在/etc/kubernetes/manifests 里面改一下 apiserver 的配置
注意：这个是 k8s 在 1.17 的新特性，如果是 1.16 版本的可以不用添加， 1.17 以后要添加。这个参
数的作用是 Aggregation 允许在不修改 Kubernetes 核心代码的同时扩展 Kubernetes API。

```sh
vim /etc/kubernetes/manifests/kube-apiserver.yaml
#在- --enable-bootstrap-token-auth=true后面增加
- --enable-aggregator-routing=true

kubectl apply -f /etc/kubernetes/manifests/kubeapiserver.yaml
kubectl get pods -n kube-system
#把 CrashLoopBackOff 状态的 pod 删除
kubectl delete pods kube-apiserver -n kube-system

kubectl apply -f metrics.yaml
kubectl get pods -n kube-system | grep metrics

cat metrics.yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: metrics-server:system:auth-delegator
  labels:
    kubernetes.io/cluster-service: "true"
    addonmanager.kubernetes.io/mode: Reconcile
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: system:auth-delegator
subjects:
- kind: ServiceAccount
  name: metrics-server
  namespace: kube-system
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: metrics-server-auth-reader
  namespace: kube-system
  labels:
    kubernetes.io/cluster-service: "true"
    addonmanager.kubernetes.io/mode: Reconcile
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: extension-apiserver-authentication-reader
subjects:
- kind: ServiceAccount
  name: metrics-server
  namespace: kube-system
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: metrics-server
  namespace: kube-system
  labels:
    kubernetes.io/cluster-service: "true"
    addonmanager.kubernetes.io/mode: Reconcile
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: system:metrics-server
  labels:
    kubernetes.io/cluster-service: "true"
    addonmanager.kubernetes.io/mode: Reconcile
rules:
- apiGroups:
  - ""
  resources:
  - pods
  - nodes
  - nodes/stats
  - namespaces
  verbs:
  - get
  - list
  - watch
- apiGroups:
  - "extensions"
  resources:
  - deployments
  verbs:
  - get
  - list
  - update
  - watch
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: system:metrics-server
  labels:
    kubernetes.io/cluster-service: "true"
    addonmanager.kubernetes.io/mode: Reconcile
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: system:metrics-server
subjects:
- kind: ServiceAccount
  name: metrics-server
  namespace: kube-system
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: metrics-server-config
  namespace: kube-system
  labels:
    kubernetes.io/cluster-service: "true"
    addonmanager.kubernetes.io/mode: EnsureExists
data:
  NannyConfiguration: |-
    apiVersion: nannyconfig/v1alpha1
    kind: NannyConfiguration
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: metrics-server
  namespace: kube-system
  labels:
    k8s-app: metrics-server
    kubernetes.io/cluster-service: "true"
    addonmanager.kubernetes.io/mode: Reconcile
    version: v0.3.6
spec:
  selector:
    matchLabels:
      k8s-app: metrics-server
      version: v0.3.6
  template:
    metadata:
      name: metrics-server
      labels:
        k8s-app: metrics-server
        version: v0.3.6
      annotations:
        scheduler.alpha.kubernetes.io/critical-pod: ''
        seccomp.security.alpha.kubernetes.io/pod: 'docker/default'
    spec:
      priorityClassName: system-cluster-critical
      serviceAccountName: metrics-server
      containers:
      - name: metrics-server
        image: k8s.gcr.io/metrics-server-amd64:v0.3.6
        imagePullPolicy: IfNotPresent
        command:
        - /metrics-server
        - --metric-resolution=30s
        - --kubelet-preferred-address-types=InternalIP
        - --kubelet-insecure-tls
        ports:
        - containerPort: 443
          name: https
          protocol: TCP
      - name: metrics-server-nanny
        image: k8s.gcr.io/addon-resizer:1.8.4
        imagePullPolicy: IfNotPresent
        resources:
          limits:
            cpu: 100m
            memory: 300Mi
          requests:
            cpu: 5m
            memory: 50Mi
        env:
          - name: MY_POD_NAME
            valueFrom:
              fieldRef:
                fieldPath: metadata.name
          - name: MY_POD_NAMESPACE
            valueFrom:
              fieldRef:
                fieldPath: metadata.namespace
        volumeMounts:
        - name: metrics-server-config-volume
          mountPath: /etc/config
        command:
          - /pod_nanny
          - --config-dir=/etc/config
          - --cpu=300m
          - --extra-cpu=20m
          - --memory=200Mi
          - --extra-memory=10Mi
          - --threshold=5
          - --deployment=metrics-server
          - --container=metrics-server
          - --poll-period=300000
          - --estimator=exponential
          - --minClusterSize=2
      volumes:
        - name: metrics-server-config-volume
          configMap:
            name: metrics-server-config
      tolerations:
        - key: "CriticalAddonsOnly"
          operator: "Exists"
        - key: node-role.kubernetes.io/master
          effect: NoSchedule
---
apiVersion: v1
kind: Service
metadata:
  name: metrics-server
  namespace: kube-system
  labels:
    addonmanager.kubernetes.io/mode: Reconcile
    kubernetes.io/cluster-service: "true"
    kubernetes.io/name: "Metrics-server"
spec:
  selector:
    k8s-app: metrics-server
  ports:
  - port: 443
    protocol: TCP
    targetPort: https
---
apiVersion: apiregistration.k8s.io/v1
kind: APIService
metadata:
  name: v1beta1.metrics.k8s.io
  labels:
    kubernetes.io/cluster-service: "true"
    addonmanager.kubernetes.io/mode: Reconcile
spec:
  service:
    name: metrics-server
    namespace: kube-system
  group: metrics.k8s.io
  version: v1beta1
  insecureSkipTLSVerify: true
  groupPriorityMinimum: 100
  versionPriority: 100

#测试 kubectl top 命令
kubectl top pods -n kube-system
kubectl top nodes
```

### 14) 把 scheduler、 controller-manager 端口变成物理机可以监听的端口

```sh
kubectl get cs
```
默认在 1.19 之后 10252 和 10251 都是绑定在 127 的，如果想要通过 prometheus 监控，会采集不到数据，所以可以把端口绑定到物理机

可按如下方法处理：
vim /etc/kubernetes/manifests/kube-scheduler.yaml
修改如下内容：

把--bind-address=127.0.0.1 变成--bind-address=192.168.40.180

把 httpGet:字段下的 hosts 由 127.0.0.1 变成 192.168.40.180

把—port=0 删除

#注意： 192.168.40.180 是 k8s 的控制节点 xianchaomaster1 的 ip

vim /etc/kubernetes/manifests/kube-controller-manager.yaml

把--bind-address=127.0.0.1 变成--bind-address=192.168.40.180

把 httpGet:字段下的 hosts 由 127.0.0.1 变成 192.168.40.180

把—port=0 删除

修改之后在 k8s 各个节点重启下 kubelet

systemctl restart kubelet

## 6. 重置集群

```
kubeadm reset
ipvsadm --clear
\rm -rf /etc/cni/net.d

# 删除遗留的网络接口
ip a | grep -E 'docker|flannel|cni'
ip link del docker0
ip link del flannel.1
ip link del cni0
ip link del kube-ipvs0
ip link del dummy0

#查看ipvs规则
ipvsadm -ln
```

