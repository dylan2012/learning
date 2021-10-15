# kubeadm安装kubernetes 1.22.2多master高可用集群

## 1. 简介

Kubernetes v1.13版本发布后，kubeadm才正式进入GA，可以生产使用,用kubeadm部署kubernetes集群也是以后的发展趋势。目前Kubernetes的对应镜像仓库，在国内阿里云也有了镜像站点，使用kubeadm部署Kubernetes集群变得简单并且容易了很多，本文使用kubeadm带领大家快速部署Kubernetes v1.13.2版本。

注意：请不要把目光仅仅放在部署上，如果你是新手，推荐先熟悉用二进制文件部署后，再来学习用kubeadm部署。二进制文件部署请查看我博客的其他文章。

## 2. 架构信息

```html
系统版本：CentOS 7.6
内核：3.10.0-1160.42.2.el7.x86_64
Kubernetes: v1.22.2
Docker-ce: 20.10.8
推荐硬件配置：2核2G

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
```

### 2) 关闭swap

```html
swapoff -a
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
cat <<EOF >  /etc/sysctl.d/k8s.conf
net.bridge.bridge-nf-call-ip6tables = 1
net.bridge.bridge-nf-call-iptables = 1
net.ipv4.ip_nonlocal_bind = 1
net.ipv4.ip_forward = 1
vm.swappiness=0
EOF

sysctl --system
```

### 6) 加载ipvs模块

```shell
cat > /etc/sysconfig/modules/ipvs.modules <<EOF
#!/bin/bash
modprobe -- ip_vs
modprobe -- ip_vs_rr
modprobe -- ip_vs_wrr
modprobe -- ip_vs_sh
modprobe -- nf_conntrack_ipv4
EOF
chmod 755 /etc/sysconfig/modules/ipvs.modules && bash /etc/sysconfig/modules/ipvs.modules && lsmod | grep -e ip_vs -e nf_conntrack_ipv4
```

### 7) 添加yum源

```html
cat << EOF > /etc/yum.repos.d/kubernetes.repo[kubernetes]name=Kubernetesbaseurl=https://mirrors.aliyun.com/kubernetes/yum/repos/kubernetes-el7-x86_64/enabled=1gpgcheck=1repo_gpgcheck=1gpgkey=https://mirrors.aliyun.com/kubernetes/yum/doc/yum-key.gpg https://mirrors.aliyun.com/kubernetes/yum/doc/rpm-package-key.gpgEOFwget http://mirrors.aliyun.com/repo/Centos-7.repo -O /etc/yum.repos.d/CentOS-Base.repowget http://mirrors.aliyun.com/repo/epel-7.repo -O /etc/yum.repos.d/epel.repo wget https://mirrors.aliyun.com/docker-ce/linux/centos/docker-ce.repo -O /etc/yum.repos.d/docker-ce.repo
```

## 4. 部署keepalived和haproxy

### 1) 安装keepalived和haproxy

在node-01和node-02安装keepalived和haproxy

```html
yum install -y keepalived haproxy
```

### 2) 修改配置

**keepalived配置**

node-01的`priority`为100，node-02的`priority`为90，其他配置一样。

```html
[root@node-01 ~]# cat /etc/keepalived/keepalived.conf! Configuration File for keepalivedglobal_defs {   notification_email {        feng110498@163.com   }   notification_email_from Alexandre.Cassen@firewall.loc   smtp_server 127.0.0.1   smtp_connect_timeout 30   router_id LVS_1}                                                     vrrp_instance VI_1 {    state MASTER              interface eth0    lvs_sync_daemon_inteface eth0    virtual_router_id 88    advert_int 1    priority 100             authentication {        auth_type PASS        auth_pass 1111    }    virtual_ipaddress {      10.199.10.230/24    }}
```

**haproxy配置**

node-01和node-02的haproxy配置是一样的。此处我们监听的是10.199.10.230的8443端口，因为haproxy是和k8s apiserver是部署在同一台服务器上，都用6443会冲突。

```html
cat /etc/haproxy/haproxy.cfgglobal        chroot  /var/lib/haproxy        daemon        group haproxy        user haproxy        log 127.0.0.1:514 local0 warning        pidfile /var/lib/haproxy.pid        maxconn 20000        spread-checks 3        nbproc 8defaults        log     global        mode    tcp        retries 3        option redispatchlisten https-apiserver        bind 10.199.10.230:8443        mode tcp        balance roundrobin        timeout server 900s        timeout connect 15s        server apiserver01 10.199.10.231:6443 check port 6443 inter 5000 fall 5        server apiserver02 10.199.10.232:6443 check port 6443 inter 5000 fall 5        server apiserver03 10.199.10.233:6443 check port 6443 inter 5000 fall 5
```

### 3) 启动服务

```html
systemctl enable keepalived && systemctl start keepalived systemctl enable haproxy && systemctl start haproxy 
```

## 5. 部署kubernetes

### 1) 安装软件

由于kubeadm对Docker的版本是有要求的，需要安装与kubeadm匹配的版本。
由于版本更新频繁，请指定对应的版本号，本文采用1.13.2版本，其它版本未经测试。

```html
yum install -y kubelet-1.22.2 kubeadm-1.22.2 kubectl-1.22.2 ipvsadm ipset docker-ce-20.10.8.ce#启动dockersystemctl enable docker && systemctl start docker#设置kubelet开机自启动systemctl enable kubelet 
```

### 2) 修改初始化配置

使用kubeadm config print init-defaults > kubeadm-init.yaml 打印出默认配置，然后在根据自己的环境修改配置.

```html
cat <<EOF > ./kubeadm-init.yamlapiVersion: kubeadm.k8s.io/v1beta2kind: ClusterConfigurationkubernetesVersion: v1.20.2controlPlaneEndpoint: "10.199.10.230:8443"networking:  serviceSubnet: "10.96.0.0/16"  podSubnet: "10.100.0.1/16"  dnsDomain: "cluster.local"EOF
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
mkdir -p $HOME/.kubecp -i /etc/kubernetes/admin.conf $HOME/.kube/configchown $(id -u):$(id -g) $HOME/.kube/configexport KUBECONFIG=/etc/kubernetes/admin.conf
```

在该配置文件中，记录了API Server的访问地址，所以后面直接执行kubectl命令就可以正常连接到API Server中。

### 6) 查看组件状态

```html
[root@node-01 ~]# kubectl get csNAME                 STATUS    MESSAGE              ERRORscheduler            Healthy   ok                   controller-manager   Healthy   ok                   etcd-0               Healthy   {"health": "true"}  [root@node-01 ~]# kubectl get nodeNAME      STATUS   ROLES    AGE   VERSIONnode-01   NotReady    master   14m   v1.13.2
```

目前只有一个节点，角色是Master，状态是NotReady。

### 7) 其他master部署

在node-01将证书文件拷贝至其他master节点

```html
USER=rootCONTROL_PLANE_IPS="node-02 node-03"for host in ${CONTROL_PLANE_IPS}; do	ssh "${USER}"@$host "mkdir -p /etc/kubernetes/pki/etcd"    scp /etc/kubernetes/pki/ca.* "${USER}"@$host:/etc/kubernetes/pki/    scp /etc/kubernetes/pki/sa.* "${USER}"@$host:/etc/kubernetes/pki/    scp /etc/kubernetes/pki/front-proxy-ca.* "${USER}"@$host:/etc/kubernetes/pki/    scp /etc/kubernetes/pki/etcd/ca.* "${USER}"@$host:/etc/kubernetes/pki/etcd/    scp /etc/kubernetes/admin.conf "${USER}"@$host:/etc/kubernetes/done
```

在其他master执行

```html
kubeadm join 10.199.10.230:8443 --token jouv11.4schn7t2u9ug8xe1 \    --discovery-token-ca-cert-hash sha256:f8964488f74b94a8377915dca61eed724d22be5b85d3cea7c0bf2aeaab5ce479 \    --control-plane --certificate-key 26162ec1eb3efccbc72d784ff156bd911b30ec3e19ebd31b482f64b7e9e9f1f2
```

> **注意**：token有效期是有限的，如果旧的token过期，可以使用`kubeadm token create --print-join-command`重新创建一条token。

### 8) node部署

在node-04、node-05、node-06执行

```html
kubeadm join 10.199.10.230:8443 --token jouv11.4schn7t2u9ug8xe1 \    --discovery-token-ca-cert-hash sha256:f8964488f74b94a8377915dca61eed724d22be5b85d3cea7c0bf2aeaab5ce479
```

### 9) 部署网络插件flannel

Master节点NotReady的原因就是因为没有使用任何的网络插件，此时Node和Master的连接还不正常。目前最流行的Kubernetes网络插件有Flannel、Calico、Canal、Weave这里选择使用flannel。

```html
wget https://raw.githubusercontent.com/coreos/flannel/master/Documentation/kube-flannel.ymlkubectl apply -f  kube-flannel.yml
```

### 10) 查看节点状态

所有的节点已经处于Ready状态。

```html
[root@node-01 ~]# kubectl get node
```

查看pod

```html
[root@node-01 ~]# kubectl get pod -n kube-system
```

查看ipvs的状态

```
[root@node-01 ~]# ipvsadm -L -n
```

### 11) 安装 Ingress Controller


```sh
kubectl apply -f https://kuboard.cn/install-script/v1.16.2/nginx-ingress.yaml# 如果打算用于生产环境，请参考 https://github.com/nginxinc/kubernetes-ingress/blob/v1.5.5/docs/installation.md 并根据您自己的情况做进一步定制
```



## 6. 重置集群

```
kubeadm resetipvsadm --clear\rm -rf /etc/cni/net.d# 删除遗留的网络接口ip a | grep -E 'docker|flannel|cni'ip link del docker0ip link del flannel.1ip link del cni0ip link del kube-ipvs0ip link del dummy0#查看ipvs规则ipvsadm -ln
```

