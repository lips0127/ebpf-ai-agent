# SSH 密钥安全指南

## 当前密钥配置

| 环境 | IP | 密钥位置 | 用途 |
|------|-----|---------|------|
| 腾讯云 | 124.223.112.190 | `~/.ssh/weizhou_PC_12600KF.pem` | 编译构建 |
| VMware | 192.168.0.113 | 密码登录 | 测试运行 |

---

## 密钥管理原则

### 1. 私钥存放位置

**永远不要**把私钥放在：
- 项目目录内
- 网盘/云存储
- Git 仓库
- 任何可被他人访问的位置

**正确位置：**
```
~/.ssh/
├── weizhou_PC_12600KF.pem    # 腾讯云私钥
├── config                      # SSH 别名配置
├── id_rsa                      # 其他密钥
└── known_hosts                 # 主机指纹
```

### 2. SSH Config 用法

```bash
# 连接到腾讯云
ssh tencent

# 复制文件到腾讯云
scp file.txt tencent:/tmp/

# 用 rsync 同步到腾讯云
rsync -avz -e "ssh -i ~/.ssh/weizhou_PC_12600KF.pem" ./ tencent:/path/
```

### 3. 文件权限

```bash
# 必须 600
chmod 600 ~/.ssh/config
chmod 600 ~/.ssh/*.pem

# 可 644
chmod 644 ~/.ssh/*.pub
chmod 644 ~/.ssh/known_hosts
```

---

## .gitignore 保护

项目 `.gitignore` 已配置保护：

```
*.pem           # 所有私钥
*.key           # 所有密钥文件
id_rsa          # RSA 私钥
config.yaml     # 配置文件
build/config.sh # 构建配置
```

---

## 腾讯云密钥生成（新密钥）

如果需要生成新的 SSH 密钥对：

```bash
# 1. 生成新密钥
ssh-keygen -t ed25519 -C "ebpf-build" -f ~/.ssh/ebpf_build.pem

# 2. 设置权限
chmod 600 ~/.ssh/ebpf_build.pem

# 3. 上传公钥到腾讯云
ssh-copy-id -i ~/.ssh/ebpf_build.pub ubuntu@124.223.112.190

# 4. 测试
ssh -i ~/.ssh/ebpf_build.pem ubuntu@124.223.112.190
```

---

## VMware 虚拟机密钥配置

为 VMware 虚拟机创建独立密钥：

```bash
# 1. 生成密钥
ssh-keygen -t ed25519 -C "vmware-test" -f ~/.ssh/vmware_key.pem

# 2. 复制公钥到虚拟机
ssh-copy-id -i ~/.ssh/vmware_key.pub ubuntu@192.168.0.113

# 3. 测试无密码登录
ssh -i ~/.ssh/vmware_key.pem ubuntu@192.168.0.113
```

---

## 密钥轮换建议

- 定期更换密钥（每3-6个月）
- 密钥泄露后立即更换
- 不同环境使用不同密钥

---

## 常见问题

### Q: .pem 文件打不开？
```bash
# 检查权限
ls -la ~/.ssh/weizhou_PC_12600KF.pem
# 应该显示：-rw-------

# 如果不对
chmod 600 ~/.ssh/weizhou_PC_12600KF.pem
```

### Q: 忘记 pem 密码？
无法恢复，只能重新生成新的密钥对。

### Q: SSH 连接被拒绝？
```bash
# 检查密钥路径是否正确
ssh -vvv -i ~/.ssh/weizhou_PC_12600KF.pem ubuntu@124.223.112.190
```
