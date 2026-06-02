# BIT 校园网 Login, But Less Painful

北京理工大学校园网官方登录脚本太烂了。于是我把它逆向了。

不是那种“有点粗糙”的烂，是那种参数不好记、报错不说人话、想挂后台还得先和它搏斗一轮的烂。所以这里放一个更适合 Linux 日常使用的北理工 SRun4K 登录脚本：单文件、零第三方依赖，拿学号和密码登录，不自动给用户名乱加后缀。

该脚本能完全替代 http://10.0.0.55/download/download_client.html 所提供的登录脚本

## 功能

- 登录校园网
- 检查 portal 是否可达
- 登出
- keepalive 掉线重登
- 自动解析 `ip` 和 `acid`
- 自动尝试 BIT 常见 portal 入口
- 支持配置文件、环境变量、命令行参数
- Debug 输出会隐藏密码

## 运行

```bash
python3 srun.py login -u 学号 -p 密码 --host 10.0.0.55
```

常用命令：

```bash
python3 srun.py login -u 学号 -p 密码 --host 10.0.0.55
python3 srun.py check --host 10.0.0.55
python3 srun.py logout -u 学号 --host 10.0.0.55
python3 srun.py keepalive -u 学号 -p 密码 --host 10.0.0.55 --interval 300
python3 srun.py --help
```

`check` 会查询 `/cgi-bin/rad_user_info`，输出当前设备是否已经在线：

```text
online: 学号 @ 在线IP
```

如果返回 `offline: ...`，说明当前设备还没通过认证。

## 配置文件

生成默认配置：

```bash
python3 srun.py init-config
```

默认路径：

```text
~/.config/srun-login/config.json
```

配置模板会包含：

```json
{
  "protocol": "http",
  "host": "10.0.0.55",
  "username": "",
  "password": "",
  "acid": "auto",
  "portal_path": "",
  "ip": "",
  "n": "200",
  "type": "1",
  "enc_ver": "srun_bx1",
  "test_url": "http://www.baidu.com/"
}
```

密码默认留空。要不要写进配置文件由你决定；不想落盘就每次用 `-p` 传。

优先级：

```text
命令行参数 > 环境变量 > 配置文件 > 默认值
```

支持的环境变量：

```bash
export SRUN_HOST=10.0.0.55
export SRUN_USERNAME=你的学号
export SRUN_PASSWORD=你的密码
export SRUN_ACID=auto
export SRUN_PORTAL_PATH=
export SRUN_IP=
```

然后：

```bash
python3 srun.py login
```

## acid 和 ip

默认会从 portal 页面自动解析 `ip` 和 `acid`。脚本支持官方客户端那套 `/index_1.html` 解析方式，也支持页面里的 `acid: "1"`。如果页面没写 `acid`，脚本会按 BIT 默认值 `1` 来，不用手动传。

如果登录成功但不能上网，或者你的接入点确实不是 `1`，再手动指定：

```bash
python3 srun.py login -u 学号 -p 密码 --host 10.0.0.55 --ip 你的IP --acid 1
```

如果出现“登录成功但不能上网”，优先怀疑 `acid` 不对。这个坑参考脚本里也提到过，确实挺校园网的。

## portal 入口

脚本会自动尝试这些入口：

```text
/srun_portal_pc.php
/srun_portal_pc?ac_id=1&theme=bit
/index.html
/
```

如果你的校园网入口比较有个性，也可以手动指定：

```bash
python3 srun.py check --host 10.0.0.55 --portal-path '/srun_portal_pc?ac_id=1&theme=bit'
python3 srun.py login -u 学号 -p 密码 --host 10.0.0.55 --portal-path '/srun_portal_pc?ac_id=1&theme=bit'
```

## Keepalive

后台保活：

```bash
nohup python3 srun.py keepalive -u 学号 -p 密码 --host 10.0.0.55 --interval 300 > srun.log 2>&1 &
```

它会定期检查网络，不通就重新登录。默认测试 URL 是：

```text
http://www.baidu.com/
```

也可以换：

```bash
python3 srun.py keepalive -u 学号 -p 密码 --test-url http://connectivitycheck.gstatic.com/generate_204
```

## systemd 示例

新建：

```text
~/.config/systemd/user/srun-login.service
```

内容：

```ini
[Unit]
Description=SRun campus network keepalive
After=network-online.target

[Service]
Type=simple
WorkingDirectory=%h/path/to/project
ExecStart=python3 srun.py keepalive --interval 300
Restart=always
RestartSec=10
Environment=SRUN_HOST=10.0.0.55
Environment=SRUN_USERNAME=你的学号
Environment=SRUN_PASSWORD=你的密码

[Install]
WantedBy=default.target
```

启用：

```bash
systemctl --user daemon-reload
systemctl --user enable --now srun-login.service
```

看日志：

```bash
journalctl --user -u srun-login.service -f
```

## 协议说明

脚本实现的是常见 SRun4K 流程：

1. 打开 portal 页面，解析 `ip` 和 `acid`
2. 请求 `/cgi-bin/get_challenge` 获取 token
3. 生成 `{MD5}` 密码字段
4. 生成 `{SRBX1}` 的 `info`
5. 计算 `chksum`
6. 请求 `/cgi-bin/srun_portal?action=login`

用户名就是你输入的完整用户名，通常是学号。

## Debug

```bash
python3 srun.py login -u 学号 -p 密码 --debug
```

Debug 会打印更多响应信息，但密码会显示为：

```text
<redacted>
```

## 测试

```bash
python3 -m unittest tests.test_srun -v
```

## 免责声明

这个脚本只是把你自己的账号密码自动提交给校园网认证系统，不提供绕过认证、破解账号、规避计费之类的功能。它的目标很朴素：让 Linux 下登录校园网别再像拆盲盒。

## 感谢

- https://github.com/Alanxtl/SpadgerBoy/BIT-srun-login-script
- https://github.com/Alanxtl/coffeehat/BIT-srun-login-script
- https://github.com/Alanxtl/AdamXuD/Sztu-srun-login-script
