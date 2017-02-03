# telegramircd

telegramircd类似于bitlbee，可以用IRC客户端收发Telegram消息。

## 安装

需要Python 3.5或以上，支持`async/await`语法
`pip install -r requirements.txt`安装依赖

### Arch Linux

- `aur/telegramircd-git`
- `aur/telegram-cli-git`
- 根据模板`/lib/systemd/system/telegramircd.service`创建`/etc/systemd/system/telegramircd.service`
- `systemctl start telegramircd`

The IRC server listens on 127.0.0.1:6669 (IRC) and 127.0.0.1:9003 (HTTP) by default.

Specify `--http-url http://127.1:9003` to display document links as `http://127.1:9003/document/$id`.
File links can be served via HTTPS with `--http-key` and `--http-cert`: `telegramircd --http-key /etc/telegramircd/key.pem --http-cert /etc/telegramircd/cert.pem --http-url https://127.1:9003`. File links will be shown as `https://127.1:9003/document/$id`.

If you run the server on another machine, it is recommended to set up IRC over TLS and an IRC connection password: `telegramircd --http-key /etc/telegramircd/key.pem --http-cert /etc/telegramircd/cert.pem --irc-cert /path/to/irc.key --irc-key /path/to/irc.cert --irc-password yourpassword`.

You can reuse the HTTPS certificate+key as IRC over TLS certificate+key. If you use WeeChat and find it difficult to set up a valid certificate (gnutls checks the hostname), type the following lines in WeeChat:
```
set irc.server.telegram.ssl on
set irc.server.telegram.ssl_verify off
set irc.server.telegram.password yourpassword`
```

My `/etc/systemd/system/telegramircd.service`:
```systemd
[Service]
User=ray
ExecStart=/usr/bin/telegramircd --join new --http-url https://i_use_nginx --logger-mask '/tmp/telegramircd/$channel/%%Y-%%m-%%d.log' --telegram-cli-poll-channels 1031857103 --ignore 污水群
```

N.B. in systemd.unit files, use `%%` in place of `%` to specify a single percent sign.

### 导入自签名证书到浏览器

`openssl req -newkey rsa:2048 -nodes -keyout key.pem -x509 -out cert.pem -subj '/CN=127.0.0.1' -dates 9999`.

Chrome/Chromium

- 访问`chrome://settings/certificates`，导入cert.pem，在Authorities标签页选择该证书，Edit->Trust this certificate for identifying websites.
- 安装Switcheroo Redirector扩展，把<https://web.telegram.org/js/app.js>重定向至<https://127.0.0.1:9003/app.js>。

Firefox

- 安装Redirector扩展，重定向js，设置` Applies to: Main window (address bar), Scripts`。
- 访问重定向后的js URL，报告Your connection is not secure，Advanced->Add Exception->Confirm Security Exception

## 使用

- 访问<https://web.telegram.org>，会自动发起WebSocket连接。若打开多个，只有第一个生效
- IRC客户端连接127.1:6669，会发现自动加入了`+telegram` channel

在`+telegram`发信并不会群发，只是为了方便查看有哪些朋友。

在`+telegram` channel可以执行一些命令：

- `help`，帮助
- `status`，已获取的mutual friend、群列表
- `eval $password $expr`: 如果运行时带上了`--password $password`选项，这里可以eval，方便调试，比如`eval $password client`

自动调用`messages.getHistory`获取历史消息，命令行选项`-H false`可关闭这一特性。
自动调用`messages.readHistory`标注接受消息已读。

## IRC命令

telegramircd是个简单的IRC服务器，可以执行通常的IRC命令，可以对其他客户端私聊，创建standard channel(以`#`开头的channel)。另外若用token与某个telegram网页版连接的，就能看到telegram联系人(朋友、群联系人)显示为特殊nick、群显示为特殊channel(以`&`开头，根据群名自动设置名称)

这些特殊nick与channel只有当前客户端能看到，因此一个服务端支持多个telegram帐号同时登录，每个用不同的IRC客户端控制。另外，以下命令会有特殊作用：

- 程序默认选项为`--join auto`，收到某个群的第一条消息后会自动加入对应的channel，即开始接收该群的消息。
- `/dcc send nick/channel filename`，给mutual friend或群发图片/文件。参见<https://en.wikipedia.org/wiki/Direct_Client-to-Client#DCC_SEND>
- `/list`，列出所有群
- `/names`，更新当前群成员列表
- `/part [channel]`的IRC原义为离开channel，转换为telegram代表在当前IRC会话中不再接收该群的消息。不用担心，telegramircd并没有主动退出群的功能
- `/query nick`打开与`$nick`的私聊窗口，与之私聊即为在telegram上和他/她/它对话
- `/who channel`，查看群成员列表

## 显示

![](https://maskray.me/static/2016-05-07-telegramircd/run.jpg)

- `[Doc] $filename filesystem:https://web.telegram.org/temporary/t_filexxxxxxxxxxxxxxx`
- `[Photo] filesystem:https://web.telegram.org/temporary/xxxxxxxxxxx`。图片(照片)

vte终端模拟器支持URL选择，但不能识别`filesystem:https://`。我修改的`aur/vte3-ng-fullwidth-emoji`添加了该类URL支持。

termite `C-S-Space` URL选择也不支持，可以用<https://gist.github.com/MaskRay/9e1c57642bedd8b2b965e39b2d58fc82>添加该类URL支持。感谢张酉夫的ELF hack指导。

## IRCv3

支持IRC version 3.1和3.2的`server-time`，`wechatircd.py`传递消息时带上创建时刻，客户端显示消息创建时刻而不是收到消息的时刻。参见<http://ircv3.net/irc/>。IRCv3客户端支持参见<http://ircv3.net/software/clients.html>。

WeeChat配置如下：
```
/set irc.server_default.capabilities "account-notify,away-notify,cap-notify,multi-prefix,server-time,znc.in/server-time-iso,znc.in/self-message"
```

## 已知问题

- supergroup和普通chat的message格式不同，不含`random_id`字段，没法判断该消息是否由IRC客户端生成的。
