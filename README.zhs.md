# telegramircd [![IRC](https://img.shields.io/badge/IRC-freenode-yellow.svg)](https://webchat.freenode.net/?channels=wechatircd) [![Telegram](https://img.shields.io/badge/chat-Telegram-blue.svg)](https://t.me/wechatircd) [![Gitter](https://img.shields.io/badge/chat-Gitter-753a88.svg)](https://gitter.im/wechatircd/wechatircd)

telegramircd类似于bitlbee，可以用IRC客户端收发Telegram消息。

### Arch Linux

- `aur/telegramircd-git`
- `aur/telegram-cli-git`。telegramircd使用telegram-cli和Telegram服务器通信。运行`telegram-cli`以获取登录凭据
- 根据模板`/lib/systemd/system/telegramircd.service`创建`/etc/systemd/system/telegramircd.service`。修改`User=`和`Group=`，否则`telegram-cli`无法加载登录凭据
- `systemctl start telegramircd`

IRC服务器默认监听127.0.0.1:6669 (IRC)和127.0.0.1:9000 (HTTPS + WebSocket over TLS)。

如果你在非本机运行，建议配置IRC over TLS，设置IRC connection password，添加这些选项：`--irc-cert /path/to/irc.key --irc-key /path/to/irc.cert --irc-password yourpassword`。

可以把HTTPS私钥证书用作IRC over TLS私钥证书。使用WeeChat的话，如果觉得让WeeChat信任证书比较麻烦(gnutls会检查hostname)，可以用：
```
/set irc.server.telegram.ssl on
/set irc.server.telegram.ssl_verify off
/set irc.server.telegram.password yourpassword
```

### 其他发行版

- python >= 3.5
- `pip install -r requirements.txt`
- `./telegramircd.py`

### 用HTTPS伺服文件链接

加上额外一些选项`--http-key /etc/telegramircd/key.pem --http-cert /etc/telegramircd/cert.pem --http-url https://127.1:9003`。文件链接就会显示为`https://127.1:9003/document/$id`.

你需要把创建CA certificate/key，并用它签署另一个certificate/key。

```zsh
openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key.pem -out ca.cert.pem -days 9999 -subj '/CN=127.0.0.1'
openssl req -new -newkey rsa:2048 -nodes -keyout key.pem -subj '/CN=127.0.0.1' |
  openssl x509 -req -out cert.pem -CAkey ca.key.pem -CA ca.cert.pem -set_serial 2 -days 9999 -extfile <(
    printf "subjectAltName = IP:127.0.0.1, DNS:localhost")
```

Chrome/Chromium

- 访问`chrome://settings/certificates`，导入`ca.cert.pem`，在Authorities标签页选择该证书，Edit->Trust this certificate for identifying websites.
- 安装Switcheroo Redirector扩展，把<https://web.telegram.org/js/app.js>重定向至<https://127.0.0.1:9003/app.js>。

IP或域名必须匹配`subjectAlternativeName`。Chrome从版本58起不再支持用证书中的`commonName`匹配IP/域名，参见<https://developers.google.com/web/updates/2017/03/chrome-58-deprecations#remove_support_for_commonname_matching_in_certificates>。

Firefox

- 安装Redirector扩展，重定向js，设置`Applies to: Main window (address bar), Scripts`。
- 访问重定向后的js URL，报告Your connection is not secure，Advanced->Add Exception->Confirm Security Exception

## 使用

- 访问<https://web.telegram.org>，会自动发起WebSocket连接。若打开多个，只有第一个生效
- IRC客户端连接127.1:6669，会发现自动加入了`+telegram` channel

在`+telegram`发信并不会群发，只是为了方便查看有哪些朋友。在`+telegram` channel可以执行一些命令：

- `help`，帮助
- `status`，已获取的mutual friend、群列表
- `eval $expr`。例如：
  ```
  eval client.peer_id2special_room
  eval client.peer_id2special_user
  ```

服务器只能和一个帐号绑定，但支持多个IRC客户端。

## IRC功能

- 对于没有`username`的用户，显示中文姓名时姓在前
- 标准IRC channel名以`#`开头
- Telegram chat/channel名以`&`开头，根据title生成。`SpecialChannel#update`
- 联系人mode为`+v`(voice，通常用`+`前缀标识)。`SpecialChannel#update_detail`
- 管理员mode为`+o`(op，通常用`@`前缀标识)
- 多行消息：`!m line0\nline1\nline2`
- 回复12:34:SS的消息：`@1234 !m multi\nline\nreply`
- 回复12:34:56的消息：`!m @123456 multi\nline\nreply`
- 回复Telegram channel/chat倒数第二条消息(自己的消息不计数)：`@2 reply`
- 粘贴检测。待发送消息延迟0.1秒发送，期间收到的所有行合并为一个多行消息发送

`!m `, `@3 `, `nick: `可以任意安排顺序。

对于, 默认的anti-flood机制会让发出去的两条消息间隔至少2秒。禁用该机制使粘贴检测生效：
```
/set irc.server.telegram.anti_flood_prio_high 0
```

若客户端启用IRC 3.1 3.2的`server-time`扩展，`wechatircd.py`会在发送的消息中包含 网页版获取的时间戳。客户端显示消息时时间就会和服务器收到的消息的时刻一致。参见<http://ircv3.net/irc/>。参见<http://ircv3.net/software/clients.html>查看IRCv3的客户端支持情况。

WeeChat配置如下：
```
/set irc.server_default.capabilities "account-notify,away-notify,cap-notify,multi-prefix,server-time,znc.in/server-time-iso,znc.in/self-message"
```

支持的IRC命令：

- `/cap`，列出支持的capabilities
- `/dcc send $nick/$channel $filename`, 发送图片或文件。借用了IRC客户端的`/dcc send`命令，但含义不同，参见<https://en.wikipedia.org/wiki/Direct_Client-to-Client#DCC_SEND>
- `/invite $nick [$channel]`，邀请用户加入群
- `/kick $nick`，删除群成员，群主才有效。由于网页版限制，可能收不到群成员变更的消息
- `/kill $nick [$reason]`，断开指定客户端的连接
- `/list`，列出所有群
- `/mode +m`, `--join new`模式下防止自动重新join。用`/mode -m`撤销
- `/names`, 更新当前群成员列表
- `/part [$channel]`的IRC原义为离开channel，这里表示当前IRC会话中不再接收该群的消息。不用担心，telegramircd并没有主动退出群的功能
- `/query $nick`，打开和`$nick`聊天的窗口
- `/topic topic`修改群标题。因为IRC不支持channel改名，实现为离开原channel并加入新channel
- `/who $channel`，查看群的成员列表

## 服务器选项

- `--config`, short option `-c`，配置文件路径，参见[config](config)
- HTTP/WebSocket相关选项
  + `--http-cert cert.pem`，HTTPS/WebSocketTLS的证书。你可以把证书和私钥合并为一个文件，省略`--http-key`选项。如果`--http-cert`和`--http-key`均未指定，使用不加密的HTTP
  + `--http-key key.pem`，HTTPS/WebSocket的私钥
  + `--http-listen 127.1 ::1`，HTTPS/WebSocket监听地址设置为`127.1`和`::1`，overriding `--listen`
  + `--http-port 9000`，HTTPS/WebSocket监听端口设置为9000
  + `--http-root .`, 存放`injector.js`的根目录
- 指定不自动加入的群名，用于补充join mode
  + `--ignore 'fo[o]' bar`，channel名部分匹配正则表达式`fo[o]`或`bar`
- `--ignore-bot`, 忽略与bot的私聊消息
- IRC相关选项
  + `--irc-cert cert.pem`，IRC over TLS的证书。你可以把证书和私钥合并为一个文件，省略`--irc-key`选项。如果`--irc-cert`和`--irc-key`均未指定，使用不加密的IRC
  + `--irc-key key.pem`，IRC over TLS的私钥
  + `--irc-listen 127.1 ::1`，IRC over TLS监听地址设置为`127.1`和`::1`，overriding `--listen`
  + `--irc-nicks ray ray1`，给客户端保留的nick。`SpecialUser`不会占用这些名字
  + `--irc-password pass`，IRC connection password设置为`pass`
  + `--irc-port 6667`，IRC监听端口
- Join mode，短选项`-j`
  + `--join auto`，默认：收到某个群第一条消息后自动加入，如果执行过`/part`命令了，则之后收到消息不会重新加入
  + `--join all`：加入所有channel
  + `--join manual`：不自动加入
  + `--join new`：类似于`auto`，但执行`/part`命令后，之后收到消息仍自动加入
- `--listen 127.0.0.1`，`-l`，IRC/HTTP/WebSocket监听地址设置为`127.0.0.1`
- 服务端日志
  + `--logger-ignore '&test0' '&test1'`，不记录部分匹配指定正则表达式的朋友/群日志
  + `--logger-mask '/tmp/wechat/$channel/%Y-%m-%d.log'`，日志文件名格式
  + `--logger-time-format %H:%M`，日志单条消息的时间格式
- `--mark-read`, 自动`mark_read`私聊消息
- `--paste-wait`，待发送消息延迟0.1秒发送，期间收到的所有行合并为一个多行消息发送
- `--special-channel-prefix`，选项：`&`, `!`, `#`, `##`，SpecialChannel的前缀。[Quassel](quassel-irc.org)似乎不支持channel前缀`&`，指定`--special-channel-prefix '##'`让Quassel高兴
- telegram-cli相关选项
  + `--telegram-cli-command telegram-cli`, telegram-cli command name.
  + `--telegram-cli-port 1235`, telegram-cli listen port.
  + `--telegram-cli-timeout 10`, telegram-cli request (like `load_photo`) timeout in seconds
  + `--telegram-cli-poll-channels 1031857103`, telegram-cli cannot receive messages in some channels <https://github.com/vysheng/tg/issues/1135>, specify their `peer_id` to poll messages with the `history` command
  + `--telegram-cli-poll-interval 10`, interval in seconds
  + `--telegram-cli-poll-limit 10`, `history channel#{peer_id} {telegram_cli_poll_limit}`

[telegramircd.service](telegramircd.service)是`/etc/systemd/system/telegramircd.service`的模板，修改其中的`User=` and `Group=`。

## Demo

![](https://maskray.me/static/2016-05-07-telegramircd/telegramircd.jpg)

## 已知问题

- 对于某些channel，telegram-cli无法接收消息<https://github.com/vysheng/tg/issues/1135>
  用`/list`命令获取这些channel的`peer_id`:

  ```
  &test0(0): channel#1000000000 test0
  &test1(0): channel#1000000001 test1
  End of LIST
  ```

  指定`--telegram-cli-poll-channels 1000000000 1000000001`让telegramircd定期执行`history channel#{channel_id} 10`命令poll消息。
