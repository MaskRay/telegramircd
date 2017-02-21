# telegramircd

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
set irc.server.telegram.ssl on
set irc.server.telegram.ssl_verify off
set irc.server.telegram.password yourpassword
```

### 其他发行版

- python >= 3.5
- `pip install -r requirements.txt`
- `./telegramircd.py`

### 自签名证书

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

- 标准IRC channel名以`#`开头
- Telegram chat/channel名以`&`开头，根据title生成。`SpecialChannel#update`
- 联系人mode为`+v`(voice，通常用`+`前缀标识)。`SpecialChannel#update_detail`
- 管理员mode为`+o`(op，通常用`@`前缀标识)
- 多行消息：`!m line0\nline1\nline2`
- 回复12:34:SS的消息：`@1234 !m multi\nline\nreply`
- 回复12:34:56的消息：`!m @123456 multi\nline\nreply`
- 回复Telegram channel/chat里倒数第二条消息：`@2 reply`

`!m `, `@3 `, `nick: `可以任意安排顺序。

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
- `/squit $any`，log out
- `/topic topic`修改群标题。因为IRC不支持channel改名，实现为离开原channel并加入新channel
- `/who $channel`，查看群的成员列表

### 显示

![](https://maskray.me/static/2016-05-07-telegramircd/run.jpg)

- `[Doc] $filename filesystem:https://web.telegram.org/temporary/t_filexxxxxxxxxxxxxxx`
- `[Photo] filesystem:https://web.telegram.org/temporary/xxxxxxxxxxx`。图片(照片)

vte终端模拟器支持URL选择，但不能识别`filesystem:https://`。我修改的`aur/vte3-ng-fullwidth-emoji`添加了该类URL支持。

termite `C-S-Space` URL选择也不支持，可以用<https://gist.github.com/MaskRay/9e1c57642bedd8b2b965e39b2d58fc82>添加该类URL支持。感谢张酉夫的ELF hack指导。

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
