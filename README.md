[简体中文](README.zhs.md)

# telegramircd [![IRC](https://img.shields.io/badge/IRC-freenode-yellow.svg)](https://webchat.freenode.net/?channels=wechatircd) [![Telegram](https://img.shields.io/badge/chat-Telegram-blue.svg)](https://t.me/wechatircd) [![Gitter](https://img.shields.io/badge/chat-Gitter-753a88.svg)](https://gitter.im/wechatircd/wechatircd)

telegramircd is an IRC server that enables IRC clients to send and receive messages from Telegram.

### Arch Linux

- `aur/telegramircd-git`
- `aur/telegram-cli-git`. telegramircd uses the JSON output of telegram-cli to communicate with Telegram servers. Run `telegram-cli` and login to get credential before using telegramircd.
- Create `/etc/systemd/system/telegramircd.service` from the template `/lib/systemd/system/telegramircd.service`. Change the `User=` and `Group=` fields, otherwise `telegram-cli` cannot load credential stored in `~/.telegram-cli/`.
- `systemctl start telegramircd`

`telegramircd.py` (the server) will listen on 127.0.0.1:6669 (IRC) and 127.0.0.1:9003 (HTTPS + WebSocket over TLS).

If you run the server on another machine, it is recommended to set up IRC over TLS and an IRC connection password with a few more options: `--irc-cert /path/to/irc.key --irc-key /path/to/irc.cert --irc-password yourpassword`. You can reuse the HTTPS certificate+key. If you use WeeChat and find it difficult to set up a valid certificate (gnutls checks the hostname), type the following lines in WeeChat:
```
set irc.server.telegram.ssl on
set irc.server.telegram.ssl_verify off
set irc.server.telegram.password yourpassword
```

### Not Arch Linux

- python >= 3.5
- `pip install -r requirements.txt`
- Install telegram-cli
- `./telegramircd.py --http-url http://localhost:9003`

### Serve file links via HTTPS

A few more options: `--http-key /etc/telegramircd/key.pem --http-cert /etc/telegramircd/cert.pem --http-url https://127.1:9003`. File links will be shown as `https://127.1:9003/document/$id`.

You need to generate self-signed certificate and import it to the browser.

`openssl req -newkey rsa:2048 -nodes -keyout key.pem -x509 -out cert.pem -subj '/CN=127.0.0.1' -dates 9999`

Chrome/Chromium

- Visit `chrome://settings/certificates`, import `cert.pem`, click the `Authorities` tab, select the `127.0.0.1` certificate, Edit->Trust this certificate for identifying websites.

Firefox

- Install extension Redirector, redirects `app.js` as above, click ` Applies to: Main window (address bar), Scripts`.
- Visit one file link, Firefox will show "Your connection is not secure", Advanced->Add Exception->Confirm Security Exception.

## Usage

- Run `telegramircd.py`.
- Connect to 127.0.0.1:6669 in your IRC client

You will join `+telegram` channel automatically and find your contact list there. Some commands are available:

- `help`
- `status`, mutual contact list、group/supergroup list
- `eval $expr`: eval the Python expression `$expr`. Examples:
  ```
  eval client.peer_id2special_room
  eval client.peer_id2special_user
  ```

The server will be bound to one account, however, you may have more than one IRC clients connected to the server.

## IRC features

- Surnames come first when displaying Chinese names for users without `username`. `SpecialUser#name`
- Standard IRC channels have names beginning with `#`.
- Telegram channels/chats have names beginning with `&`. The channel name is generated from the group title. `SpecialChannel#update`
- Contacts have modes `+v` (voice, usually displayed with a prefix `+`). `SpecialChannel#update_detail`
- Multi-line messages: `!m line0\nline1`
- Multi-line messages: `!html line0<br>line1`
- `nick0: nick1: test` will be converted to `@GroupAlias0 @GroupAlias1 test`, where `GroupAlias0` is the name set by that user, not your `Set Remark and Tag`. It corresponds to `On-screen names` in the mobile application.
- Reply to the message at 12:34:SS: `@1234 !m multi\nline\nreply`, which will be sent as `「Re GroupAlias: text」text`
- Reply to the message at 12:34:56: `!m @123456 multi\nline\nreply`
- Reply to the penultimate message (your own messages are not counted) in this channel/chat: `@2 reply`
- Paste detection. PRIVMSG lines will be hold for up to 0.1 seconds, lines in this interval will be packed to a multiline message

`!m `, `@3 `, `nick: ` can be arranged in any order

For WeeChat, its anti-flood mechanism will prevent two user messages sent to IRC server in the same time. Disable anti-flood to enable paste detection.
```
/set irc.server.wechat.anti_flood_prio_high 0
```

`server-time` extension from IRC version 3.1, 3.2. `telegramircd.py` includes the timestamp (obtained from JavaScript) in messages to tell IRC clients that the message happened at the given time. See <http://ircv3.net/irc/>. See<http://ircv3.net/software/clients.html> for Client support of IRCv3.

Configuration for WeeChat:
```
/set irc.server_default.capabilities "account-notify,away-notify,cap-notify,multi-prefix,server-time,znc.in/server-time-iso,znc.in/self-message"
```

Supported IRC commands:

- `/cap`, supported capabilities.
- `/dcc send $nick/$channel $filename`, send image or file。This feature borrows the command `/dcc send` which is well supported in IRC clients. See <https://en.wikipedia.org/wiki/Direct_Client-to-Client#DCC_SEND>.
- `/invite $nick [$channel]`, invite a contact to the channel.
- `/kick $nick`, delete a group member. You must be the group leader to do this. Due to the defect of the Web client, you may not receive notifcations about the change of members.
- `/kill $nick [$reason]`, cause the connection of that client to be closed
- `/list`, list groups.
- `/mode +m`, no rejoin in `--join new` mode. `/mode -m` to revert.
- `/names`, update nicks in the channel.
- `/part [$channel]`, no longer receive messages from the channel. It just borrows the command `/part` and it will not leave the group.
- `/query $nick`, open a chat window with `$nick`.
- `/topic topic`, change the topic of a group. Because IRC does not support renaming of a channel, you will leave the channel with the old name and join a channel with the new name.
- `/who $channel`, see the member list.

## Server options

- `--config`, short option `-c`, config file path, see [config](config)
- HTTP/WebSocket related options
  + `--http-cert cert.pem`, TLS certificate for HTTPS. You may concatenate certificate+key, specify a single PEM file and omit `--http-key`. Use HTTP if neither --http-cert nor --http-key is specified.
  + `--http-url http://localhost`, Show file links as http://localhost/document/$id .
  + `--http-key key.pem`, TLS key for HTTPS.
  + `--http-listen 127.1 ::1`, change HTTPS listen address to `127.1` and `::1`, overriding `--listen`.
  + `--http-port 9003`, change HTTPS listen port to 9003.
- Groups that should not join automatically. This feature supplements join mode.
  + `--ignore '&fo[o]' '&bar'`, do not auto join channels whose names(generated from topics) partially match regex `&fo[o]` or `&bar`
  + `--ignore-topic 'fo[o]' bar`, short option `-I`, do not auto join channels whose topics match regex `fo[o]` or `bar`
- `--ignore-bot`, ignore private messages with bots
- IRC related options
  + `--irc-cert cert.pem`, TLS certificate for IRC over TLS. You may concatenate certificate+key, specify a single PEM file and omit `--irc-key`. Use plain IRC if neither --irc-cert nor --irc-key is specified.
  + `--irc-key key.pem`, TLS key for IRC over TLS.
  + `--irc-listen 127.1 ::1`, change IRC listen address to `127.1` and `::1`, overriding `--listen`.
  + `--irc-nicks ray ray1`, reverved nicks for clients. `SpecialUser` will not have these nicks.
  + `--irc-password pass`, set the connection password to `pass`.
  + `--irc-port 6669`, IRC server listen port.
- Join mode, short option `-j`
  + `--join auto`, default: join the channel upon receiving the first message, no rejoin after issuing `/part` and receiving messages later
  + `--join all`: join all the channels
  + `--join manual`: no automatic join
  + `--join new`: like `auto`, but rejoin when new messages arrive even if after `/part`
- `--listen 127.0.0.1`, short option `-l`, change IRC/HTTP/WebSocket listen address to `127.0.0.1`.
- Server side log
  + `--logger-ignore '&test0' '&test1'`, list of ignored regex, do not log contacts/groups whose names match
  + `--logger-mask '/tmp/telegram/$channel/%Y-%m-%d.log'`, format of log filenames
  + `--logger-time-format %H:%M`, time format of server side log
- `--mark-read`, `mark_read` private messages from users
- `--paste-wait`, PRIVMSG lines will be hold for up to `$paste_wait` seconds, lines in this interval will be packed to a multiline message
- telegram-cli related options
  + `--telegram-cli-command telegram-cli`, telegram-cli command name.
  + `--telegram-cli-port 1235`, telegram-cli listen port.
  + `--telegram-cli-timeout 10`, telegram-cli request (like `load_photo`) timeout in seconds
  + `--telegram-cli-poll-channels 1031857103`, telegram-cli cannot receive messages in some channels <https://github.com/vysheng/tg/issues/1135>, specify their `peer_id` to poll messages with the `history` command
  + `--telegram-cli-poll-interval 10`, interval in seconds
  + `--telegram-cli-poll-limit 10`, `history channel#{peer_id} {telegram_cli_poll_limit}`

See [telegramircd.service](telegramircd.service) for a template of `/etc/systemd/system/telegramircd.service`. Change `User=` and `Group=`. Change the `User=` and `Group=` fields.

## Demo

![](https://maskray.me/static/2016-05-07-telegramircd/telegramircd.jpg)

## Known issues

- telegram-cli cannot receive messages (most messages if not all, `tgl/mtproto-client.c:rpc_execute`) from some channels <https://github.com/vysheng/tg/issues/1135>.
  Use `/list` to get their `peer_id`:

  ```
  &test0(0): channel#1000000000 test0
  &test1(0): channel#1000000001 test1
  End of LIST
  ```

  Specify `--telegram-cli-poll-channels 1000000000 1000000001` to make telegramircd poll messages with the `history channel#{channel_id} 10` command.
- Blocked users do not have the `TGLUF_BLOCKED` flag (<https://github.com/vysheng/tgl/blob/master/tgl-layout.h>) before doing `user_info`
