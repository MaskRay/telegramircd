[简体中文](README.zhs.md)

# telegramircd [![IRC](https://img.shields.io/badge/IRC-freenode-yellow.svg)](https://webchat.freenode.net/?channels=wechatircd) [![Telegram](https://img.shields.io/badge/chat-Telegram-blue.svg)](https://t.me/wechatircd) [![Gitter](https://img.shields.io/badge/chat-Gitter-753a88.svg)](https://gitter.im/wechatircd/wechatircd)

telegramircd is an IRC server that enables IRC clients to send and receive messages from Telegram.

telegramircd uses [telethon-sync](https://github.com/LonamiWebs/Telethon) to communicate with Telegram servers.

## Installation

- `git clone https://github.com/MaskRay/telegramircd && cd telegramircd`
- python >= 3.5
- libmagic
- `pip3 install -r requirements.txt`

Create a Telegram App.

- Visit <https://my.telegram.org/apps>, create an App, and get `app_id, app_hash`.
- Update `config`: change `tg-api-id, tg-api-hash, tg-phone`; change `tg-session-dir` to the directory where you want to store `telegramircd.session` (defaults to `.` for current working directory, it will be created after the initial login)
- `./telegramircd.py -c config`

### Arch Linux

The `git clone` and `pip3 install -r requirements.txt` steps can be replaced with:

- Install `aur/telegramircd-git` (which depends on `aur/python-telethon`. You may also use `archlinuxcn/python-telethon`).
- The server is installed at `/usr/bin/telegramircd`.

A systemd service template is install at `/lib/systemd/system/telegramircd.service`. You may create `/etc/systemd/system/telegramircd.service` from the template. Change the `User=` and `Group=` fields to whom `telethon` is installed with. Run `systemctl start telegramircd`.

## Running telegramircd

`telegramircd.py` (the server) will listen on 127.0.0.1:6669 (IRC, `irc-listen, irc-port`) and 127.0.0.1:9003 (HTTPS + WebSocket over TLS, `http-url`).

Connect to the IRC server with you favorite IRC client. You will join the channel `+telegram` automatically. For the first login, you need to type `/oper a $login_code` where `$login_code` is sent to your phone as a short message. If two-step verification is enabled, you will need to type `/oper a $password`. A file named `$tg_session.session` is saved in `$tg_session_dir`, and login code is not required for future logins.

Session files can also be created by executing `TelegramClient(session_name, api_id, api_hash)` (see <https://github.com/LonamiWebs/Telethon>).

If you run the server on another machine, it is recommended to set up IRC over TLS and an IRC connection password with a few more options: `--irc-cert /path/to/irc.key --irc-key /path/to/irc.cert --irc-password yourpassword`. As an alternative to the IRC connection password, you may specify `--sasl-password yourpassword` and authenticate with SASL PLAIN. You can reuse the HTTPS certificate+key. If you use WeeChat and find it difficult to set up a valid certificate (gnutls checks the hostname), type the following lines in WeeChat:
```
/set irc.server.telegram.ssl on
/set irc.server.telegram.ssl_verify off
/set irc.server.telegram.password yourpassword
```

### Serve file links via HTTPS

A few more options: `--http-key /etc/telegramircd/key.pem --http-cert /etc/telegramircd/cert.pem --http-url https://127.1:9003`. File links will be shown as `https://127.1:9003/document/$id`.

You may create a CA certificate/key pair and use that to sign another certificate/key pair.

```zsh
openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key.pem -out ca.cert.pem -days 9999 -subj '/CN=127.0.0.1'
openssl req -new -newkey rsa:2048 -nodes -keyout key.pem -subj '/CN=127.0.0.1' |
  openssl x509 -req -out cert.pem -CAkey ca.key.pem -CA ca.cert.pem -set_serial 2 -days 9999 -extfile <(
    printf "subjectAltName = IP:127.0.0.1, DNS:localhost")
```

Chrome/Chromium

- Visit `chrome://settings/certificates`, import `ca.cert.pem`, click the `Authorities` tab, select the `127.0.0.1` certificate, Edit->Trust this certificate for identifying websites.

The IP address or the domain name should match the `subjectAlternativeName` fields. Chrome has removed support for `commonName` matching in certificates since version 58. See <https://developers.google.com/web/updates/2017/03/chrome-58-deprecations#remove_support_for_commonname_matching_in_certificates> for detail.

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
- `--mark-read`, when to `mark_read` private messages from users
  + `always`, `mark_read` all messages
  + `reply`, default: `mark_read` when sending messages to the peer
  + `never`, never
- `--paste-wait`, PRIVMSG lines will be hold for up to `$paste_wait` seconds, lines in this interval will be packed to a multiline message
- `--sasl-password pass`, set the SASL password to `pass`.
- `--special-channel-prefix`, choices: `&`, `!`, `#`, `##`, prefix for SpecialChannel. [Quassel](quassel-irc.org) does not seem to support channels with prefixes `&`, `--special-channel-prefix '##'` to make Quassel happy
- Telegram related options
  + `--tg-phone`, phone number
  + `--tg-api-id`
  + `--tg-api-hash`
  + `--tg-session telegramircd`, session filename.
  + `--tg-session-dir .`, where to save session file

See [telegramircd.service](example_services/telegramircd.service) for a template of `/etc/systemd/system/telegramircd.service`. Change `User=` and `Group=`. Change the `User=` and `Group=` fields.

## Demo

![](https://maskray.me/static/2016-05-07-telegramircd/telegramircd.jpg)

## Known issues

- Sometimes `struct.error: required argument is not an integer` when calling `self.channel_get_participants(channel)`
