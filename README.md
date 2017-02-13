# telegramircd

telegramircd is an IRC server that enables IRC clients to send and receive messages from Telegram.

### Arch Linux

- `aur/telegramircd-git`
- `aur/telegram-cli-git`. telegramircd uses the JSON output of telegram-cli to communicate with Telegram servers. Run `telegram-cli` and login to get credential before using telegramircd.
- Create `/etc/systemd/system/telegramircd.service` from the template `/lib/systemd/system/telegramircd.service`
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
- `./telegramircd.py --http-uri http://localhost:9003`

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

- Standard IRC channels have names beginning with `#`.
- Telegram channels/chats have names beginning with `&`. The channel name is generated from the group title. `SpecialChannel#update`
- Contacts have modes `+v` (voice, usually displayed with a prefix `+`). `SpecialChannel#update_detail`
- Multi-line messages: `!m line0\nline1`
- Multi-line messages: `!html line0<br>line1`
- `nick0: nick1: test` will be converted to `@GroupAlias0 @GroupAlias1 test`, where `GroupAlias0` is the name set by that user, not your `Set Remark and Tag`. It corresponds to `On-screen names` in the mobile application.
- Reply to the message at 12:34:SS: `@1234 !m multi\nline\nreply`, which will be sent as `「Re GroupAlias: text」text`
- Reply to the message at 12:34:56: `!m @123456 multi\nline\nreply`
- Reply to the penultimate message in this channel/chat: `@2 reply`

`!m `, `@3 `, `nick: ` can be arranged in any order.

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
- `/squit $any`, log out
- `/topic topic`, change the topic of a group. Because IRC does not support renaming of a channel, you will leave the channel with the old name and join a channel with the new name.
- `/who $channel`, see the member list.

## Server options

- Join mode, short option `-j`
  + `--join auto`, default: join the channel upon receiving the first message, no rejoin after issuing `/part` and receiving messages later
  + `--join all`: join all the channels
  + `--join manual`: no automatic join
  + `--join new`: like `auto`, but rejoin when new messages arrive even if after `/part`
- Surnames come first when displaying Chinese names. `SpecialUser#name`
- HTTP/WebSocket related options
  + `--http-cert cert.pem`, TLS certificate for HTTPS. You may concatenate certificate+key, specify a single PEM file and omit `--http-key`. Use HTTP if neither --http-cert nor --http-key is specified.
  + `--http-url http://localhost`, Show file links as http://localhost/document/$id .
  + `--http-key key.pem`, TLS key for HTTPS.
  + `--http-listen 127.1 ::1`, change HTTPS listen address to `127.1` and `::1`, overriding `--listen`.
  + `--http-port 9003`, change HTTPS listen port to 9003.
- `--listen 127.0.0.1`, short option `-l`, change IRC/HTTP/WebSocket listen address to `127.0.0.1`.
- IRC related options
  + `--irc-cert cert.pem`, TLS certificate for IRC over TLS. You may concatenate certificate+key, specify a single PEM file and omit `--irc-key`. Use plain IRC if neither --irc-cert nor --irc-key is specified.
  + `--irc-key key.pem`, TLS key for IRC over TLS.
  + `--irc-listen 127.1 ::1`, change IRC listen address to `127.1` and `::1`, overriding `--listen`.
  + `--irc-nicks ray ray1`, reverved nicks for clients. `SpecialUser` will not have these nicks.
  + `--irc-password pass`, set the connection password to `pass`.
  + `--irc-port 6669`, IRC server listen port.
- telegram-cli related options
  + `--telegram-cli-command telegram-cli`, telegram-cli command name.
  + `--telegram-cli-port 1235`, telegram-cli listen port.
  + `--telegram-cli-timeout 10`, telegram-cli request (like `load_photo`) timeout in seconds
  + `--telegram-cli-poll-channels 1031857103`, telegram-cli cannot receive messages in some channels <https://github.com/vysheng/tg/issues/1135>, specify their `peer_id` to poll messages with the `history` command
  + `--telegram-cli-poll-interval 10`, interval in seconds
  + `--telegram-cli-poll-limit 10`, `history channel#{peer_id} {telegram_cli_poll_limit}`
- Server side log
  + `--logger-ignore '&test0' '&test1'`, list of ignored regex, do not log contacts/groups whose names match
  + `--logger-mask '/tmp/telegram/$channel/%Y-%m-%d.log'`, format of log filenames
  + `--logger-time-format %H:%M`, time format of server side log

See [telegramircd.service](telegramircd.service) for a template of `/etc/systemd/system/telegramircd.service`.

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
