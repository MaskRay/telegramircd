# telegramircd

telegramircd is an IRC server that enables IRC clients to send and receive messages from Telegram.

## Installation

- `>=python-3.5`, `pip install --user -r requirements.txt`
- `telegram-cli`. telegramircd uses the JSON output of telegram-cli to communicate with Telegram servers. Run `telegram-cli` and login to get credential.

### Arch Linux

- `aur/telegramircd-git`
- `aur/telegram-cli-git`
- Create `/etc/systemd/system/telegramircd.service` from the template `/lib/systemd/system/telegramircd.service`
- `systemctl start telegramircd`

The IRC server listens on 127.0.0.1:6669 (IRC) and 127.0.0.1:9003 (HTTP) by default.

Specify `--http-host 127.1:9003` to display file links as `http://127.1:9003/photo/$id`.
File links can be served via HTTPS with `--http-key` and `--http-cert`: `/usr/bin/telegramircd --http-key /etc/telegramircd/key.pem --http-cert /etc/telegramircd/cert.pem --http-host 127.1:9003`. File links will be shown as `https://127.1:9003/photo/$id`.

If you run the server on another machine, it is recommended to set up IRC over TLS and an IRC connection password: `/usr/bin/telegramircd --http-key /etc/telegramircd/key.pem --http-cert /etc/telegramircd/cert.pem --irc-cert /path/to/irc.key --irc-key /path/to/irc.cert --irc-password yourpassword`.

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
ExecStart=/usr/bin/telegramircd --join new --http-key /etc/telegramircd/key.pem --http-cert /etc/telegramircd/cert.pem --http-host file_links_host:12345 --logger-mask '/tmp/telegramircd/$channel/%%Y-%%m-%%d.log' --ignore 污水群
```

N.B. in systemd.unit files, use `%%` in place of `%` to specify a single percent sign.

### Import self-signed certificate to the browser

`openssl req -newkey rsa:2048 -nodes -keyout key.pem -x509 -out cert.pem -subj '/CN=127.0.0.1' -dates 9999`.

Chrome/Chromium

- Visit `chrome://settings/certificates`, import `cert.pem`, click the `Authorities` tab, select the `127.0.0.1` certificate, Edit->Trust this certificate for identifying websites.

Firefox

- Install extension Redirector, redirects `app.js` as above, click ` Applies to: Main window (address bar), Scripts`.
- Visit one file link, Firefox will show "Your connection is not secure", Advanced->Add Exception->Confirm Security Exception.

## Usage

- Run `telegramircd.py` to start the IRC + HTTP/HTTPS.
- Connect to 127.0.0.1:6669 in your IRC client

You will join `+telegram` channel automatically and find your contact list there. Some commands are available:

- `help`
- `status`, mutual contact list、group/supergroup list

## Server options

- Join mode. There are three modes, the default is `--join auto`: join the channel upon receiving the first message, no rejoin after issuing `/part` and receiving messages later. The other three are `--join all`: join all the channels; `--join manual`: no automatic join; `--join new`: like `auto`, but rejoin when new messages arrive even if after `/part`.
- Groups that should not join automatically. This feature supplements join mode.
  + `--ignore 'fo[o]' bar`, do not auto join chatrooms whose channel name(generated from DisplayName) matches regex `fo[o]` or `bar`
  + `--ignore-topic 'fo[o]' bar`, do not auto join chatrooms whose topics matches regex `fo[o]` or `bar`
- Surnames come first when displaying Chinese names. `SpecialUser#name`
- History mode. The default is to receive history messages, specify `--history false` to turn off the mode.
- HTTP related options
  + `--http-cert cert.pem`, TLS certificate for HTTPS. You may concatenate certificate+key, specify a single PEM file and omit `--http-key`. Use HTTP if neither --http-cert nor --http-key is specified.
  + `--http-host $host`, Show file links as http://$host/photo/$id .
  + `--http-key key.pem`, TLS key for HTTPS.
  + `--http-listen 127.1 ::1`, change HTTPS listen address to `127.1` and `::1`, overriding `--listen`.
  + `--http-port 9003`, change HTTPS listen port to 9003.
- `-l 127.0.0.1`, change IRC/HTTP listen address to `127.0.0.1`.
- IRC related options
  + `--irc-cert cert.pem`, TLS certificate for IRC over TLS. You may concatenate certificate+key, specify a single PEM file and omit `--irc-key`. Use plain IRC if neither --irc-cert nor --irc-key is specified.
  + `--irc-key key.pem`, TLS key for IRC over TLS.
  + `--irc-listen 127.1 ::1`, change IRC listen address to `127.1` and `::1`, overriding `--listen`.
  + `--irc-password pass`, set the connection password to `pass`.
  + `--irc-port 6669`, IRC server listen port.
- telegram-cli related options
  + `--telegram-cli-command telegram-cli`, telegram-cli command name.
  + `--telegram-cli-port 1235`, telegram-cli listen port.
  + `--telegram-cli-timeout 10`, telegram-cli request (like `load_photo`) timeout in seconds
- Server side log
  + `--logger-ignore '&test0' '&test1'`, list of ignored regex, do not log contacts/groups whose names match
  + `--logger-mask '/tmp/telegram/$channel/%Y-%m-%d.log'`, format of log filenames
  + `--logger-time-format %H:%M`, time format of server side log

## IRC features

- Standard IRC channels have names beginning with `#`.
- Telegram groups have names beginning with `&`. The channel name is generated from the group title. `SpecialChannel#update`
- Mutual contacts have modes `+v` (voice, usually displayed with a prefix `+`). `SpecialChannel#update_detail`
- `channelParticipantCreator`, `channelParticipantModerator` have modes `+o` (op, usually displayed with a prefix `@`).
- `channelParticipantEditor` have modes `+h` (halfop).

`server-time` extension from IRC version 3.1, 3.2. `telegramircd.py` includes the timestamp (obtained from JavaScript) in messages to tell IRC clients that the message happened at the given time. See <http://ircv3.net/irc/>. See<http://ircv3.net/software/clients.html> for Client support of IRCv3.

Configuration for WeeChat:
```
/set irc.server_default.capabilities "account-notify,away-notify,cap-notify,multi-prefix,server-time,znc.in/server-time-iso,znc.in/self-message"
```

Supported IRC commands:

- `/cap`, supported capabilities.
- `/dcc send $nick/$channel $filename`, send image or file。This feature borrows the command `/dcc send` which is well supported in IRC clients. See <https://en.wikipedia.org/wiki/Direct_Client-to-Client#DCC_SEND>.
- `/list`, list groups.
- `/mode +m`, no rejoin in `--join new` mode. `/mode -m` to revert.
- `/names`, update nicks in the channel.
- `/part $channel`, no longer receive messages from the channel. It just borrows the command `/part` and it will not leave the group.
- `/query $nick`, open a chat window with `$nick`.
- `/who $channel`, see the member list.

Multi-line messages: `!m line0\nline1\nline2`

## Demo

![](https://maskray.me/static/2016-05-07-telegramircd/run.jpg)

## Known issues

- I do not know how to retrieve members of a `chat` (not `channel`).
