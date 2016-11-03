# telegramircd

telegramircd injects JavaScript (`webogram.patch`) to web.telegram.org, which uses WebSocket to communicate with an IRC server (`telegramircd.py`), thus enable IRC clients connected to the server to send and receive messages from Telegram.

## Installation

`>=python-3.5`

`pip install -r requirements.txt`

### Arch Linux

- `yaourt -S telegramircd-git`. It will generate a self-signed key/certificate pair in `/etc/telegramircd/` (see below).
- Import `/etc/telegramircd/cert.pem` to the browser (see below).
- `systemctl start telegramircd`, which runs `/usr/bin/telegramircd --http-cert /etc/telegramircd/cert.pem --http-key /etc/telegramircd/key.pem --http-root /usr/share/telegramircd`.

The IRC server listens on 127.0.0.1:6669 (IRC) and 127.0.0.1:9003 (HTTPS + WebSocket over TLS) by default.

If you run the server on another machine, it is recommended to set up IRC over TLS and an IRC connection password: `/usr/bin/telegramircd --http-cert /etc/telegramircd/cert.pem --http-key /etc/telegramircd/key.pem --http-root /usr/share/telegramircd --irc-cert /path/to/irc.key --irc-key /path/to/irc.cert --irc-password yourpassword`.

You can reuse the HTTPS certificate+key as IRC over TLS certificate+key. If you use WeeChat and find it difficult to set up a valid certificate (gnutls checks the hostname), type the following lines in WeeChat:
```
set irc.server.telegram.ssl on`
set irc.server.telegram.ssl_verify off
set irc.server.telegram.password yourpassword`
```

### Not Arch Linux

- Generate a self-signed private key/certificate pair with `openssl req -newkey rsa:2048 -nodes -keyout key.pem -x509 -out cert.pem -subj '/CN=127.0.0.1' -dates 9999`.
- Import `cert.pem` to the browser.
- `./telegramircd.py --tls-cert cert.pem --tls-key key.pem`

### Import self-signed certificate to the browser

The JavaScript in the web client will be redirected to a modified one served by the server `telegramircd.py`. It needs a self-signed certificate to serve the JavaScript file through HTTPS and communicate with the JavaScript through WebSocket over TLS.

Chrome/Chromium

- Visit `chrome://settings/certificates`, import `cert.pem`, click the `Authorities` tab, select the `127.0.0.1` certificate, Edit->Trust this certificate for identifying websites.
- Install extension Switcheroo Redirector, redirects <https://web.telegram.org/js/app.js> to <https://127.0.0.1:9003/app.js>.

Firefox

- Install extension Redirector, redirects `app.js` as above, click ` Applies to: Main window (address bar), Scripts`.
- Visit the redirected JavaScript URL, Firefox will show "Your connection is not secure", Advanced->Add Exception->Confirm Security Exception.

### Headless browser in Linux

- Create a new browser user profile with `/opt/google/chrome/google-chrome --user-data-dir=$HOME/.config/google-chrome-telegramircd https://web.telegram.org`, and do the aforementioned configuration.
- Install xvfb
- Run `/opt/google/chrome/google-chrome --user-data-dir=$HOME/.config/google-chrome-telegramircd https://web.telegram.org`

## Usage

- Run `telegramircd.py` to start the IRC + HTTPS + WebSocket server.
- Visit <https://web.telegram.org>, the injected JavaScript will create a WebSocket connection to the server
- Connect to 127.0.0.1:6669 in your IRC client

You will join `+telegram` channel automatically and find your contact list there. Some commands are available:

- `help`
- `status`, mutual contact list、group/supergroup list

## Server options

- Join mode. There are three modes, the default is `--join auto`: join the channel upon receiving the first message. The other two are `--join all`: join all the channels; `--join manual`: no automatic join.
- Groups that should not join automatically. This feature supplements join mode.
  + `--ignore 'fo[o]' bar`, do not auto join chatrooms whose channel name(generated from DisplayName) matches regex `fo[o]` or `bar`
  + `--ignore-topic 'fo[o]' bar`, do not auto join chatrooms whose topics matches regex `fo[o]` or `bar`
- Surnames come first when displaying Chinese names. `SpecialUser#name`
- History mode. The default is to receive history messages, specify `--history false` to turn off the mode.
- HTTP/WebSocket related options
  + `--http-cert cert.pem`, TLS certificate for HTTPS/WebSocket. You may concatenate certificate+key, specify a single PEM file and omit `--http-key`. Use HTTP if neither --http-cert nor --http-key is specified.
  + `--http-key key.pem`, TLS key for HTTPS/WebSocket.
  + `--http-listen 127.1 ::1`, change HTTPS/WebSocket listen address to `127.1` and `::1`, overriding `--listen`.
  + `--http-port 9003`, change HTTPS/WebSocket listen port to 9003.
  + `--http-root .`, the root directory to serve `app.js`.
- `-l 127.0.0.1`, change IRC/HTTP/WebSocket listen address to `127.0.0.1`.
- IRC related options
  + `--irc-cert cert.pem`, TLS certificate for IRC over TLS. You may concatenate certificate+key, specify a single PEM file and omit `--irc-key`. Use plain IRC if neither --irc-cert nor --irc-key is specified.
  + `--irc-key key.pem`, TLS key for IRC over TLS.
  + `--irc-listen 127.1 ::1`, change IRC listen address to `127.1` and `::1`, overriding `--listen`.
  + `--irc-password pass`, set the connection password to `pass`.
  + `--irc-port 6669`, IRC server listen port.
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
- `/names`, update nicks in the channel.
- `/part $channel`, no longer receive messages from the channel. It just borrows the command `/part` and it will not leave the group.
- `/query $nick`, open a chat window with `$nick`.
- `/who $channel`, see the member list.

Multi-line messages: `!m line0\nline1\nline2`

## Demo

![](https://maskray.me/static/2016-05-07-telegramircd/run.jpg)

- `[Doc] $filename filesystem:https://web.telegram.org/temporary/t_filexxxxxxxxxxxxxxx`
- `[Photo] filesystem:https://web.telegram.org/temporary/xxxxxxxxxxx`

vte based terminal emulators expose the function for URI detection, but it does not recognize `filesystem:https://`. Replace `vte3-ng` with my `aur/vte3-ng-fullwidth-emoji` to support this URI scheme.

## Build `app.js` from source

```
git clone https://github.com/zhukov/webogram
cd webogram
git checkout 9cf85f3a0d4e9f3e170eaed2b27ba6b0aed3952e
patch -Np1 -i ../webogram.patch
make
cp dist/js/app.js /path/to/telegramircd/
```

## Known issues

- Messages delivered to a supergroup are different from messages to a group. They do not include the `random_id` field, it is hard to tell whether they are generated from the IRC client.
