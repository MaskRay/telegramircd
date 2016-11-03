# telegramircd

telegramircd injects JavaScript (`webogram.patch`) to web.telegram.org, which uses WebSocket to communicate with an IRC server (`telegramircd.py`), thus enable IRC clients connected to the server to send and receive messages from Telegram.

## Installation

`>=python-3.5`

`pip install -r requirements.txt`

### Arch Linux

- `yaourt -S telegramircd-git`. It will generate a self-signed key/certificate pair in `/etc/telegramircd/` (see below).
- Import `/etc/telegramircd/cert.pem` to the browser (see below).
- `systemctl start telegramircd`, which runs `/usr/bin/telegramircd --tls-key /etc/telegramircd/key.pem --tls-cert /etc/telegramircd/cert.pem --http-root /usr/share/telegramircd`.

The IRC server listens on 127.0.0.1:6669 (IRC) and 127.0.0.1:9003 (HTTPS + WebSocket over TLS) by default.

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
- Groups that should not join automatically. This feature supplement join mode, use `--ignore aa bb` to specify ignored groups by matching generated channel names, `--ignore-topic xx yy` to specify ignored group titles.
- `$nick: ` will be converted to `@$nick ` to notify that user in Telegram. `Client#at_users`
- Surnames come first when displaying Chinese names. `SpecialUser#name`
- History mode. The default is to receive history messages, specify `--history false` to turn off the mode.
- `-l 127.0.0.1`, change IRC listen address to `127.0.0.1`.
- `-p 6669`, change IRC listen port to `6669`.
- `--web-port 9003`, change HTTPS/WebSocket listen port to 9003.
- `--http-root .`, the root directory to serve `app.js`.
- `--tls-key`, TLS key for HTTPS/WebSocket.
- `--tls-cert`, TLS certificate for HTTPS/WebSocket.
- `--logger-ignore '&test0' '&test1'`, list of ignored regex, do not log contacts/groups whose names match
- `--logger-mask '/tmp/wechat/$channel/%Y-%m-%d.log'`, server side log
- `--logger-time-format %H:%M`, time format of server side log

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
```

## Known issues

- Messages delivered to a supergroup are different from messages to a group. They do not include the `random_id` field, it is hard to tell whether they are generated from the IRC client.
