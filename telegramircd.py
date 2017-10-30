#!/usr/bin/env python3
from configargparse import ArgParser, Namespace
#from ipdb import set_trace as bp
from collections import deque
from datetime import datetime, timezone
from itertools import chain

from telethon import TelegramClient
import telethon.tl as tl
#from telethon.tl.functions.contacts import GetContactsRequest
import telethon.tl.types as tg_types
import telethon.tl.functions.contacts
import telethon.tl.functions.messages

import aiohttp.web, asyncio, base64, inspect, json, logging.handlers, mimetypes, os, pprint, random, re, \
    shlex, signal, socket, ssl, string, sys, tempfile, time, traceback, uuid, weakref

logger = logging.getLogger('telegramircd')
im_name = 'Telegram'
capabilities = set(['away-notify', 'draft/message-tags', 'echo-message', 'multi-prefix', 'sasl', 'server-time'])  # http://ircv3.net/irc/
options = None
server = None
web = None


def debug(msg, *args):
    logger.debug(msg, *args)


def info(msg, *args):
    logger.info(msg, *args)


def warning(msg, *args):
    logger.warning(msg, *args)


def error(msg, *args):
    logger.error(msg, *args)


class ExceptionHook(object):
    instance = None

    def __call__(self, *args, **kwargs):
        if self.instance is None:
            from IPython.core import ultratb
            self.instance = ultratb.VerboseTB(call_pdb=True)
        return self.instance(*args, **kwargs)


class TelegramCliFail(Exception):
    def __init__(self, *msg):
        super().__init__(*msg)

### HTTP server

class Web(object):
    def __init__(self, tls):
        global web
        web = self
        self.tls = tls
        self.id2media = {}
        self.id2message = {}
        self.recent_messages = deque()
        self.proc = None
        self.authorized = False
        self.two_step = False

    async def handle_media(self, type, request):
        id = re.sub(r'\..*', '', request.match_info.get('id'))
        if id not in self.id2media:
            return aiohttp.web.Response(status=404, text='Not Found')
        try:
            media, filename = self.id2media[id]
            if not filename:
                try:
                    with tempfile.NamedTemporaryFile(dir=options.tg_media_dir, suffix='.jpg') as temp:
                        filename = temp.name
                    self.proc.download_media(media, filename)
                    self.id2media[id] = (media, filename)
                except asyncio.TimeoutError:
                    return aiohttp.web.Response(status=504, text='I used to live in 504A')
                except TelegramCliFail as ex:
                    return aiohttp.web.Response(status=404, text=ex.args[0])
            with open(filename, 'rb') as f:
                return aiohttp.web.Response(body=f.read(),
                        headers={'Content-Type': mimetypes.guess_type(filename)[0]})
        except Exception as ex:
            return aiohttp.web.Response(status=500, text=str(ex))

    async def handle_document(self, request):
        return await self.handle_media('document', request)

    def run_telethon(self):
        if self.proc:
            self.proc.disconnect()
        self.proc = TelegramClient(options.tg_session, options.tg_api_id, options.tg_api_hash, update_workers=4)
        if not self.proc.connect():
            error('Failed to connect to Telegram server')
            sys.exit(2)
        self.authorized = self.proc.is_user_authorized()
        if not self.authorized and not options.tg_phone:
            error('Not authorized. Please set --tg-phone')
            sys.exit(2)
        self.proc.add_update_handler(server.on_telegram_update)

    async def restart_telegram_cli(self):
        traceback.print_stack()
        if self.proc:
            try:
                self.proc.disconnect()
                time.sleep(1)
            except:
                pass
        os.execl(sys.executable, sys.executable, *sys.argv)

    def start(self, listens, port, loop):
        self.loop = loop
        self.app = aiohttp.web.Application()
        self.app.router.add_route('GET', '/document/{id}', self.handle_document)
        self.handler = self.app.make_handler()
        self.srv = []
        for i in listens:
            self.srv.append(loop.run_until_complete(
                loop.create_server(self.handler, i, port, ssl=self.tls)))
        self.run_telethon()
        if self.authorized:
            self.init()

        #async def poll():
        #    while 1:
        #        await asyncio.sleep(options.tg_poll_interval)
        #        for peer_id in options.tg_poll_channels:
        #            self.proc.stdin.write('history channel#{} {}\n'.format(peer_id, options.tg_poll_limit).encode())

        #if options.telegram_cli_poll_channels:
        #    self.poll = loop.create_task(poll())

    def stop(self):
        self.proc.disconnect()
        for i in self.srv:
            i.close()
            self.loop.run_until_complete(i.wait_closed())
        self.loop.run_until_complete(self.app.shutdown())
        self.loop.run_until_complete(self.handler.finish_connections(0))
        self.loop.run_until_complete(self.app.cleanup())
        for _, filename in self.id2media.values():
            if filename:
                try:
                    os.unlink(filename)
                except:
                    pass

    def append_history(self, record):
        if len(self.recent_messages) >= 10000:
            msg = self.recent_messages.popleft()
            del self.id2message[msg['id']]
        self.recent_messages.append(record)
        self.id2message[record['id']] = record

    # TODO admin channel.update_admins(members)
    def channel_get_participants(self, channel):
        tg_users = []
        offset = 0
        while True:
            participants = self.proc.invoke(tl.functions.channels.GetParticipantsRequest(
                channel.tg_room,
                tl.types.ChannelParticipantsSearch(''),
                offset,
                100,
            ))
            if not participants.users: break
            tg_users.extend(participants.users)
            offset += len(participants.users)
        channel.update_members(tg_users)

    def channel_invite(self, client, channel, user):
        try:
            if channel.is_type(tl.types.PeerChannel):
                # TODO
                pass
            elif channel.is_type(tl.types.PeerChat):
                self.proc.invoke(tl.functions.messages.AddChatUserRequest(
                    channel.peer.chat_id,
                    self.proc.get_input_entity(user.user_id),
                    0,
                ))
        except telethon.errors.rpc_error_list.UserAlreadyParticipantError:
            client.err_useronchannel(user.nick, channel.name)
        except telethon.errors.rpc_base_errors.RPCError:
            pass

    async def channel_set_admin(self, client, channel, user, ty):
        if channel.is_type(tl.types.PeerChannel):
            try:
                await self.send_command('channel_set_admin {} {} {}'.format(channel.peer, user.peer, ty))
            except (asyncio.TimeoutError, TelegramCliFail):
                client.err_chanoprivsneeded(channel.name)
            else:
                if ty == 0:
                    self.unset_cmode(user, 'h')
                    self.unset_cmode(user, 'o')
                elif ty == 1:
                    self.set_cmode(user, 'h')
                    channel.halfop_event(user)
                elif ty == 2:
                    self.set_cmode(user, 'o')
                    channel.op_event(user)
        else:
            client.err_chanoprivsneeded(channel.name)

    def channel_kick(self, client, channel, user):
        try:
            if channel.is_type(tl.types.PeerChannel):
                pass
            elif channel.is_type(tl.types.PeerChat):
                self.proc.invoke(tl.functions.messages.DeleteChatUserRequest(
                    channel.peer.chat_id,
                    self.proc.get_input_entity(user.user_id),
                ))
        except telethon.errors.rpc_error_list.UserNotParticipantError:
            client.err_usernotinchannel(user.nick, channel.name)
        except telethon.errors.rpc_base_errors.RPCError:
            pass

    #async def channel_list(self):
    #    for data in await self.send_command('channel_list'):
    #        if not (data['flags'] & TGLCF_DEACTIVATED):
    #            server.ensure_special_room(data)

    #async def chat_info(self, channel):
    #    data = await self.send_command('chat_info {}'.format(channel.peer))
    #    channel.update_members(data['members'])
    #from telethon.tl.functions.channels import GetParticipantsRequest
    #from telethon.tl.types import ChannelParticipantsSearch
    #from time import sleep
    #
    #offset = 0
    #limit = 100
    #all_participants = []
    #
    #while True:
    #    participants = client.invoke(GetParticipantsRequest(
    #        channel, ChannelParticipantsSearch(''), offset, limit
    #    ))
    #    if not participants.users:
    #        break
    #    all_participants.extend(participants.users)
    #    offset += len(participants.users)
    #    # sleep(1)  # This line seems to be optional, no guarantees!

    def contact_list(self):
        contacts = self.proc(tl.functions.contacts.GetContactsRequest(0))
        for tg_user in contacts.users:
            server.ensure_special_user(tg_user.id, tg_user)

    def channel_list(self):
        # TODO retrieve all Channel/Chat
        _, entities = self.proc.get_dialogs(20)
        for entity in entities:
            if isinstance(entity, (tl.types.Channel, tl.types.Chat)):
                server.ensure_special_room(entity.id, entity)

    def message_get(self, id):
        messages = self.proc(tl.functions.messages.GetMessagesRequest([id])).messages
        return messages[0] if messages else None

    def get_self(self):
        data = self.proc.get_me()
        server.user_id = data.id

    def init(self):
        try:
            web.get_self()
            web.channel_list()
            web.contact_list()
        except Exception as ex:
            traceback.print_exc()

    def mark_read(self, peer, max_id):
        self.proc.send_read_acknowledge(peer, max_id=max_id)

    async def channel_members(self, channel):
        try:
            if channel.is_type(tl.types.PeerChannel):
                self.channel_get_participants(channel)
            elif channel.is_type(tl.types.PeerChat):
                # FIXME self.chat_info(channel)
                pass
        except Exception as ex:
            error('channel_members %r', channel)
            traceback.print_exc()

    def send_file(self, client, peer, filename, body):
        with tempfile.TemporaryDirectory() as directory:
            filename = os.path.join(directory, filename)
            try:
                with open(filename, 'wb') as f:
                    f.write(body)
                    f.flush()
                self.proc.send_file(peer, f.name)
            except TelegramCliFail as ex:
                client.err_cannotsendtochan(peer.nick, 'Cannot send the file')
            os.unlink(filename)

    def msg(self, client, peer, text):
        try:
            self.proc.send_message(peer, text)
        except telethon.errors.rpc_base_errors.RPCError:
            traceback.print_exc()
            if isinstance(peer, SpecialChannel):
                client.err_nosuchchannel(peer.name)
            elif isinstance(peer, SpecialUser):
                client.err_nosuchnick(peer.nick)

    def reply(self, client, peer, msg_id, text):
        try:
            self.proc.send_message(peer, text, reply_to=msg_id)
        except telethon.errors.rpc_base_errors.RPCError:
            traceback.print_exc()
            if isinstance(peer, SpecialChannel):
                client.err_nosuchchannel(peer.name)
            elif isinstance(peer, SpecialUser):
                client.err_nosuchnick(peer.nick)


### IRC utilities

def irc_lower(s):
    irc_trans = str.maketrans(string.ascii_uppercase + '[]\\^',
                              string.ascii_lowercase + '{}|~')
    return s.translate(irc_trans)


# loose
def irc_escape(s):
    s = re.sub(r',', '.', s)       # `,` is used as seprator in IRC messages
    s = re.sub(r'&amp;?', '', s)   # chatroom name may include `&`
    s = re.sub(r'<[^>]*>', '', s)  # remove emoji
    return re.sub(r'[^-\w$%^*()=./]', '', s)


def irc_escape_nick(s):
    return re.sub('^[&#!+:]*', '', irc_escape(s))


def process_text(to, text):
    # !m
    # @(\d\d)(\d\d)(\d\d)?
    reply = None
    multiline = False
    while 1:
        cont = False
        match = re.match(r'@(\d\d)(\d\d)(\d\d)? ', text)
        if match:
            cont = True
            text = text[match.end():]
            HH, MM, SS = int(match.group(1)), int(match.group(2)), match.group(3)
            if SS is not None:
                SS = int(SS)
            for msg in reversed(web.recent_messages):
                if msg['to'] is to:
                    dt = datetime.fromtimestamp(msg['date'])
                    if dt.hour == HH and dt.minute == MM and (SS is None or dt.second == SS):
                        reply = msg['id']
                        break
        match = re.match(r'@(\d{1,2}) ', text)
        if match:
            cont = True
            text = text[match.end():]
            which = int(match.group(1))
            in_channel = isinstance(to, SpecialChannel)
            if which > 0:
                for msg in reversed(web.recent_messages):
                    if (msg['to'] is to and msg['from'] is not server) if in_channel \
                            else (msg['from'] is to and msg['to'] is server):
                        which -= 1 if 'media' in msg else len(msg['message'].splitlines())
                        if which <= 0:
                            reply = msg['id']
                            break
        if text.startswith('!m '):
            cont = True
            text = text[3:]
            multiline = True
        if not cont: break
    if multiline:
        text = text.replace('\\n', '\n')

    # nick: -> @username
    at = ''
    i = 0
    while i < len(text) and text[i] != ' ':
        j = text.find(': ', i)
        if j == -1: break
        nick = text[i:j]
        if not server.has_special_user(nick): break
        at += '@'+server.get_special_user(nick).preferred_nick()+' '
        i = j+2
    return reply, at + text[i:]


def irc_log(where, peer, local_time, sender, line):
    if options.logger_mask is None:
        return
    for regex in options.logger_ignore or []:
        if re.search(regex, peer.name):
            return
    filename = local_time.strftime(options.logger_mask.replace('$channel', peer.nick))
    time_str = local_time.strftime(options.logger_time_format.replace('$channel', peer.nick))
    if where.log_file is None or where.log_file.name != filename:
        if where.log_file is not None:
            where.log_file.close()
        os.makedirs(os.path.dirname(filename), exist_ok=True)
        where.log_file = open(filename, 'a')
    where.log_file.write('{}\t{}\t{}\n'.format(
        time_str, sender.nick,
        re.sub(r'\x03\d+(,\d+)?|[\x02\x0f\x1d\x1f\x16]', '', line)))
    where.log_file.flush()


def irc_privmsg(client, command, to, text):
    if command == 'PRIVMSG' and client.ctcp(to.peer, text):
        return

    def send():
        if to.privmsg_reply:
            print('+++++', client, to.peer, reply, to.privmsg_text)
            web.reply(client, to.peer, reply, to.privmsg_text)
        else:
            web.msg(client, to.peer, to.privmsg_text)
        to.last_text_by_client[client] = to.privmsg_text
        to.privmsg_reply = None
        to.privmsg_text = ''

    async def wait(seq):
        await asyncio.sleep(options.paste_wait)
        if to.privmsg_seq == seq:
            send()

    reply, text = process_text(to, text)
    if reply and len(to.privmsg_text):
        send()
    to.privmsg_reply = reply
    to.privmsg_seq = to.privmsg_seq+1
    if len(to.privmsg_text):
        to.privmsg_text += '\n'
    to.privmsg_text += text
    server.loop.create_task(wait(to.privmsg_seq))

### Commands

cmd_use_case = {}


def registered(v):
    def wrapped(fn):
        cmd_use_case[fn.__name__] = v
        return fn
    return wrapped


class Command:
    @staticmethod
    @registered(7)
    def authenticate(client, arg):
        if arg.upper() == 'PLAIN':
            client.write('AUTHENTICATE +')
            return
        if not (client.nick and client.user):
            return
        try:
            if base64.b64decode(arg).split(b'\0')[2].decode() == options.sasl_password:
                client.authenticated = True
                client.reply('900 {} {} {} :You are now logged in as {}', client.nick, client.user, client.nick, client.nick)
                client.reply('903 {} :SASL authentication successful', client.nick)
                client.register()
            else:
                client.reply('904 {} :SASL authentication failed', client.nick)
        except:
            client.reply('904 {} :SASL authentication failed', client.nick)

    @staticmethod
    def away(client):
        pass

    @staticmethod
    @registered(7)
    def cap(client, *args):
        if not args: return
        comm = args[0].lower()
        if comm == 'list':
            client.reply('CAP * LIST :{}', ' '.join(client.capabilities))
        elif comm == 'ls':
            client.reply('CAP * LS :{}', ' '.join(capabilities))
        elif comm == 'req':
            enabled, disabled = set(), set()
            for name in args[1].split():
                if name.startswith('-'):
                    disabled.add(name[1:])
                else:
                    enabled.add(name)
            client.capabilities = (capabilities & enabled) - disabled
            client.reply('CAP * ACK :{}', ' '.join(client.capabilities))

    @staticmethod
    def info(client):
        client.rpl_info('{} users', len(server.nicks))
        client.rpl_info('{} {} users', im_name, len(client.nick2special_user))
        client.rpl_info('{} {} rooms', im_name, len(client.name2special_room))

    @staticmethod
    def invite(client, nick, channelname):
        if client.is_in_channel(channelname):
            server.get_channel(channelname).on_invite(client, nick)
        else:
            client.err_notonchannel(channelname)

    @staticmethod
    def ison(client, *nicks):
        client.reply('303 {} :{}', client.nick,
                     ' '.join(nick for nick in nicks
                              if server.has_nick(nick)))

    @staticmethod
    def join(client, *args):
        if not args:
            self.err_needmoreparams('JOIN')
        else:
            arg = args[0]
            if arg == '0':
                channels = list(client.channels.values())
                for channel in channels:
                    channel.on_part(client, channel.name)
            else:
                JOINCHAT = 'https://t.me/joinchat/'
                for channelname in arg.split(','):
                    # Join via joinchat link
                    if channelname.startswith(JOINCHAT):
                        web.proc(tl.functions.messages.ImportChatInviteRequest(channelname[len(JOINCHAT):]))
                    else:
                        if server.has_special_room(channelname):
                            server.get_special_room(channelname).on_join(client)
                        else:
                            try:
                                server.ensure_channel(channelname).on_join(client)
                            except ValueError:
                                client.err_nosuchchannel(channelname)

    @staticmethod
    def kick(client, channelname, nick, reason=None):
        if client.is_in_channel(channelname):
            server.get_channel(channelname).on_kick(client, nick, reason)
        else:
            client.err_notonchannel(channelname)

    @staticmethod
    def kill(client, nick, reason=None):
        if not server.has_nick(nick):
            client.err_nosuchnick(nick)
            return
        user = server.get_nick(nick)
        if not isinstance(user, Client) or user == client:
            client.err_nosuchnick(nick)
            return
        user.disconnect(reason)

    @staticmethod
    def list(client, arg=None):
        if arg:
            channels = []
            for channelname in arg.split(','):
                if server.has_channel(channelname):
                    channels.append(server.get_channel(channelname))
        else:
            web.init()
            channels = set(server.channels.values())
            channels.update(server.name2special_room.values())
            channels = list(channels)
        channels.sort(key=lambda ch: ch.name)
        for channel in channels:
            n = channel.n_members(client)
            if n == 0 and channel.is_type(tl.types.PeerChat):
                n = channel.tg_room.participants_count
            client.reply('322 {} {} {} :{}', client.nick, channel.name, n, channel.topic)
        client.reply('323 {} :End of LIST', client.nick)

    @staticmethod
    def lusers(client):
        client.reply('251 :There are {} users and {} {} users on 1 server',
                     len(server.nicks),
                     len(server.nick2special_user),
                     im_name
                     )

    @staticmethod
    def mode(client, target, *args):
        if server.has_nick(target):
            if args:
                client.err_umodeunknownflag()
            else:
                client.rpl_umodeis(server.get_nick(target).mode)
        elif server.has_channel(target):
            server.get_channel(target).on_mode(client, *args)
        else:
            client.err_nosuchchannel(target)

    @staticmethod
    def motd(client):
        async def do():
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get('https://api.github.com/repos/MaskRay/telegramircd/commits') as resp:
                        client.reply('375 {} :- {} Message of the Day -', client.nick, server.name)
                        data = await resp.json()
                        for x in data[:5]:
                            client.reply('372 {} :- {} {} {}'.format(client.nick, x['sha'][:7], x['commit']['committer']['date'][:10], x['commit']['message'].replace('\n', '\\n')))
                        client.reply('376 {} :End of /MOTD command.', client.nick)
            except:
                pass
        server.loop.create_task(do())

    @staticmethod
    def names(client, target):
        if not client.is_in_channel(target):
            client.err_notonchannel(target)
            return
        channel = server.get_channel(target)
        server.loop.create_task(web.channel_members(channel))
        channel.on_names(client)

    @staticmethod
    @registered(7)
    def nick(client, *args):
        if len(options.irc_password) and not client.authenticated:
            client.err_passwdmismatch('NICK')
            return
        if not args:
            client.err_nonicknamegiven()
            return
        server.change_nick(client, args[0])

    @staticmethod
    @registered(7)
    def oper(client, _, password):
        ok = False
        StatusChannel.instance.respond(client, 'Signing in...')
        if web.two_step:
            web.two_step = False
            ok = web.proc.sign_in(password=password)
            if not ok:
                StatusChannel.instance.respond(client, 'Wrong password. Please type /oper a $login_code; /oper a $password')
        else:
            try:
                ok = web.proc.sign_in(options.tg_phone, password)
                if not ok:
                    StatusChannel.instance.respond(client, 'Wrong login code. Please type /oper a $login_code')
            except SessionPasswordNeededError:
                web.two_step = True
                StatusChannel.instance.respond(client, 'Two step verification enabled. Please type /oper a $password')
        if ok:
            StatusChannel.instance.respond(client, 'Authorized. Initializing...')
            web.init()

    @staticmethod
    def notice(client, *args):
        Command.notice_or_privmsg(client, 'NOTICE', *args)

    @staticmethod
    def part(client, arg, *args):
        partmsg = args[0] if args else None
        for channelname in arg.split(','):
            if client.is_in_channel(channelname):
                server.get_channel(channelname).on_part(client, partmsg)
            else:
                client.err_notonchannel(channelname)

    @staticmethod
    @registered(6)
    def pass_(client, password):
        if len(options.irc_password) and password == options.irc_password:
            client.authenticated = True
            client.register()

    @staticmethod
    @registered(7)
    def ping(client, *args):
        if not args:
            client.err_noorigin()
            return
        client.reply('PONG {} :{}', server.name, args[0])

    @staticmethod
    @registered(7)
    def pong(client, *args):
        pass

    @staticmethod
    def privmsg(client, *args):
        Command.notice_or_privmsg(client, 'PRIVMSG', *args)

    @staticmethod
    @registered(7)
    def quit(client, *args):
        client.disconnect(args[0] if args else client.prefix)

    @staticmethod
    def squit(client, *args):
        client.err_unknowncommand('SQUIT')

    @staticmethod
    def stats(client, query):
        if len(query) == 1:
            if query == 'u':
                td = datetime.now() - server._boot
                client.reply('242 {} :Server Up {} days {}:{:02}:{:02}',
                             client.nick, td.days, td.seconds // 3600,
                             td.seconds // 60 % 60, td.seconds % 60)
            client.reply('219 {} {} :End of STATS report', client.nick, query)

    @staticmethod
    def summon(client, nick, msg):
        client.err_nologin(nick)

    @staticmethod
    def time(client):
        client.reply('391 {} {} :{}Z', client.nick, server.name,
                     datetime.utcnow().isoformat())

    @staticmethod
    def topic(client, channelname, new=None):
        if not client.is_in_channel(channelname):
            client.err_notonchannel(channelname)
            return
        server.get_channel(channelname).on_topic(client, new)

    @staticmethod
    def who(client, target):
        if server.has_channel(target):
            server.get_channel(target).on_who(client)
        elif server.has_nick(target):
            server.get_nick(target).on_who_member(client, server)
        client.reply('315 {} {} :End of WHO list', client.nick, target)

    @staticmethod
    def whois(client, *args):
        if not args:
            client.err_nonicknamegiven()
            return
        elif len(args) == 1:
            target = args[0]
        else:
            target = args[1]
        if server.has_nick(target):
            server.get_nick(target).on_whois(client)
        else:
            client.err_nosuchnick(target)
            return
        client.reply('318 {} {} :End of WHOIS list', client.nick, target)

    @classmethod
    def notice_or_privmsg(cls, client, command, *args):
        if not args:
            client.err_norecipient(command)
            return
        if len(args) == 1:
            client.err_notexttosend()
            return
        target = args[0]
        msg = args[1]
        # on name conflict, prefer to resolve user first
        if server.has_nick(target):
            user = server.get_nick(target)
            if isinstance(user, Client):
                user.write(':{} PRIVMSG {} :{}'.format(client.prefix, user.nick, msg))
            else:
                user.on_notice_or_privmsg(client, command, msg)
        # IRC channel or special chatroom
        elif client.is_in_channel(target):
            server.get_channel(target).on_notice_or_privmsg(
                client, command, msg)
        elif command == 'PRIVMSG':
            client.err_nosuchnick(target)

    @staticmethod
    @registered(6)
    def user(client, user, mode, _, realname):
        if len(options.irc_password) and not client.authenticated:
            client.err_passwdmismatch('USER')
            return
        client.user = user
        client.realname = realname
        client.register()

### Channels: StandardChannel, StatusChannel, SpecialChannel

class Channel:
    def __init__(self, name):
        self.name = name
        self.peer_type = ''
        self.topic = ''
        self.mode = 'n'
        self.members = {}

    def __repr__(self):
        return repr({k: v for k, v in self.__dict__.items()
            if k in ('name', 'topic')})

    @property
    def prefix(self):
        return self.name

    def log(self, source, fmt, *args):
        info('%s %s '+fmt, self.name, source.nick, *args)

    def multicast_group(self, source):
        return self.members.keys()

    def n_members(self, client):
        return len(self.members)

    def event(self, source, command, fmt, *args, include_source=True):
        line = fmt.format(*args) if args else fmt
        for client in self.multicast_group(source):
            if client != source or include_source:
                client.write(':{} {} {}'.format(source.prefix, command, line))

    def dehalfop_event(self, user):
        self.event(self, 'MODE', '{} -h {}', self.name, user.nick)

    def deop_event(self, user):
        self.event(self, 'MODE', '{} -o {}', self.name, user.nick)

    def devoice_event(self, user):
        self.event(self, 'MODE', '{} -v {}', self.name, user.nick)

    def halfop_event(self, user):
        self.event(self, 'MODE', '{} +h {}', self.name, user.nick)

    def nick_event(self, user, new):
        self.event(user, 'NICK', new)

    def join_event(self, user):
        self.event(user, 'JOIN', self.name)

    def kick_event(self, kicker, channel, kicked, reason=None):
        if reason:
            self.event(kicker, 'KICK', '{} {}: {}', channel.name, kicked.nick, reason)
        else:
            self.event(kicker, 'KICK', '{} {}', channel.name, kicked.nick)
        self.log(kicker, 'kicked %s', kicked.prefix)

    def op_event(self, user):
        self.event(self, 'MODE', '{} +o {}', self.name, user.nick)

    def part_event(self, user, partmsg):
        if partmsg:
            self.event(user, 'PART', '{} :{}', self.name, partmsg)
        else:
            self.event(user, 'PART', self.name)

    def voice_event(self, user):
        self.event(user, 'MODE', '{} +v {}', self.name, user.nick)

    def on_invite(self, client, nick):
        # TODO
        client.err_chanoprivsneeded(self.name)

    # subclasses should return True if succeeded to join
    def on_join(self, client):
        client.enter(self)
        self.join_event(client)
        self.on_topic(client)
        self.on_names(client)

    def on_kick(self, client, nick, reason):
        client.err_chanoprivsneeded(self.name)

    def on_mode(self, client):
        client.rpl_channelmodeis(self.name, self.mode)

    def on_names(self, client):
        self.on_names_impl(client, self.members.items())

    def on_names_impl(self, client, items):
        names = []
        for u, mode in items:
            nick = u.nick
            prefix = ''
            while 1:
                if 'o' in mode:
                    prefix += '@'
                    if 'multi-prefix' not in client.capabilities:
                        break
                if 'h' in mode:
                    prefix += '%'
                    if 'multi-prefix' not in client.capabilities:
                        break
                if 'v' in mode:
                    prefix += '+'
                    if 'multi-prefix' not in client.capabilities:
                        break
                break
            names.append(prefix+nick)
        buf = ''
        bytelen = 0
        maxlen = 510-1-len(server.name)-5-len(client.nick.encode())-3-len(self.name.encode())-2
        for name in names:
            if bytelen+1+len(name.encode()) > maxlen:
                client.reply('353 {} = {} :{}', client.nick, self.name, buf)
                buf = ''
                bytelen = 0
            if buf:
                buf += ' '
                bytelen += 1
            buf += name
            bytelen += len(name.encode())
        if buf:
            client.reply('353 {} = {} :{}', client.nick, self.name, buf)
        client.reply('366 {} {} :End of NAMES list', client.nick, self.name)

    def on_topic(self, client, new=None):
        if new:
            client.err_nochanmodes(self.name)
        else:
            if self.topic:
                client.reply('332 {} {} :{}', client.nick, self.name, self.topic)
            else:
                client.reply('331 {} {} :No topic is set', client.nick, self.name)


class StandardChannel(Channel):
    def __init__(self, name):
        super().__init__(name)

    def on_notice_or_privmsg(self, client, command, msg):
        self.event(client, command, '{} :{}', self.name, msg, include_source=False)

    def on_join(self, client):
        if client in self.members:
            return False
        # first user becomes op
        self.members[client] = 'o' if not self.members else ''
        super().on_join(client)
        return True

    def on_kick(self, client, nick, reason):
        if 'o' not in self.members[client]:
            client.err_chanoprivsneeded(self.name)
        elif not server.has_nick(nick):
            client.err_usernotinchannel(nick, self.name)
        else:
            user = server.get_nick(nick)
            if user not in self.members:
                client.err_usernotinchannel(nick, self.name)
            elif client != user:
                self.kick_event(client, self, user, reason)
                self.on_part(user, None)

    def on_part(self, client, msg=None):
        if client not in self.members:
            client.err_notonchannel(self.name)
            return False
        if msg:  # explicit PART, not disconnection
            self.part_event(client, msg)
        if len(self.members) == 1:
            server.remove_channel(self.name)
        elif 'o' in self.members.pop(client):
            user = next(iter(self.members))
            self.members[user] += 'o'
            self.op_event(user)
        client.leave(self)
        return True

    def on_topic(self, client, new=None):
        if new:
            self.log(client, 'set topic %r', new)
            self.topic = new
            self.event(client, 'TOPIC', '{} :{}', self.name, new)
        else:
            super().on_topic(client, new)

    def on_who(self, client):
        for member in self.members:
            member.on_who_member(client, self)


# A special channel where each client can only see himself
class StatusChannel(Channel):
    instance = None

    def __init__(self):
        super().__init__('+telegram')
        self.topic = "Your friends are listed here. Messages wont't be broadcasted to them. Type 'help' to see available commands"
        assert not StatusChannel.instance
        StatusChannel.instance = self

    def respond(self, client, fmt, *args):
        if args:
            client.write((':{} PRIVMSG {} :'+fmt).format(self.name, self.name, *args))
        else:
            client.write((':{} PRIVMSG {} :').format(self.name, self.name)+fmt)

    def multicast_group(self, source):
        return (x for x in self.members if isinstance(x, Client))

    def on_notice_or_privmsg(self, client, command, msg):
        if client not in self.members:
            client.err_notonchannel(self.name)
            return
        if msg == 'help':
            self.respond(client, 'help')
            self.respond(client, '  display this help')
            self.respond(client, 'eval expression')
            self.respond(client, '  eval a Python expression')
            self.respond(client, 'status [pattern]')
            self.respond(client, '  show contacts/chats/channels')
        elif msg.startswith('status'):
            pattern = None
            ary = msg.split(' ', 1)
            if len(ary) > 1:
                pattern = ary[1]
            self.respond(client, 'IRC channels:')
            for name, room in server.channels.items():
                if pattern is not None and pattern not in name: continue
                if isinstance(room, StandardChannel):
                    self.respond(client, '  ' + name)
            self.respond(client, '{} contacts:', im_name)
            for peer_id, user in server.user_id2special_user.items():
                if user.is_contact:
                    if pattern is not None and not (pattern in user.username or pattern in user.printname): continue
                    self.respond(client, '  ' + repr(user))
            self.respond(client, '{} chats/channels:', im_name)
            for peer_id, room in server.peer_id2special_room.items():
                if pattern is not None and pattern not in room.name: continue
                if isinstance(room, SpecialChannel):
                    self.respond(client, '  ' + room.name)
        else:
            m = re.match(r'eval (.+)$', msg.strip())
            if m:
                try:
                    r = pprint.pformat(eval(m.group(1)))
                except:
                    r = traceback.format_exc()
                for line in r.splitlines():
                    self.respond(client, line)
            else:
                self.respond(client, 'Unknown command {}', msg)

    def on_join(self, member):
        if isinstance(member, Client):
            if member in self.members:
                return False
            self.members[member] = 'o'
            super().on_join(member)
        else:
            if member in self.members:
                return False
            member.enter(self)
            self.join_event(member)
            if member.tg_user.mutual_contact:
                self.voice_event(member)
                self.members[member] = 'v'
            else:
                self.members[member] = ''
        return True

    def on_part(self, member, msg=None):
        if isinstance(member, Client):
            if member not in self.members:
                member.err_notonchannel(self.name)
                return False
            self.part_event(member, msg)
            del self.members[member]
        else:
            if member not in self.members:
                return False
            self.part_event(member, msg)
            del self.members[member]
        member.leave(self)
        return True

    def on_who(self, client):
        if client in self.members:
            client.on_who_member(client, self)


class SpecialChannel(Channel):
    def __init__(self, tg_room):
        super().__init__(None)
        if isinstance(tg_room, tl.types.Channel):
            self.peer = tl.types.PeerChannel(tg_room.id)
        elif isinstance(tg_room, tl.types.Chat):
            self.peer = tl.types.PeerChat(tg_room.id)
        else:
            assert False
        self.joined = {}      # `client` has not joined
        self.explicit_parted = set()
        self.update(tg_room)
        self.log_file = None
        self.last_text_by_client = weakref.WeakKeyDictionary()
        self.max_id = 0
        self.privmsg_reply = None
        self.privmsg_seq = 0
        self.privmsg_text = ''

    def __repr__(self):
        return repr({k: v for k, v in self.__dict__.items()
            if k in ('flags', 'name', 'peer')})

    @property
    def nick(self):
        return self.name

    def is_type(self, type):
        return isinstance(self.peer, type)

    def update(self, tg_room):
        self.tg_room = tg_room
        old_name = getattr(self, 'name', None)
        base = options.special_channel_prefix  + irc_escape(tg_room.title)
        #if base == options.special_channel_prefix:
        #    base += '.'.join(member.nick for member in self.members)[:20]
        suffix = ''
        while 1:
            name = base+suffix
            if name == old_name or not server.has_channel(name):
                break
            suffix = str(int(suffix or 0)+1)
        if name != old_name:
            # PART -> rename -> JOIN to notify the IRC client
            joined = [client for client in server.auth_clients() if client in self.joined]
            for client in joined:
                self.on_part(client, 'Changing name')
            self.name = name
            for client in joined:
                self.on_join(client)
        if self.is_type(tl.types.PeerChannel):
            topic = '{} {}'.format(self.peer.channel_id, tg_room.title.replace('\n', '\\n'))
        elif self.is_type(tl.types.PeerChat):
            topic = 'chat#{} {}'.format(self.peer.chat_id, tg_room.title.replace('\n', '\\n'))
        if self.topic != topic:
            self.topic = topic
            for client in server.auth_clients():
                client.reply('332 {} {} :{}', client.nick, self.name, self.topic)

    def update_admins(self, admins):
        seen_me = False
        seen = set()
        for admin in admins:
            user = server.ensure_special_user(admin)
            if user == server:
                seen_me = True
            elif user in self.members:
                seen.add(user)
        for client, mode in self.joined.items():
            if 'o' in mode and not seen_me:
                self.unset_cmode(user, 'o')
                self.deop_event(client)
            if 'o' not in mode and seen_me:
                self.set_cmode(user, 'o')
                self.op_event(client)
        for user, mode in self.members.items():
            if 'o' in mode and user not in seen:
                self.unset_cmode(user, 'o')
                self.deop_event(user)
            if 'o' not in mode and user in seen:
                self.set_cmode(user, 'o')
                self.op_event(user)

    def update_members(self, tg_users):
        seen = {}
        for tg_user in tg_users:
            user = server.ensure_special_user(tg_user.id, tg_user)
            if user != server:
                seen[user] = 'v' if user.is_contact else ''
        for user in self.members.keys() - seen.keys():
            self.on_part(user, self.name)
        for user in seen.keys() - self.members.keys():
            self.on_join(user)
        for user, mode in seen.items():
            old = self.members.get(user, '')
            if 'h' in old and 'h' not in mode:
                self.unset_cmode(user, 'h')
                self.dehalfop_event(user)
            if 'h' not in old and 'h' in mode:
                self.set_cmode(user, 'h')
                self.halfop_event(user)
            if 'v' in old and 'v' not in mode:
                self.unset_cmode(user, 'v')
                self.devoice_event(user)
            if 'v' not in old and 'v' in mode:
                self.set_cmode(user, 'v')
                self.voice_event(user)
        self.members = seen

    def multicast_group(self, source):
        ret = []
        for client in server.auth_clients():
            if client in self.joined:
                ret.append(client)
        return ret

    def set_cmode(self, user, m):
        if user in self.joined:
            self.joined[user] = m+self.joined[user].replace(m, '')
        elif user in self.members:
            self.members[user] = m+self.members[user].replace(m, '')

    def unset_cmode(self, user, m):
        if user in self.joined:
            self.joined[user] = self.joined[user].replace(m, '')
        elif user in self.members:
            self.members[user] = self.members[user].replace(m, '')

    def on_mode(self, client, *args):
        if len(args):
            if args[0] == '+m':
                self.mode = 'm'+self.mode.replace('m', '')
                self.event(client, 'MODE', '{} {}', self.name, args[0])
            elif args[0] == '-m':
                self.mode = self.mode.replace('m', '')
                self.event(client, 'MODE', '{} {}', self.name, args[0])
            elif args[0] in ('+o', '-o', '+h', '-h') and len(args) == 2:
                nick = args[1]
                if not server.has_special_user(nick):
                    client.err_nosuchnick(nick)
                else:
                    user = server.get_special_user(nick)
                    if self not in user.channels:
                        client.err_usernotinchannel(nick, self.name)
                    else:
                        server.loop.create_task(web.channel_set_admin(client, self, user, {'+h':1,'-h':0,'+o':2,'-o':0}[args[0]]))
            elif re.match('[-+]', args[0]):
                client.err_unknownmode(args[0][1] if len(args[0]) > 1 else '')
            else:
                client.err_unknownmode(args[0][0] if len(args[0]) else '')
        else:
            client.rpl_channelmodeis(self.name, self.mode)

    def on_names(self, client):
        self.on_names_impl(client, chain(self.joined.items(), self.members.items()))

    def on_notice_or_privmsg(self, client, command, text):
        irc_privmsg(client, command, self, text)

    def on_invite(self, client, nick):
        if server.has_special_user(nick):
            user = server.get_special_user(nick)
            if user in self.members:
                client.err_useronchannel(nick, self.name)
            else:
                web.channel_invite(client, self, user)
        else:
            client.err_nosuchnick(nick)

    def on_join(self, member):
        if isinstance(member, Client):
            if member in self.joined:
                return False
            self.joined[member] = ''
            self.explicit_parted.discard(member)
            server.loop.create_task(web.channel_members(self))
            super().on_join(member)
        else:
            if member in self.members:
                return False
            self.members[member] = ''
            member.enter(self)
            self.join_event(member)
        return True

    def on_kick(self, client, nick, reason):
        if server.has_special_user(nick):
            user = server.get_special_user(nick)
            web.channel_kick(client, self, user)
        else:
            client.err_usernotinchannel(nick, self.name)

    def on_part(self, member, msg=None):
        if isinstance(member, Client):
            if member not in self.joined:
                member.err_notonchannel(self.name)
                return False
            if msg:  # not msg implies being disconnected/kicked/...
                self.part_event(member, msg)
            del self.joined[member]
            self.explicit_parted.add(member)
        else:
            if member not in self.members:
                return False
            self.part_event(member, msg)
            del self.members[member]
        member.leave(self)
        return True

    def on_topic(self, client, new=None):
        if new:
            client.err_nochanmodes(self.name)
        else:
            super().on_topic(client, new)

    def on_who(self, client):
        members = tuple(self.members)+(client,)
        for member in members:
            member.on_who_member(client, self)


class Client:
    def __init__(self, reader, writer):
        self.reader = reader
        self.writer = writer
        peer = writer.get_extra_info('socket').getpeername()
        self.host = peer[0]
        if self.host[0] == ':':
            self.host = '[{}]'.format(self.host)
        self.user = None
        self.nick = None
        self.registered = False
        self.mode = ''
        self.channels = {}             # joined, name -> channel
        self.capabilities = set()
        self.authenticated = False

    def enter(self, channel):
        self.channels[irc_lower(channel.name)] = channel

    def leave(self, channel):
        del self.channels[irc_lower(channel.name)]

    def auto_join(self, room):
        for regex in options.ignore or []:
            if re.search(regex, room.name):
                return
        for regex in options.ignore_topic or []:
            if re.search(regex, room.topic):
                return
        room.on_join(self)

    def is_in_channel(self, name):
        return irc_lower(name) in self.channels

    def disconnect(self, quitmsg):
        if quitmsg:
            self.write('ERROR :{}'.format(quitmsg))
            self.message_related(False, ':{} QUIT :{}', self.prefix, quitmsg)
        if self.nick is not None:
            info('Disconnected from %s', self.prefix)
        try:
            self.writer.write_eof()
            self.writer.close()
        except:
            pass
        if self.nick is None:
            return
        channels = list(self.channels.values())
        for channel in channels:
            channel.on_part(self, None)
        server.remove_nick(self.nick)
        self.nick = None
        server.clients.discard(self)

    def reply(self, msg, *args):
        '''Respond to the client's request'''
        self.write((':{} '+msg).format(server.name, *args))

    def write(self, msg):
        try:
            self.writer.write(msg.encode()+b'\r\n')
        except:
            pass

    def status(self, msg):
        '''A status message from the server'''
        self.write(':{} NOTICE {} :{}'.format(server.name, server.name, msg))

    @property
    def prefix(self):
        return '{}!{}@{}'.format(self.nick or '', self.user or '', self.host or '')

    def rpl_umodeis(self, mode):
        self.reply('221 {} +{}', self.nick, mode)

    def rpl_channelmodeis(self, channelname, mode):
        self.reply('324 {} {} +{}', self.nick, channelname, mode)

    def rpl_endofnames(self, channelname):
        self.reply('366 {} {} :End of NAMES list', self.nick, channelname)

    def rpl_info(self, fmt, *args):
        line = fmt.format(*args) if args else fmt
        self.reply('371 {} :{}', self.nick, line)

    def rpl_endofinfo(self, msg):
        self.reply('374 {} :End of INFO list', self.nick)

    def err_nosuchnick(self, name):
        self.reply('401 {} {} :No such nick/channel', self.nick, name)

    def err_nosuchserver(self, name):
        self.reply('402 {} {} :No such server', self.nick, name)

    def err_nosuchchannel(self, channelname):
        self.reply('403 {} {} :No such channel', self.nick, channelname)

    def err_cannotsendtochan(self, channelname, text):
        self.reply('404 {} {} :{}', self.nick, channelname, text or 'Cannot send to channel')

    def err_noorigin(self):
        self.reply('409 {} :No origin specified', self.nick)

    def err_norecipient(self, command):
        self.reply('411 {} :No recipient given ({})', self.nick, command)

    def err_notexttosend(self):
        self.reply('412 {} :No text to send', self.nick)

    def err_unknowncommand(self, command):
        self.reply('421 {} {} :Unknown command', self.nick, command)

    def err_nonicknamegiven(self):
        self.reply('431 {} :No nickname given', self.nick)

    def err_errorneusnickname(self, nick):
        self.reply('432 * {} :Erroneous nickname', nick)

    def err_nicknameinuse(self, nick):
        self.reply('433 * {} :Nickname is already in use', nick)

    def err_usernotinchannel(self, nick, channelname):
        self.reply("441 {} {} {} :They are't on that channel", self.nick, nick, channelname)

    def err_notonchannel(self, channelname):
        self.reply("442 {} {} :You're not on that channel", self.nick, channelname)

    def err_useronchannel(self, nick, channelname):
        self.reply('443 {} {} {} :is already on channel', self.nick, nick, channelname)

    def err_nologin(self, nick):
        self.reply('444 {} {} :User not logged in', self.nick, nick)

    def err_needmoreparams(self, command):
        self.reply('461 {} {} :Not enough parameters', self.nick, command)

    def err_passwdmismatch(self, command):
        self.reply('464 * {} :Password incorrect', command)

    def err_unknownmode(self, mode):
        self.reply("472 {} {} :is unknown mode char to me", self.nick, mode)

    def err_nochanmodes(self, channelname):
        self.reply("477 {} {} :Channel doesn't support modes", self.nick, channelname)

    def err_chanoprivsneeded(self, channelname):
        self.reply("482 {} {} :You're not channel operator", self.nick, channelname)

    def err_umodeunknownflag(self):
        self.reply('501 {} :Unknown MODE flag', self.nick)

    def message_related(self, include_self, fmt, *args):
        '''Send a message to related clients which source is self'''
        line = fmt.format(*args)
        clients = [c for c in server.clients if c != self]
        if include_self:
            clients.append(self)
        for client in clients:
            client.write(line)

    def register(self):
        if self.registered:
            return
        if self.user and self.nick and (not (options.irc_password or options.sasl_password) or self.authenticated):
            self.registered = True
            info('%s registered', self.prefix)
            self.reply('001 {} :Hi, welcome to IRC', self.nick)
            self.reply('002 {} :Your host is {}', self.nick, server.name)
            self.reply('005 {} PREFIX=(ohv)@%+ CHANTYPES=!#&+ CHANMODES=,,,m SAFELIST :are supported by this server', self.nick)
            Command.lusers(self)
            Command.motd(self)

            Command.join(self, StatusChannel.instance.name)
            StatusChannel.instance.respond(self, 'Your contacts are listed in this channel')
            if not web.authorized:
                StatusChannel.instance.respond(self, 'This session is unauthorized. Requesting login code. Please type /oper a $login_code')
                web.proc.send_code_request(options.tg_phone)
            else:
                StatusChannel.instance.respond(self, 'Reuse {}.session . Initializing...', options.tg_session)

    def handle_command(self, command, args):
        cmd = irc_lower(command)
        if cmd == 'pass':
            cmd = cmd+'_'
        if type(Command.__dict__.get(cmd)) != staticmethod:
            self.err_unknowncommand(command)
            return
        fn = getattr(Command, cmd)
        if not web.authorized:
            code = 4
        elif not self.registered:
            code = 2
        else:
            code = 1

        if not (cmd_use_case.get(cmd, 1) & code):
            self.err_unknowncommand(command)
            return
        try:
            ba = inspect.signature(fn).bind(self, *args)
        except TypeError:
            self.err_needmoreparams(command)
            return
        fn(*ba.args)

    async def handle_irc(self):
        sent_ping = False
        while 1:
            try:
                line = await asyncio.wait_for(
                    self.reader.readline(), loop=server.loop,
                    timeout=options.heartbeat)
            except asyncio.TimeoutError:
                if sent_ping:
                    self.disconnect('ping timeout')
                    return
                else:
                    sent_ping = True
                    self.write('PING :'+server.name)
                    continue
            except ConnectionResetError:
                self.disconnect('ConnectionResetError')
                break
            if not line:
                return
            line = line.rstrip(b'\r\n').decode('utf-8', 'ignore')
            sent_ping = False
            if not line:
                continue
            # http://ircv3.net/specs/core/message-tags-3.2.html
            if line.startswith('@'):
                x = line.split(' ', 1)
                if len(x) == 1: continue
                line = x[1]

            x = line.split(' ', 1)
            command = x[0]
            if len(x) == 1:
                args = []
            elif len(x[1]) > 0 and x[1][0] == ':':
                args = [x[1][1:]]
            else:
                y = x[1].split(' :', 1)
                args = y[0].split(' ')
                if len(y) == 2:
                    args.append(y[1])
            try:
                self.handle_command(command, args)
            except:
                traceback.print_exc()
                self.disconnect('client error')
                break

    def ctcp(self, peer, msg):
        async def download():
            reader, writer = await asyncio.open_connection(ip, port)
            body = b''
            while 1:
                # TODO timeout
                buf = await reader.read(size-len(body))
                if not buf:
                    break
                body += buf
                if len(body) >= size:
                    break
            web.send_file(self, peer, filename, body)

        async def download_wrap():
            try:
                await asyncio.wait_for(download(), options.dcc_send_download_timeout)
            except asyncio.TimeoutError:
                self.status('Downloading of DCC SEND timeout')

        if len(msg) > 2 and msg[0] == '\1' and msg[-1] == '\1':
            # VULNERABILITY used as proxy
            try:
                dcc_, send_, filename, ip, port, size = msg[1:-1].split(' ')
                ip = socket.gethostbyname(str(int(ip)))
                size = int(size)
                assert dcc_ == 'DCC' and send_ == 'SEND'
                if 0 < size <= options.dcc_send:
                    server.loop.create_task(download())
                else:
                    self.status('DCC SEND: invalid size of {}, (0,{}] is acceptable'.format(
                            filename, options.dcc_send))
            except:
                pass
            return True
        return False

    def on_who_member(self, client, channel):
        client.reply('352 {} {} {} {} {} {} H :0 {}', client.nick, channel.name,
                     self.user, self.host, server.name,
                     self.nick, self.realname)

    def on_whois(self, client):
        client.reply('311 {} {} {} {} * :{}', client.nick, self.nick,
                     self.user, self.host, self.realname)
        client.reply('319 {} {} :{}', client.nick, self.nick,
                     ' '.join(name for name in
                              client.channels.keys() & self.channels.keys()))


class SpecialUser:
    def __init__(self, tg_user):
        self.user_id = tg_user.id
        self.peer = tl.types.PeerUser(tg_user.id)
        self.username = None
        self.channels = set()
        self.is_contact = False
        self.mode = ''
        self.update(tg_user)
        self.log_file = None
        self.last_text_by_client = weakref.WeakKeyDictionary()
        self.max_id = 0
        self.privmsg_reply = None
        self.privmsg_seq = 0
        self.privmsg_text = ''

    def __repr__(self):
        return repr({k: v for k, v in self.__dict__.items()
            if k in ('flags', 'name', 'peer_id', 'print_name', 'username')})

    @property
    def prefix(self):
        return '{}!{}@{}'.format(self.nick, self.user_id, im_name)

    def preferred_nick(self):
        if self.username:
            return self.username
        # fix order of Chinese names
        han = r'[\u3400-\u4dbf\u4e00-\u9fff\U00020000-\U0002ceaf]'
        m = re.match('({}+)_({}+)$'.format(han, han), self.print_name)
        if m:
            return m.group(2)+m.group(1)
        return self.print_name

    def event(self, command, fmt=None, *args):
        if fmt:
            line = fmt.format(*args) if args else fmt
        for client in server.auth_clients():
            if command == 'AWAY' and 'away-notify' not in client.capabilities: continue
            if fmt:
                client.write(':{} {} {}'.format(self.prefix, command, line))
            else:
                client.write(':{} {}'.format(self.prefix, command))

    def set_umode(self, m):
        if m not in self.mode:
            self.mode += m

    def unset_umode(self, m):
        if m in self.mode:
            self.mode = self.mode.replace(m, '')

    def update(self, tg_user):
        self.tg_user = tg_user
        self.username = tg_user.username
        self.print_name = (tg_user.first_name or '') + '_' + (tg_user.last_name or '')
        old_nick = getattr(self, 'nick', None)
        base = irc_escape_nick(self.preferred_nick()) or 'Guest'
        suffix = ''
        while 1:
            nick = base+suffix
            lower = irc_lower(nick)
            if nick and (nick == old_nick or
                    not (server.has_nick(nick) or lower in server.services or lower in options.irc_nicks)):
                break
            suffix = str(int(suffix or 0)+1)
        if nick != old_nick:
            for channel in self.channels:
                channel.nick_event(self, nick)
            self.nick = nick
        if tg_user.contact and not tg_user.restricted:
            if not self.is_contact:
                self.is_contact = True
                StatusChannel.instance.on_join(self)
                for channel in self.channels:
                    if isinstance(channel, SpecialChannel):
                        channel.set_cmode(self, 'v')
                        channel.voice_event(self)
        else:
            if self.is_contact:
                self.is_contact = False
                StatusChannel.instance.on_part(self)
                for channel in self.channels:
                    if isinstance(channel, SpecialChannel):
                        channel.unset_cmode(self, 'v')
                        channel.devoice_event(self)

    def enter(self, channel):
        self.channels.add(channel)

    def leave(self, channel):
        self.channels.remove(channel)

    def on_notice_or_privmsg(self, client, command, text):
        irc_privmsg(client, command, self, text)
        if 'a' in self.mode:
            client.write(':{} AWAY away'.format(self.prefix))
        if options.mark_read == 'reply':
            web.mark_read(self.peer, self.max_id)

    def on_who_member(self, client, channel):
        client.reply('352 {} {} {} {} {} {} H :0 {}', client.nick, channel.name,
                     self.user_id, im_name, server.name,
                     self.nick, self.print_name)

    def on_whois(self, client):
        client.reply('311 {} {} {} {} * :{}', client.nick, self.nick,
                     self.user_id, im_name, self.print_name)
        if 'a' in self.mode:
            client.reply('301 {} {} away', client.nick, self.nick)


class Server:
    valid_nickname = re.compile(r"^[][\`_^{|}A-Za-z][][\`_^{|}A-Za-z0-9-]{0,50}$")
    # initial character `+` is reserved for StatusChannel
    # initial character `&` is reserved for SpecialChannel
    valid_channelname = re.compile(r"^[#!][^\x00\x07\x0a\x0d ,:]{0,50}$")

    def __init__(self):
        global server
        server = self
        status = StatusChannel()
        self.channels = {status.name: status}
        self.name = 'telegramircd.maskray.me'
        self.nicks = {}
        self.clients = weakref.WeakSet()
        self.log_file = None
        self._boot = datetime.now()
        self.services = ('ChanServ',)

        self.last_text_by_client = weakref.WeakKeyDictionary()
        self.max_id = 0
        self.user_id = 0
        self.name2special_room = {}    # name -> Telegram chatroom
        self.peer_id2special_room = {} # peer_id -> SpecialChannel
        self.user_id2special_user = {} # peer_id -> SpecialUser
        self.nick2special_user = {}    # nick -> IRC user or Telegram user (friend or room contact)

    def _accept(self, reader, writer):
        try:
            client = Client(reader, writer)
            self.clients.add(client)
            task = self.loop.create_task(client.handle_irc())
            def done(task):
                client.disconnect(None)

            task.add_done_callback(done)
        except Exception as e:
            traceback.print_exc()

    def auth_clients(self):
        return (client for client in self.clients if client.registered)

    def preferred_client(self):
        n = len(self.clients)
        opt, optv = None, n+2
        for c in self.clients:
            if c.nick:
                try:
                    v = options.irc_nicks.index(c.nick)
                except ValueError:
                    v = n+1 if c.nick.endswith('bot') else n
                if v < optv:
                    opt, optv = c, v
        return opt

    def has_channel(self, name):
        x = irc_lower(name)
        return x in self.channels or x in self.name2special_room

    def has_nick(self, nick):
        x = irc_lower(nick)
        return x in self.nicks or x in self.nick2special_user

    def has_special_room(self, name):
        return irc_lower(name) in self.name2special_room

    def has_special_user(self, nick):
        return irc_lower(nick) in self.nick2special_user

    def get_channel(self, name):
        x = irc_lower(name)
        return self.channels[x] if x in self.channels else self.name2special_room[x]

    def get_nick(self, nick):
        x = irc_lower(nick)
        return self.nicks[x] if x in self.nicks else self.nick2special_user[x]

    def get_special_user(self, nick):
        return self.nick2special_user[irc_lower(nick)]

    def get_special_room(self, name):
        return self.name2special_room[irc_lower(name)]

    def remove_special_user(self, nick):
        del self.nick2special_user[irc_lower(nick)]

    # IRC channel or special chatroom
    def ensure_channel(self, channelname):
        if self.has_channel(channelname):
            return self.channels[irc_lower(channelname)]
        if not Server.valid_channelname.match(channelname):
            raise ValueError
        channel = StandardChannel(channelname)
        self.channels[irc_lower(channelname)] = channel
        return channel

    def ensure_special_room(self, peer_id, tg_room):
        debug('ensure_special_room %r %r', peer_id, tg_room)
        if peer_id in self.peer_id2special_room:
            room = self.peer_id2special_room[peer_id]
            del self.name2special_room[irc_lower(room.name)]
            #room.update(record)
        else:
            if tg_room is None:
                tg_room = web.proc.get_entity(peer_id)
            room = SpecialChannel(tg_room)
            self.peer_id2special_room[peer_id] = room
            if options.join == 'all':
                for client in self.auth_clients():
                    client.auto_join(room)
        self.name2special_room[irc_lower(room.name)] = room
        return room

    def ensure_special_user(self, user_id, tg_user):
        debug('ensure_special_user %r %r', user_id, tg_user)
        if user_id == self.user_id:
            return self
        if user_id in self.user_id2special_user:
            user = self.user_id2special_user[user_id]
            self.remove_special_user(user.nick)
            #user.update(tg_user)
        else:
            if tg_user is None:
                tg_user = web.proc.get_entity(user_id)
            user = SpecialUser(tg_user)
            self.user_id2special_user[user.user_id] = user
        self.nick2special_user[irc_lower(user.nick)] = user
        return user

    def remove_channel(self, channelname):
        del self.channels[irc_lower(channelname)]

    def change_nick(self, client, new):
        lower = irc_lower(new)
        if self.has_nick(new) or lower in self.services:
            client.err_nicknameinuse(new)
        elif not Server.valid_nickname.match(new):
            client.err_errorneusnickname(new)
        else:
            if client.nick:
                info('%s changed nick to %s', client.prefix, new)
                self.remove_nick(client.nick)
                client.message_related(True, ':{} NICK {}', client.prefix, new)
            self.nicks[lower] = client
            client.nick = new

    def remove_nick(self, nick):
        del self.nicks[irc_lower(nick)]

    def start(self, loop, tls):
        self.loop = loop
        self.servers = []
        for i in options.irc_listen if options.irc_listen else options.listen:
            self.servers.append(loop.run_until_complete(
                asyncio.streams.start_server(self._accept, i, options.irc_port, ssl=tls)))

    def stop(self):
        for i in self.servers:
            i.close()
            self.loop.run_until_complete(i.wait_closed())

    def on_telegram_update(self, update):
        debug('on_telegram_update %r %r', update, update.to_dict())
        #if update.id in web.id2message:
        #    return
        if isinstance(update, tl.types.ChannelParticipantsKicked):
            # TODO
            pass
        elif isinstance(update, tl.types.UpdateNewChannelMessage):
            msg = update.message
            sender = server.ensure_special_user(msg.from_id, None)
            to = server.ensure_special_room(msg.to_id.channel_id, None)
        elif isinstance(update, tl.types.UpdateNewMessage):
            msg = update.message
            sender = server.ensure_special_user(msg.from_id, None)
            if isinstance(msg.to_id, tl.types.PeerUser):
                to = server.ensure_special_user(msg.to_id.user_id, None)
            elif isinstance(msg.to_id, tl.types.PeerChannel):
                to = server.ensure_special_room(msg.to_id.channel_id, None)
            elif isinstance(msg.to_id, tl.types.PeerChat):
                to = server.ensure_special_room(msg.to_id.chat_id, None)
        elif isinstance(update, tl.types.UpdateShortChatMessage):
            msg = update
            sender = server.ensure_special_user(update.from_id, None)
            to = server.ensure_special_room(update.chat_id, None)
        elif isinstance(update, tl.types.UpdateShortMessage):
            msg = update
            sender = server.ensure_special_user(update.user_id, None)
            to = server
        elif isinstance(update, tl.types.UpdateUserStatus):
            try:
                user = server.ensure_special_user(update.user_id, None)
            except:
                return
            if user is not server:
                if isinstance(update.status, tl.types.UserStatusOffline):
                    user.set_umode('a')
                    user.event('AWAY', 'offline')
                elif isinstance(update.status, tl.types.UserStatusOnline):
                    user.unset_umode('a')
                    user.event('AWAY')
            return
        else:
            return
        if options.ignore_bot and (
                isinstance(to, SpecialUser) and to.bot or
                isinstance(sender, SpecialUser) and sender.bot):
            return

        sender.max_id = msg.id
        record = {'id': msg.id, 'from': sender, 'to': to, 'message': msg.message}
        web.append_history(record)
        # UpdateShort{,Chat}Message do not have update.media
        # UpdateNewChannelMessage may have {media: None}
        if getattr(msg, 'media', None):
            text = None
            if isinstance(msg.media, tl.types.MessageMediaContact):
                type = 'contact'
            elif isinstance(msg.media, tl.types.MessageMediaDocument):
                type = 'document'
            elif isinstance(msg.media, tl.types.MessageMediaEmpty):
                type = 'empty'
            elif isinstance(msg.media, tl.types.MessageMediaGeo):
                type = 'geo'
                text = '[{}] latitude:{} longitude:{}'.format(type, msg.media.geo.long, msg.media.geo.lat)
            elif isinstance(msg.media, tl.types.MessageMediaPhoto):
                type = 'photo'
            elif isinstance(msg.media, tl.types.MessageMediaWebPage):
                type = 'webpage'
                if isinstance(msg.media, tl.types.WebPage):
                    text = '[{}] {}'.format(type, msg.media.webpage.url)
            else:
                type = 'unknown'
            if type in ('document', 'photo'):
                media_id = str(len(web.id2media))
                text = '[{}] {}/document/{}{}'.format(type, options.http_url, media_id, {'photo': '.jpg'}.get(type, ''))
                if type == 'photo' and isinstance(msg.media.photo, tl.types.Photo):
                    for size in msg.media.photo.sizes:
                        if isinstance(size, tl.types.PhotoCachedSize):
                            text += ' {}x{}'.format(size.w, size.h)
                        elif isinstance(size, tl.types.PhotoSize):
                            text += ' {}x{},{}B'.format(size.w, size.h, size.size)
                    web.id2media[media_id] = (msg.media, None)
            elif text is None:
                text = '[{}] {}'.format(type, msg.media.to_dict())
        else:
            text = msg.message
        for line in text.splitlines():
            if msg.reply_to_msg_id is not None:
                if msg.reply_to_msg_id in web.id2message:
                    refer = web.id2message[msg.reply_to_msg_id]
                else:
                    message = web.message_get(msg.reply_to_msg_id)
                    refer = {'id': message.id,
                             'from': server.ensure_special_user(message.from_id, None),
                             'message': message.message}
                    if isinstance(message.to_id, tl.types.PeerUser):
                        refer['to'] = server.ensure_special_user(message.to_id.user_id, None)
                    elif isinstance(message.to_id, tl.types.PeerChannel):
                        refer['to'] = server.ensure_special_room(message.to_id.channel_id, None)
                    elif isinstance(message.to_id, tl.types.PeerChat):
                        refer['to'] = server.ensure_special_room(message.to_id.chat_id, None)
                    web.append_history(refer)
                refer_text = refer['message'].replace('\n', '\\n')
                if len(refer_text) > 8:
                    refer_text = refer_text[:8]+'...'
                user = refer['from']
                for client in server.auth_clients():
                    line = '\x0315「Re {}: {}」\x0f{}'.format(
                        client.nick if user == server else user.nick, refer_text, line)
                    break

            client = server.preferred_client()
            if client:
                where = sender if to == server else to
                irc_log(where, client if where == server else where, msg.date,
                        client if sender == server else sender, line)

            if isinstance(to, SpecialChannel):
                for c in server.auth_clients():
                    if c not in to.joined and 'm' not in to.mode:
                        if options.join in ('all', 'auto') and c not in to.explicit_parted or options.join == 'new':
                            c.auto_join(to)
            for client in server.auth_clients():
                #if isinstance(to, Channel) and client not in to.joined or (
                #        'echo-message' not in client.capabilities and
                #        sender == server and 'media' not in data and
                #        data['text'] == to.last_text_by_client.get(client)):
                #    continue
                sender_prefix = client.prefix if sender == server else sender.prefix
                to_nick = client.nick if to == server else to.nick
                line = ':{} PRIVMSG {} :{}'.format(sender_prefix, to_nick, line)
                tags = []
                if 'draft/message-tags' in client.capabilities:
                    tags.append('draft/msgid={}'.format(msg.id))
                if 'server-time' in client.capabilities:
                    tags.append('time={}Z'.format(datetime.utcfromtimestamp(msg.date.timestamp())
                                                  .strftime('%FT%T.%f')[:23]))
                if tags:
                    line = '@{} {}'.format(';'.join(tags), line)
                client.write(line)
        if options.mark_read == 'always' and isinstance(sender, SpecialUser):
            if to is server:
                if sender is not server:
                    web.mark_read(sender.peer, msg.id)
            else:
                web.mark_read(to.peer, msg.id)

    def on_disconnect(self, peername):
        # PART all special channels, these chatrooms will be garbage collected
        for room in self.peer_id2special_room.values():
            if self in room.joined:
                room.on_part(self, 'client disconnection')
        self.peer_id2special_room.clear()

        # instead of flooding +telegram with massive PART messages,
        # take the shortcut by rejoining the client
        self.user_id2special_user.clear()
        status = StatusChannel.instance
        clients = [x for x in status.members if isinstance(x, Client)]
        status.members.clear()
        for client in clients:
            status.on_part(self, 'client disconnected from {}'.format(peername))
            status.on_join(self)


def main():
    ap = ArgParser(description='telegramircd brings Telegram to IRC clients')
    ap.add('-c', '--config', is_config_file=True, help='config file path')
    ap.add_argument('-d', '--debug', action='store_true', help='run ipdb on uncaught exception')
    ap.add_argument('--dcc-send', type=int, default=10*1024*1024, help='size limit receiving from DCC SEND. 0: disable DCC SEND')
    ap.add_argument('--heartbeat', type=int, default=30, help='time to wait for IRC commands. The server will send PING and close the connection after another timeout of equal duration if no commands is received.')
    ap.add_argument('--http-cert', help='TLS certificate for HTTPS over TLS. You may concatenate certificate+key, specify a single PEM file and omit `--http-key`. Use HTTP if neither --http-cert nor --http-key is specified')
    ap.add_argument('--http-url', default='http://localhost',
                    help='Show document links as http://localhost/document/$id')
    ap.add_argument('--http-key', help='TLS key for HTTPS over TLS')
    ap.add_argument('--http-listen', nargs='*',
                    help='HTTP listen addresses (overriding --listen)')
    ap.add_argument('--http-port', type=int, default=9003, help='HTTP listen port, default: 9003')
    ap.add_argument('-i', '--ignore', nargs='*',
                    help='list of ignored regex, do not auto join to a '+im_name+' chatroom whose channel name(generated from DisplayName) matches')
    ap.add_argument('--ignore-bot', action='store_true', help='ignore private messages with bots')
    ap.add_argument('-I', '--ignore-topic', nargs='*',
                    help='list of ignored regex, do not auto join to a '+im_name+' chatroom whose topic matches')
    ap.add_argument('--irc-cert', help='TLS certificate for IRC over TLS. You may concatenate certificate+key, specify a single PEM file and omit `--irc-key`. Use plain IRC if neither --irc-cert nor --irc-key is specified')
    ap.add_argument('--irc-key', help='TLS key for IRC over TLS')
    ap.add_argument('--irc-listen', nargs='*',
                    help='IRC listen addresses (overriding --listen)')
    ap.add_argument('--irc-nicks', nargs='*', default=[],
                    help='reserved nicks for clients')
    ap.add_argument('--irc-password', default='', help='Set the IRC connection password')
    ap.add_argument('--irc-port', type=int, default=6669,
                    help='IRC server listen port. default: 6669')
    ap.add_argument('-j', '--join', choices=['all', 'auto', 'manual', 'new'], default='new',
                    help='join mode for '+im_name+' chatrooms. all: join all after connected; auto: join after the first message arrives; manual: no automatic join; new: join whenever messages arrive (even if after /part); default: auto')
    ap.add_argument('-l', '--listen', nargs='*', default=['127.0.0.1'],
                    help='IRC/HTTP listen addresses, default: 127.0.0.1')
    ap.add_argument('--logger-ignore', nargs='*', help='list of ignored regex, do not log contacts/chatrooms whose names match')
    ap.add_argument('--logger-mask', help='WeeChat logger.mask.irc')
    ap.add_argument('--logger-time-format', default='%H:%M', help='WeeChat logger.file.time_format')
    ap.add_argument('--mark-read', choices=('always', 'reply', 'never'), default='reply', help='when to mark_read private messages from users. always: mark_read all messages; reply: mark_read when sending messages to the peer; never: never mark_read. default: reply'),
    ap.add_argument('--paste-wait', type=float, default=0.1, help='PRIVMSG lines will be hold for up to $paste_wait seconds, lines in this interval will be packed to a multiline message')
    ap.add_argument('-q', '--quiet', action='store_const', const=logging.WARN, dest='loglevel')
    ap.add_argument('--sasl-password', default='', help='Set the SASL password')
    ap.add_argument('--special-channel-prefix', choices=('&', '!', '#', '##'), default='&', help='prefix for SpecialChannel')
    ap.add_argument('--tg-api-id', type=int, help='App api_id on https://my.telegram.org/apps')
    ap.add_argument('--tg-api-hash', help='App api_hash on https://my.telegram.org/apps')
    ap.add_argument('--tg-media-dir', default='/tmp/telegramircd', help='directory of media files')
    ap.add_argument('--tg-session', default='telegramircd', help='Telethon session name')
    ap.add_argument('--tg-session-dir', default='.', help='directory of Telethon session file')
    ap.add_argument('--tg-phone', type=int, help='phone number')
    ap.add_argument('-v', '--verbose', action='store_const', const=logging.DEBUG, dest='loglevel')
    global options
    options = ap.parse_args()
    options.irc_nicks = [irc_lower(x) for x in options.irc_nicks]

    os.chdir(options.tg_session_dir)
    os.makedirs(options.tg_media_dir, exist_ok=True)

    if sys.platform == 'linux':
        # send to syslog if run as a daemon (no controlling terminal)
        try:
            with open('/dev/tty'):
                pass
            logging.basicConfig(format='%(levelname)s: %(message)s')
        except OSError:
            logging.root.addHandler(logging.handlers.SysLogHandler('/dev/log'))
    else:
        logging.basicConfig(format='%(levelname)s: %(message)s')
    logging.root.setLevel(options.loglevel or logging.INFO)

    if options.http_cert or options.http_key:
        http_tls = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
        http_tls.load_cert_chain(options.http_cert or options.http_key,
                                 options.http_key or options.http_cert)
    else:
        http_tls = None
    if options.irc_cert or options.irc_key:
        irc_tls = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
        irc_tls.load_cert_chain(options.irc_cert or options.irc_key,
                                options.irc_key or options.irc_cert)
    else:
        irc_tls = None

    loop = asyncio.get_event_loop()
    if options.debug:
        sys.excepthook = ExceptionHook()
    server = Server()
    web = Web(http_tls)

    # FIXME
    def exception_handler(loop, context):
        server.loop.create_task(web.restart_telegram_cli())
    #loop.set_exception_handler(exception_handler)

    server.start(loop, irc_tls)
    web.start(options.http_listen if options.http_listen else options.listen,
              options.http_port, loop)

    for signame in ('SIGINT', 'SIGTERM'):
        loop.add_signal_handler(getattr(signal, signame), loop.stop)
    try:
        loop.run_forever()
    finally:
        server.stop()
        web.stop()
        loop.close()


if __name__ == '__main__':
    sys.exit(main())
