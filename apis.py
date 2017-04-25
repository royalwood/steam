from flask import request

import os
import time
from datetime import datetime, timedelta
from collections import OrderedDict, namedtuple
import email
import requests
from requests_oauthlib import OAuth1Session

try:
    import config
    from .helpers import log
except ImportError:
    # test environment
    from .mock import config, log

### External APIs ###
def nexmo(endpoint, **kwargs):
    """
    Shorthand for nexmo api calls
    """
    kwargs['api_key'] = config.NEXMO_API_KEY
    kwargs['api_secret'] = config.NEXMO_API_SECRET
    result = requests.post('https://api.nexmo.com/%s/json' % endpoint, data=kwargs)
    return result.json()

def geocode(address):
    # TODO: caching
    # FIXME: error handling
    ret = requests.get('https://maps.googleapis.com/maps/api/geocode/json', params={
        'address': address,
        'sensor': False,
    }).json()
    loc = ret['results'][0]['geometry']['location']
    return loc['lat'], loc['lng']
class IPInfo:
    """
    This is a wrapper for ipinfo.io api with caching.
    """
    iso3 = None # will be filled on first use
    cache = OrderedDict()
    cache_max = 100
    @classmethod
    def country(cls, ip=None, default=None):
        """
        Returns ISO3 country code using country.io for conversion.
        IP defaults to `request.remote_addr`.
        Will return `default` value if no country found (e.g. for localhost ip)
        """
        if not ip:
            ip = request.remote_addr
        if ip in cls.cache:
            # move to end to make it less likely to pop
            cls.cache.move_to_end(ip)
            return cls.cache[ip] or default
        ret = requests.get('http://ipinfo.io/{}/geo'
                           .format(ip))
        try:
            ret = ret.json()
        except ValueError:
            log.warn('No JSON returned by ipinfo.io: '+ret.text)
            ret = {}
        result = None
        if 'country' in ret:
            if not cls.iso3:
                cls.iso3 = requests.get('http://country.io/iso3.json').json()
            result = cls.iso3.get(ret['country'])
            if not result:
                log.warn('couldn\'t convert country code {} to ISO3'.format(
                    ret['country']))
        cls.cache[ip] = result
        if len(cls.cache) > cls.cache_max:
            # remove oldest item
            cls.cache.popitem(last=False)
        return result or default

class PayPal:
    token = None
    token_ttl = None
    base_url = 'https://{}.paypal.com/v1/'.format('api.sandbox'
                                                  if config.PAYPAL_SANDBOX else
                                                  'api')
    @classmethod
    def get_token(cls):
        if cls.token_ttl and cls.token_ttl <= datetime.utcnow():
            cls.token = None # expired
        if not cls.token:
            ret = requests.post(
                cls.base_url+'oauth2/token',
                data={'grant_type': 'client_credentials'},
                auth=(config.PAYPAL_CLIENT, config.PAYPAL_SECRET),
            )
            if ret.status_code != 200:
                log.error('Couldn\'t get token: {}'.format(ret.status_code))
                return
            ret = ret.json()
            cls.token = ret['access_token']
            cls.token_lifetime = (datetime.utcnow() +
                                  timedelta(seconds =
                                            # -10sec to be sure
                                            ret['expires_in'] - 10))
        return cls.token
    @classmethod
    def call(cls, method, url, params=None, json=None):
        if not json:
            json = params
            params = None
        url = cls.base_url + url
        headers = {
            'Authorization': 'Bearer '+cls.get_token(),
            #TODO: 'PayPal-Request-Id': None, # use generated nonce
        }
        ret = requests.request(method, url,
                            params=params,
                            json=json,
                            headers = headers,
                            )
        log.debug('Paypal result: {} {}'.format(ret.status_code, ret.text))
        try:
            jret = ret.json()
        except ValueError:
            log.error('Paypal failure - code %s' % ret.status_code,
                      exc_info=True);
            jret = {}
        jret['_code'] = ret.status_code
        return jret

class Fixer:
    # fixer rates are updated daily, but it should be enough for us
    item = namedtuple('item', ['ttl','rate'])
    cache = OrderedDict()
    cache_max = 100
    cache_ttl = timedelta(minutes=15)
    @classmethod
    def latest(cls, src, dst):
        if src == dst:
            return 1

        now = datetime.now()
        if (src,dst) in cls.cache:
            cls.cache.move_to_end((src,dst))
            if cls.cache[(src,dst)].ttl > now:
                return cls.cache[(src,dst)].rate

        result = requests.get('http://api.fixer.io/latest', params={
            'base': src, 'symbols': dst}).json()
        if 'rates' not in result:
            log.warning('Failure with Fixer api: '+str(result))
            return None
        rate = result.get('rates').get(dst)
        if rate is None:
            raise ValueError('Unknown currency '+dst)

        cls.cache[(src,dst)] = cls.item(now+cls.cache_ttl, rate)
        if len(cls.cache) > cls.cache_max:
            cls.cache.popitem(last=False)

        return rate

def mailsend(user, mtype, sender=None, delayed=None, usebase=True, **kwargs):
    subjects = dict(
        greeting = 'Welcome to BetGame',
        greet_personal = 'Hey {}'.format(user.nickname or 'BetGame user'),
        recover = 'BetGame password recovery',
        win = 'BetGame win notification',
    )
    if mtype not in subjects:
        raise ValueError('Unknown message type {}'.format(mtype))

    kwargs['name'] = user.nickname
    kwargs['email'] = user.email

    def load(name, ext, values, base=False):
        f = open('{}/templates/mail/{}.{}'.format(
            os.path.dirname(__file__)+'/..', # load from path relative to self
            name, ext
        ), 'r')
        txt = f.read()
        for key,val in values.items():
            txt = txt.replace('{%s}' % key, str(val))
        if not base:
            txt = load('base', ext, dict(
                content = txt,
            ), base=True)
        return txt

    params = {
        'from': sender or config.MAIL_SENDER,
        'to': '{} <{}>'.format(user.nickname, user.email),
        'subject': subjects[mtype],
        'text': load(mtype, 'txt', kwargs, not usebase),
        'html': load(mtype, 'html', kwargs, not usebase),
    }
    if delayed:
        params['o:deliverytime'] = email.utils.format_datetime(
            datetime.utcnow() + delayed
        )
    ret = requests.post(
        'https://api.mailgun.net/v3/{}/messages'.format(config.MAIL_DOMAIN),
        auth=('api',config.MAILGUN_KEY),
        data=params,
    )
    try:
        jret = ret.json()
        if 'id' in jret:
            log.info('mail sent: '+jret['message'])
            return True
        else:
            log.error('mail sending failed: '+jret['message'])
            return False
    except Exception:
        log.exception('Failed to send {} mail to {}'.format(mtype, user))
        log.error('{} {}'.format(ret.status_code, ret.text))
        return False

class Twitter:
    @classmethod
    def session(cls, identity):
        if ':' not in identity:
            raise ValueError('Incorrect identity, should be <token>:<secret>')
        key, secret = identity.split(':',1)
        return OAuth1Session(
            config.TWITTER_API_KEY,
            client_secret = config.TWITTER_API_SECRET,
            resource_owner_key = key,
            resource_owner_secret = secret,
        )
    @classmethod
    def identity(cls, token):
        url = 'https://api.twitter.com/1.1/account/verify_credentials.json'
        ret = cls.session(token).get(url, params=dict(
            include_email='true', # plain True doesn't work here
            skip_status='true', # here True would work as well
        ))
        try:
            jret = ret.json()
        except:
            jret = {}
        jret['_ret'] = ret
        jret['_code'] = ret.status_code
        return jret

class JsonApi:
    @classmethod
    def session(cls):
        " If overriden, should return a requests.session object "
        return requests
    @classmethod
    def request(cls, *args, **kwargs):
        " Can be overriden "
        return cls.session().request(*args, **kwargs)
    @classmethod
    def request_json(cls, *args, **kwargs):
        ret = cls.request(*args, **kwargs)
        try:
            resp = ret.json()
        except ValueError: # json decode error
            # error decoding json
            log.exception('{} API: not a json in reply, code {}, text {}'.format(
                cls.__name__,
                ret.status_code,
                ret.text,
            ))
            resp = {}
        resp['_code'] = ret.status_code

        return resp

class LimitedApi(JsonApi):
    # this is default delay between subsequent requests to the same api,
    # can be overriden in subclasses
    DELAY = timedelta(seconds=2)

    @classmethod
    def request(cls, *args, **kwargs):
        """
        This overrides JsonApi's method adding delay.
        """
        # TODO: maybe use session for delaying?
        now = datetime.utcnow()
        last = getattr(cls, '_last', None)
        if last:
            diff = now - last
            delay = cls.DELAY - diff
            seconds = delay.total_seconds()
            if seconds > 0:
                time.sleep(seconds)
        # and before we actually call the method, save current time
        # (so that api's internal delay will count as a part of our delay)
        cls._last = datetime.utcnow()

        # now that we slept if needed, call Requests
        # and handle any json-related problems
        return super().request(*args, **kwargs)

class Riot(LimitedApi):
    URL = 'https://{region}.api.pvp.net/api/lol/{region}/{version}/{method}'
    REGIONS = [
        'br', 'eune', 'euw', 'kr',
        'lan', 'las', 'na', 'oce',
        'ru', 'tr',
    ]

    @classmethod
    def summoner_check(cls, val, region = None):
        """
        Summoner name can be either full (with region) or short.
        If it is full, it should be in format 'region/name'.
        If it is short, this method will try to find matching name
        in the first region where it exists.

        Returns summoner data in form 'region/name/id'.
        """
        if not region and '/' in val:
            region, nval = val.split('/',1)
            if region in cls.REGIONS:
                val = nval
            else:
                region = None
        if not region:
            for region in cls.REGIONS:
                try:
                    return cls.summoner_check(val, region)
                except ValueError:
                    pass
            raise ValueError('Summoner {} not exists in any region'.format(val))

        ret = cls.call(region, 'v1.4', 'summoner/by-name/'+val)
        if val.lower() in ret:
            return '/'.join([
                region,
                ret[val.lower()]['name'],
                str(ret[val.lower()]['id']),
            ])
        raise ValueError('Unknown summoner name')

    @classmethod
    def call(cls, region, version, method, params=None, data=None):
        if region not in cls.REGIONS:
            raise ValueError('Unknown region %s' % region)

        params = params or {}
        data = data or {}

        params['api_key'] = config.RIOT_KEY
        return cls.request_json(
            'GET',
            cls.URL.format(
                region=region,
                version=version,
                method=method,
            ),
            params = params,
            data = data,
        )

class Steam(LimitedApi):
    # as recommended in http://dev.dota2.com/showthread.php?t=47115
    DELAY = timedelta(seconds=1)
    STEAM_ID_64_BASE = 76561197960265728

    @classmethod
    def id_to_32(cls, val):
        if val > cls.STEAM_ID_64_BASE:
            val -= cls.STEAM_ID_64_BASE
        return val
    @classmethod
    def id_to_64(cls, val):
        if val < cls.STEAM_ID_64_BASE:
            val += cls.STEAM_ID_64_BASE
        return val

    @classmethod
    def parse_id(cls, val):
        # convert it to int if applicable
        try:
            val = int(val)
            return cls.id_to_64(val)
        except ValueError: pass

        if val.startswith('STEAM_'):
            val = val.split('STEAM_',1)[1]
            ver, a, b = map(int, val.split(':'))
            if ver == 0:
                return cls.id_to_64(b << 1 + (a & 1))
            raise ValueError('unknown ver: '+val)
        elif 'steamcommunity.com/' in val: # url
            if '/id/' in val:
                vanity_name = val.split('/id/',1)[1]
                # and fall down
            elif '/profiles/' in val:
                val = val.split('/profiles/',1)[1]
                val = val.split('/')[0]
                return int(val)
            else:
                raise ValueError(val)
        else:
            # val is probably nickname for vanity URL, so -
            vanity_name = val
        # at this point val is probably a nickname (or vanity URL part)
        # so try to parse it
        ret = cls.call(
            'ISteamUser', 'ResolveVanityURL', 'v0001',
            vanityurl=vanity_name,
        )
        if 'steamid' not in ret:
            raise ValueError('Bad vanity URL '+val)
        return int(ret['steamid']) # it was returned as string

    @classmethod
    def player_nick(cls, val):
        """
        Gets *numeric steam ID*, retrieves properly-spelled nickname.
        """
        ret = cls.call(
            'ISteamUser', 'GetPlayerSummaries', 'v0002',
            steamids = val,
        )
        ps = ret.get('players')
        if not ps:
            log.error('Couldn\'t load player nickname from Steam')
            return None
        return ps[0].get('personaname')
    @classmethod
    def pretty_id(cls, val):
        steam_id = cls.parse_id(val)
        name = cls.player_nick(steam_id)
        if not name:
            return steam_id # store w/o dot
        return '{}.{}'.format(steam_id, name)
    @classmethod
    def split_identity(cls, val):
        """
        This is reverse for `pretty_id`
        """
        id, sep, name = val.partition('.')
        return id, name or str(id)

    @classmethod
    def call(cls, path, method, version, **params):
        # TODO: on 503 error, retry in 30 seconds
        params['key'] = config.STEAM_KEY
        ret = cls.request_json(
            'GET',
            'https://api.steampowered.com/{}/{}/{}/'.format(
                path,
                method,
                version,
            ),
            params = params,
        )
        for wrapper in ['result', 'response']:
            if ret.keys() == set([wrapper, '_code']): # nothing more
                ret[wrapper]['_code'] = ret.get('_code')
                return ret[wrapper]
        return ret
    @classmethod
    def dota2(cls, method, match=True, **params):
        # docs available at https://wiki.teamfortress.com/wiki/WebAPI#Dota_2
        return cls.call('IDOTA2{}_570'.format('Match' if match else ''),
                        method, 'V001', **params)

class BattleNet(LimitedApi):
    # FIXME: there are 2 partitions - CN and Worldwide. We only use worldwide.
    # https://dev.battle.net/docs/concepts/Regionality
    # https://dev.battle.net/docs/concepts/AccountIds
    HOSTS = dict(
        us = 'https://us.api.battle.net/',
        eu = 'https://eu.api.battle.net/',
        kr = 'https://kr.api.battle.net/',
        tw = 'https://tw.api.battle.net/',
        cn = 'https://api.battlenet.com.cn/',
        sea = 'https://sea.api.battle.net/',
    )
    @classmethod
    def call(cls, region, game, endpoint, *params):
        host = cls.HOSTS[region]
        url = 'https://{host}/{game}/{endpoint}'.format(**locals())
        params['apikey'] = config.BATTLENET_KEY
        return cls.request_json('GET', url, params=params)
class StarCraft(BattleNet):
    @classmethod
    def find_uid(cls, val):
        """
        Search given user ID on sc2ranks site.
        """
        # TODO: api seems not functional
        ret = cls.request_json(
            'POST',
            'http://api.sc2ranks.com/v2/characters/search',
        )
        # TODO
        ret
    @classmethod
    def check_uid(cls, val):
        if val.startswith('http'):
            val = val.split('://',1)[1]
        parts = val.split('/')
        if 'sc2ranks.com/character' in val:
            # sc2ranks url example:
            # http://www.sc2ranks.com/character/us/5751755/Violet/hots/1v1
            region, uid, uname = parts[2:5]
            ureg = '1' # seems that it is always 1
        elif 'battle.net/sc2' in val and '/profile/' in val:
            # battle.net url example:
            # http://us.battle.net/sc2/en/profile/7098504/1/Neeblet/matches
            if parts[0] == 'www.battlenet.com.cn':
                region = 'cn'
            else:
                # region = subdomain
                region = parts[0].split('.',1)[0]
            uid, ureg, uname = parts[4:7]
        else:
            if len(parts) != 4:
                return cls.find_uid(val)
            region, uid, ureg, uname = parts
        if region not in cls.HOSTS:
            raise ValueError('Unknown region '+region)
        int(uid) # to check for valueerror
        int(ureg)
        return '/'.join([region, uid, ureg, uname])
    @classmethod
    def profile(cls, user, part=''):
        region, uid, ureg, uname = user.split('/')
        return cls.call(
            region,
            'sc2',
            '{}/{}/{}/{}'.format(uid, ureg, uname, part),
        )

class Twitch:
    @classmethod
    def call(cls, endpoint, version=None):
        ret = requests.get(
            'https://api.twitch.tv/kraken/{}'.format(endpoint),
            headers = {
                'Accept': 'application/vnd.twitchtv{}+json'.format(
                    '.'+version if version else ''),
                #'Client-ID': ...,
            },
        )
        try:
            jret = ret.json()
        except ValueError:
            jret = {}
        jret['_code'] = ret.status_code
        return jret

    @classmethod
    def channel(cls, handle):
        return cls.call('channels/{}'.format(handle), 'v3')

    @classmethod
    def check_handle(cls, val):
        pos = val.find('twitch.tv/')
        if pos >= 0:
            val = val[pos+10:]
        # now validate id over twitch
        ret = cls.channel(val)
        if ret['_code'] == 404:
            raise ValueError('No such channel "{}"'.format(val))
        log.info('Twitch channel: current game is {}'.format(ret.get('game')))
        return val

class WilliamHill:
    """
    Unlike other APIs in this module,
    this one should be instantiated for usage.
    This is because it requires user credentials.
    """
    class WilliamHillError(Exception):
        pass
    BASE = 'https://sandbox.whapi.com/v1/' # XXX is it correct? doc mentions sandbox.*
    CAS_HOST = ('https://auth.williamhill%s.com' %
                ('-test' if config.WH_SANDBOX else ''))
    def __init__(self, ticket=None):
        self.session = requests.Session()
        self.session.headers.update({
            'Accept': 'application/vnd.who.Sportsbook+json;v=1;charset=utf-8',
            'who-apiKey': config.WH_KEY,
            'who-secret': config.WH_SECRET,
        })
        if ticket:
            self.session.headers.update({
                'who-ticket': ticket,
            })
    def request(self, method, url, accept_simple=False, *args, **kwargs):
        if accept_simple:
            if 'headers' not in kwargs:
                kwargs['headers'] = {}
            kwargs['headers']['Accept'] = 'application/json'
        try:
            ret = self.session.request(method, self.BASE+url, *args, **kwargs)
            jret = ret.json()
        except ValueError: # not a json?
            return dict(
                error = 'No JSON available',
            )
        if 'whoFaults' in jret:
            fault = jret['whoFaults']
            fault = fault[0] if len(fault) > 0 else {}
            return dict(
                error = fault.get('faultString') or '(no fault description)',
                error_code = fault.get('faultCode'),
                error_name = fault.get('faultName'),
            )
        return jret
