import {ACLPolicy, FlowControl, RateLimit, TagRule, URLMap, WAFPolicy} from '@/types'

const Titles: { [key: string]: string } = {
  'admin': 'Admin',
  'allow': 'Allow',
  'allow_bot': 'Allow Bot',
  'args': 'Arguments',
  'attrs': 'Attributes',
  'audit-log': 'Audit Log',
  'bypass': 'Bypass',
  'cookies': 'Cookies',
  'curiefense-lists': 'Curiefense Lists',
  'customsigs': 'Custom Signatures',
  'deny': 'Deny',
  'deny_bot': 'Deny Bot',
  'events-and-attacks': 'Events & Attacks',
  'external-lists': 'External Lists',
  'force_deny': 'Enforce Deny',
  'headers': 'Headers',
  'names': 'Name',
  'reg': 'Regex',
  'regex': 'Regex',
  'saml2-sso': 'SAML2 SSO',
  'top-activities': 'Top Activities',
  'traffic-overview': 'Traffic Overview',
  'update-log': 'Update log',
  'version-control': 'Version Control',
  'include': 'Include',
  'exclude': 'Exclude',

  'headers-entry': 'Header',
  'cookies-entry': 'Cookie',
  'args-entry': 'Argument',
  'attrs-entry': 'Attribute',


  'aclpolicies': 'ACL Policies',
  'ratelimits': 'Rate Limits',
  'urlmaps': 'URL Maps',
  'wafpolicies': 'WAF Policies',
  'wafrules': 'WAF Signatures',
  'tagrules': 'Tag Rules',
  'flowcontrol': 'Flow Control',
}

const LimitRulesTypes = {
  'headers': 'Header',
  'cookies': 'Cookie',
  'args': 'Argument',
  'attrs': 'Attribute',
}

const LimitAttributes = {
  'ip': 'IP Address',
  'asn': 'Provider',
  'uri': 'URI',
  'path': 'Path',
  'tags': 'Tag',
  'query': 'Query',
  'method': 'Method',
  'company': 'Company',
  'country': 'Country',
  'authority': 'Authority',
}

const ResponseActions = {
  'default': {'title': '503 Service Unavailable'},
  'challenge': {'title': 'Challenge'},
  'monitor': {'title': 'Tag Only'},
  'response': {'title': 'Response', 'params': {'status': '', 'content': ''}},
  'redirect': {'title': 'Redirect', 'params': {'status': '30[12378]', 'location': 'https?://.+'}},
  'ban': {'title': 'Ban', 'params': {'ttl': '[0-9]+', 'action': {'type': 'default', 'params': {}}}},
  'request_header': {'title': 'Header', 'params': {'headers': ''}},
}

function convertToUUID() {
  let dt = new Date().getTime()
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
    const r = (dt + Math.random() * 16) % 16 | 0
    dt = Math.floor(dt / 16)
    return (c == 'x' ? r : (r & 0x3 | 0x8)).toString(16)
  })
}

function convertToUUID2() {
  return convertToUUID().split('-')[4]
}

const NewDocEntryFactory: { [key: string]: Function } = {
  aclpolicies(): ACLPolicy {
    return {
      'id': convertToUUID2(),
      'name': 'New ACL Policy',
      'allow': [] as string[],
      'allow_bot': [] as string[],
      'deny_bot': [] as string[],
      'bypass': [] as string[],
      'force_deny': [] as string[],
      'deny': [] as string[],
    }
  },

  wafpolicies(): WAFPolicy {
    return {
      'id': convertToUUID2(),
      'name': 'New WAF Policy',
      'ignore_alphanum': true,

      'max_header_length': 1024,
      'max_cookie_length': 1024,
      'max_arg_length': 1024,

      'max_headers_count': 42,
      'max_cookies_count': 42,
      'max_args_count': 512,

      'args': {
        'names': [],
        'regex': [],
      },
      'headers': {
        'names': [],
        'regex': [],
      },
      'cookies': {
        'names': [],
        'regex': [],
      },
    }
  },

  tagrules(): TagRule {
    return {
      'id': convertToUUID2(),
      'name': 'New Tag Rules',
      'source': 'self-managed',
      'mdate': (new Date()).toISOString(),
      'notes': 'New List Notes and Remarks',
      'entries_relation': 'OR',
      'active': true,
      'tags': [],
      'action': {
        'type': 'monitor',
      },
      'rule': {
        'relation': 'OR',
        'sections': [],
      },
    }
  },

  urlmaps(): URLMap {
    return {
      'id': convertToUUID2(),
      'name': 'New URL Map',
      'match': '__default__',
      'map': [
        {
          'match': '/',
          'name': 'default',
          'acl_profile': '__default__',
          'waf_profile': '__default__',
          'acl_active': true,
          'waf_active': true,
          'limit_ids': [],
        },
      ],
    }
  },

  ratelimits(): RateLimit {
    return {
      'id': convertToUUID2(),
      'description': 'New Rate Limit Rule',
      'name': 'New Rate Limit Rule',
      'limit': '3',
      'key': [
        {
          'attrs': 'ip',
        },
      ],
      'ttl': '180',
      'action': {
        'type': 'default',
      },
      'exclude': {
        'headers': {},
        'cookies': {},
        'args': {},
        'attrs': {'tags': 'allowlist'},
      },
      'include': {
        'headers': {},
        'cookies': {},
        'args': {},
        'attrs': {'tags': 'blocklist'},
      },
      'pairwith': {
        'self': 'self',
      },
    }
  },

  flowcontrol(): FlowControl {
    return {
      'id': convertToUUID2(),
      'name': 'New Flow Control',
      'ttl': 60,
      'active': true,
      'notes': 'New Flow Control Notes and Remarks',
      'key': [
        {
          'attrs': 'ip',
        },
      ],
      'action': {
        'type': 'default',
      },
      'exclude': [],
      'include': ['all'],
      'sequence': [],
    }
  },

}

const ConfAPIRoot = '/conf/api'
const ConfAPIVersion = 'v1'

const LogsAPIRoot = '/logs/api'
const LogsAPIVersion = 'v1'

const ACCESSLOG_SQL = `SELECT * FROM (SELECT *, CAST(row_to_json(row) as text) as json_row FROM logs row) rows`
const ACCESSLOG_SQL_SUFFIX = ' ORDER BY StartTime DESC LIMIT 2048'

export default {
  name: 'DatasetsUtils',
  Titles,
  ResponseActions,
  LimitAttributes,
  LimitRulesTypes,
  convertToUUID,
  convertToUUID2,
  ConfAPIRoot,
  ConfAPIVersion,
  NewDocEntryFactory,
  LogsAPIRoot,
  LogsAPIVersion,
  ACCESSLOG_SQL,
  ACCESSLOG_SQL_SUFFIX,
}
