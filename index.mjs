import {
  authenticationMode,
  bearer,
  check,
  connection,
  credential,
  envName,
  error,
  includesAll,
  matchesState,
  oauth1Authorization,
  secretPath,
  segment,
  service,
  stateOption,
  target,
  text,
  verdict,
  z,
} from '@cairul/pdk';

export default function trello({ authMode, keyEnv, keyFile, keySecretFile, tokenSecretFile, ...options } = {}) {
  if (keyEnv !== undefined) envName.parse(keyEnv);
  for (const path of [keyFile, keySecretFile, tokenSecretFile]) {
    if (path !== undefined) secretPath.parse(path);
  }
  const prefix = 'TRELLO';
  const getKey = credential(prefix, 'KEY', { envName: keyEnv, file: keyFile, legacy: 'TRELLO_API_KEY' });
  const getKeySecret = credential(prefix, 'KEY_SECRET', { file: keySecretFile, required: true });
  const getTokenSecret = credential(prefix, 'TOKEN_SECRET', { file: tokenSecretFile, required: true });
  const mode = authenticationMode(prefix, authMode, ['auto', 'bearer', 'key-token', 'oauth1'], 'auto');
  const api = connection(options, {
    prefix,
    baseUrl: 'https://api.trello.com/1',
    tokenEnv: 'TRELLO_TOKEN',
    required: true,
    auth: async (token, _email, signal, request) => {
      if (mode === 'bearer') return bearer(token);
      const key = await getKey(signal);
      if (!key && mode === 'auto') return bearer(token);
      if (!key) throw new Error('Set the Trello API key for the selected authentication mode.');
      if (mode === 'oauth1') {
        const [consumerSecret, tokenSecret] = await Promise.all([getKeySecret(signal), getTokenSecret(signal)]);
        return { authorization: oauth1Authorization({ ...request, key, token, consumerSecret, tokenSecret }) };
      }
      if (!/^[\w.-]+$/.test(key) || !/^[\w.-]+$/.test(token)) throw new Error('Invalid Trello API-key credentials.');
      return { authorization: 'OAuth oauth_consumer_key="' + key + '", oauth_token="' + token + '"' };
    },
  });
  function cardCheck(resource, shape, evaluate) {
    return check(z.strictObject({ card: text.optional(), ...shape }), (config, context) =>
      service(async () => {
        const id = target(config.card, context.workItemUrl, ['trello.com', api.host], /^\/c\/([^/]+)(?:\/|$)/);
        const payload = await api.request(`cards/${segment(id)}${resource}`, { signal: context.signal });
        return evaluate(payload, config);
      })
    );
  }
  return {
    checkKinds: {
      'trello.card-list': cardCheck('', { listId: stateOption }, (card, { listId }) =>
        matchesState(card.idList, listId, 'Card list')
      ),
      'trello.card-labels': cardCheck('', { labels: z.array(text).min(1) }, (card, { labels }) =>
        includesAll(
          card.labels?.map((label) => label.name),
          labels,
          'card labels'
        )
      ),
      'trello.card-attachments': cardCheck('/attachments', { names: z.array(text).min(1) }, (attachments, { names }) =>
        includesAll(
          Array.isArray(attachments) ? attachments.map(({ name }) => name) : undefined,
          names,
          'card attachments'
        )
      ),
      'trello.checklist-complete': cardCheck('/checklists', { name: text }, (lists, { name }) => {
        if (!Array.isArray(lists)) return error('Trello returned no card checklists.');
        const matching = lists.filter((list) => list.name === name);
        if (matching.length > 1) return error('More than one checklist uses this name.');
        const items = matching[0]?.checkItems;
        return verdict(
          !!items?.length && items.every((item) => item.state === 'complete'),
          `Waiting for checklist "${name}" to be complete.`
        );
      }),
    },
  };
}
