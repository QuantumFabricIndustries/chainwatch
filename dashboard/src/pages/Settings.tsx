import { useEffect, useState } from 'react';
import { setApiKey, clearApiKey, api, type ApiKeyInfo } from '../api.js';

export default function Settings() {
  const [keyInput, setKeyInput] = useState('');
  const [slackUrl, setSlackUrl] = useState('');
  const [slackMinSeverity, setSlackMinSeverity] = useState('high');
  const [testResult, setTestResult] = useState<string | null>(null);
  const [testLoading, setTestLoading] = useState(false);
  const [saved, setSaved] = useState(false);
  const [keys, setKeys] = useState<ApiKeyInfo[]>([]);
  const [newKeyLabel, setNewKeyLabel] = useState('');
  const [newKeyValue, setNewKeyValue] = useState<string | null>(null);
  const [keysError, setKeysError] = useState<string | null>(null);

  useEffect(() => {
    refreshKeys();
  }, []);

  async function refreshKeys() {
    try {
      const { keys } = await api.getApiKeys();
      setKeys(keys);
      setKeysError(null);
    } catch (e) {
      setKeysError((e as Error).message);
    }
  }

  async function handleCreateKey() {
    try {
      const { api_key } = await api.createApiKey(newKeyLabel.trim() || 'dashboard');
      setNewKeyValue(api_key);
      setNewKeyLabel('');
      await refreshKeys();
    } catch (e) {
      setKeysError((e as Error).message);
    }
  }

  async function handleRevokeKey(id: string) {
    if (!window.confirm('Revoke this API key? Clients using it will lose access.')) return;
    try {
      await api.deleteApiKey(id);
      await refreshKeys();
    } catch (e) {
      setKeysError((e as Error).message);
    }
  }

  function handleSaveKey() {
    if (keyInput.trim()) {
      setApiKey(keyInput.trim());
      setSaved(true);
      setTimeout(() => setSaved(false), 2000);
    }
  }

  function handleClearKey() {
    clearApiKey();
    setKeyInput('');
    window.location.reload();
  }

  async function handleTestSlack() {
    if (!slackUrl.trim()) {
      setTestResult('Enter a Slack webhook URL first.');
      return;
    }
    setTestLoading(true);
    setTestResult(null);
    try {
      const result = await api.testAlert('slack', { url: slackUrl.trim() });
      setTestResult(result.success ? '✅ Test alert sent successfully!' : `❌ ${result.message}`);
    } catch (e) {
      setTestResult(`❌ ${(e as Error).message}`);
    } finally {
      setTestLoading(false);
    }
  }

  async function handleSaveSlack() {
    if (!slackUrl.trim()) return;
    try {
      await api.createAlert('slack', { url: slackUrl.trim() }, slackMinSeverity);
      setTestResult('✅ Slack alert saved.');
    } catch (e) {
      setTestResult(`❌ ${(e as Error).message}`);
    }
  }

  return (
    <div className="space-y-8 max-w-2xl">
      <h1 className="text-2xl font-bold text-gray-900">Settings</h1>

      {/* API Key */}
      <section className="bg-white rounded-lg border border-gray-200 p-6">
        <h2 className="text-lg font-semibold text-gray-900 mb-4">API Key</h2>
        <p className="text-sm text-gray-500 mb-4">
          Your ChainWatch API key authenticates all dashboard requests.
          Get one by running <code className="bg-gray-100 px-1 rounded">chainwatch sync</code> or
          creating a workspace at the API.
        </p>
        <div className="flex gap-2">
          <input
            type="password"
            value={keyInput}
            onChange={(e) => setKeyInput(e.target.value)}
            placeholder="cw_<workspace>_<key>"
            className="flex-1 border border-gray-300 rounded px-3 py-2 text-sm font-mono"
          />
          <button
            onClick={handleSaveKey}
            className="px-4 py-2 bg-chainwatch-red text-white rounded text-sm font-medium hover:bg-red-700"
          >
            Save
          </button>
          <button
            onClick={handleClearKey}
            className="px-4 py-2 border border-gray-300 rounded text-sm text-gray-600 hover:bg-gray-50"
          >
            Clear
          </button>
        </div>
        {saved && <p className="text-sm text-green-600 mt-2">✅ Key saved.</p>}
      </section>

      {/* API Key Management */}
      <section className="bg-white rounded-lg border border-gray-200 p-6">
        <h2 className="text-lg font-semibold text-gray-900 mb-4">Manage API Keys</h2>
        <p className="text-sm text-gray-500 mb-4">
          Create keys for CI pipelines and team members. The raw key is shown once at creation.
        </p>

        {newKeyValue && (
          <div className="mb-4 p-3 bg-green-50 border border-green-200 rounded">
            <p className="text-sm font-medium text-green-800 mb-1">New key — copy it now, it won't be shown again:</p>
            <code className="block text-xs font-mono text-green-900 break-all">{newKeyValue}</code>
            <button
              onClick={() => { navigator.clipboard.writeText(newKeyValue); }}
              className="mt-2 text-xs text-green-700 underline"
            >
              Copy to clipboard
            </button>
          </div>
        )}

        <div className="flex gap-2 mb-4">
          <input
            type="text"
            value={newKeyLabel}
            onChange={(e) => setNewKeyLabel(e.target.value)}
            placeholder="Label (e.g. ci-prod)"
            className="flex-1 border border-gray-300 rounded px-3 py-2 text-sm"
          />
          <button
            onClick={handleCreateKey}
            className="px-4 py-2 bg-chainwatch-red text-white rounded text-sm font-medium hover:bg-red-700"
          >
            Create Key
          </button>
        </div>

        {keysError && <p className="text-sm text-red-600 mb-3">{keysError}</p>}

        {keys.length > 0 && (
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left text-gray-500 border-b border-gray-200">
                <th className="pb-2 font-medium">Label</th>
                <th className="pb-2 font-medium">Last used</th>
                <th className="pb-2 font-medium">Created</th>
                <th className="pb-2 font-medium"></th>
              </tr>
            </thead>
            <tbody>
              {keys.map((k) => (
                <tr key={k.id} className="border-b border-gray-100">
                  <td className="py-2 font-medium text-gray-900">{k.label ?? '—'}</td>
                  <td className="py-2 text-gray-500">{k.last_used_at ? new Date(k.last_used_at).toLocaleDateString() : 'never'}</td>
                  <td className="py-2 text-gray-500">{new Date(k.created_at).toLocaleDateString()}</td>
                  <td className="py-2 text-right">
                    <button
                      onClick={() => handleRevokeKey(k.id)}
                      className="text-xs text-red-600 hover:text-red-800 font-medium"
                    >
                      Revoke
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>

      {/* Slack Integration */}
      <section className="bg-white rounded-lg border border-gray-200 p-6">
        <h2 className="text-lg font-semibold text-gray-900 mb-4">Slack Integration</h2>
        <p className="text-sm text-gray-500 mb-4">
          Get alerts in Slack when ChainWatch finds CRITICAL or HIGH severity issues.
          Create a Slack incoming webhook at{' '}
          <a href="https://api.slack.com/messaging/webhooks" target="_blank" rel="noreferrer"
             className="text-chainwatch-red underline">
            api.slack.com/messaging/webhooks
          </a>.
        </p>
        <div className="space-y-3">
          <input
            type="url"
            value={slackUrl}
            onChange={(e) => setSlackUrl(e.target.value)}
            placeholder="https://hooks.slack.com/services/T.../B.../..."
            className="w-full border border-gray-300 rounded px-3 py-2 text-sm font-mono"
          />
          <div className="flex items-center gap-3">
            <label className="text-sm text-gray-600">Minimum severity:</label>
            <select
              value={slackMinSeverity}
              onChange={(e) => setSlackMinSeverity(e.target.value)}
              className="text-sm border border-gray-300 rounded px-2 py-1"
            >
              <option value="low">Low</option>
              <option value="medium">Medium</option>
              <option value="high">High</option>
              <option value="critical">Critical</option>
            </select>
          </div>
          <div className="flex gap-2">
            <button
              onClick={handleSaveSlack}
              className="px-4 py-2 bg-chainwatch-red text-white rounded text-sm font-medium hover:bg-red-700"
            >
              Save Alert Config
            </button>
            <button
              onClick={handleTestSlack}
              disabled={testLoading}
              className="px-4 py-2 border border-gray-300 rounded text-sm text-gray-600 hover:bg-gray-50 disabled:opacity-50"
            >
              {testLoading ? 'Sending...' : 'Send Test Alert'}
            </button>
          </div>
          {testResult && <p className="text-sm mt-2">{testResult}</p>}
        </div>
      </section>
    </div>
  );
}
