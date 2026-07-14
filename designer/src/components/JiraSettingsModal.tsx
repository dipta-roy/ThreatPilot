import React, { useState, useEffect } from 'react';

interface JiraSettingsModalProps {
  onClose: () => void;
}

const JiraSettingsModal: React.FC<JiraSettingsModalProps> = ({ onClose }) => {
  const [url, setUrl] = useState('');
  const [email, setEmail] = useState('');
  const [token, setToken] = useState('');
  const [projectKey, setProjectKey] = useState('');
  const [issueType, setIssueType] = useState('Story');
  const [isTesting, setIsTesting] = useState(false);
  const [testResult, setTestResult] = useState<{success: boolean, message: string} | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    fetch('/api/jira/config')
      .then(res => res.json())
      .then(data => {
        setUrl(data.jira_url || '');
        setEmail(data.jira_email || '');
        setProjectKey(data.jira_project_key || '');
        setIssueType(data.jira_issue_type || 'Story');
        if (data.has_token) {
          setToken('*****');
        }
      })
      .catch(err => console.error("Failed to load Jira config", err))
      .finally(() => setIsLoading(false));
  }, []);

  const handleTestConnection = async () => {
    setIsTesting(true);
    setTestResult(null);
    try {
      const res = await fetch('/api/jira/config', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          jira_url: url,
          jira_email: email,
          jira_project_key: projectKey,
          jira_issue_type: issueType,
          jira_api_token: token
        })
      });
      const data = await res.json();
      if (res.ok) {
        setTestResult({ success: true, message: data.message || "Connection successful!" });
      } else {
        setTestResult({ success: false, message: data.error || "Connection failed." });
      }
    } catch (e: any) {
      setTestResult({ success: false, message: e.message || "Network error." });
    } finally {
      setIsTesting(false);
    }
  };

  const handleSave = () => {
    if (testResult && testResult.success) {
      onClose();
    } else {
      handleTestConnection().then(() => {
        // Will close manually if successful
      });
    }
  };

  if (isLoading) return null;

  return (
    <div className="fixed inset-0 bg-slate-900/80 backdrop-blur-sm flex items-center justify-center z-50 p-4">
      <div className="bg-white dark:bg-slate-800 rounded-lg shadow-xl w-full max-w-md flex flex-col max-h-[90vh]">
        <div className="flex items-center justify-between p-4 border-b border-slate-200 dark:border-slate-700">
          <h2 className="text-lg font-semibold text-slate-800 dark:text-slate-100 flex items-center gap-2">
            <svg className="w-5 h-5 text-blue-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1"></path></svg>
            Jira Integration Settings
          </h2>
          <button onClick={onClose} className="text-slate-400 hover:text-slate-600 dark:hover:text-slate-300">
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M6 18L18 6M6 6l12 12"></path></svg>
          </button>
        </div>

        <div className="p-6 overflow-y-auto flex-1">
          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">Jira Instance URL</label>
              <input type="text" value={url} onChange={e => setUrl(e.target.value)} placeholder="https://your-domain.atlassian.net" className="w-full px-3 py-2 bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-600 rounded-md shadow-sm focus:outline-none focus:ring-2 focus:ring-primary-500 dark:text-white" />
            </div>
            
            <div>
              <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">Email Address</label>
              <input type="email" value={email} onChange={e => setEmail(e.target.value)} placeholder="your.email@company.com" className="w-full px-3 py-2 bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-600 rounded-md shadow-sm focus:outline-none focus:ring-2 focus:ring-primary-500 dark:text-white" />
            </div>
            
            <div>
              <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">API Token</label>
              <input type="password" value={token} onChange={e => setToken(e.target.value)} placeholder="Create at id.atlassian.com/manage-profile/security/api-tokens" className="w-full px-3 py-2 bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-600 rounded-md shadow-sm focus:outline-none focus:ring-2 focus:ring-primary-500 dark:text-white" />
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">Project Key</label>
                <input type="text" value={projectKey} onChange={e => setProjectKey(e.target.value)} placeholder="e.g. SEC" className="w-full px-3 py-2 bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-600 rounded-md shadow-sm focus:outline-none focus:ring-2 focus:ring-primary-500 dark:text-white" />
              </div>
              
              <div>
                <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">Issue Type</label>
                <input type="text" value={issueType} onChange={e => setIssueType(e.target.value)} placeholder="Story" className="w-full px-3 py-2 bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-600 rounded-md shadow-sm focus:outline-none focus:ring-2 focus:ring-primary-500 dark:text-white" />
              </div>
            </div>

            {testResult && (
              <div className={`p-3 rounded-md text-sm ${testResult.success ? 'bg-green-50 text-green-700 dark:bg-green-900/30 dark:text-green-400' : 'bg-red-50 text-red-700 dark:bg-red-900/30 dark:text-red-400'}`}>
                {testResult.message}
              </div>
            )}
          </div>
        </div>

        <div className="p-4 border-t border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800/50 flex justify-between rounded-b-lg">
          <button 
            onClick={handleTestConnection}
            disabled={isTesting}
            className="px-4 py-2 text-sm font-medium text-slate-700 bg-white border border-slate-300 rounded-md shadow-sm hover:bg-slate-50 dark:bg-slate-700 dark:text-slate-200 dark:border-slate-600 dark:hover:bg-slate-600 focus:outline-none"
          >
            {isTesting ? 'Testing...' : 'Test Connection'}
          </button>
          
          <div className="flex gap-2">
            <button 
              onClick={onClose}
              className="px-4 py-2 text-sm font-medium text-slate-700 bg-white border border-slate-300 rounded-md shadow-sm hover:bg-slate-50 dark:bg-slate-700 dark:text-slate-200 dark:border-slate-600 dark:hover:bg-slate-600 focus:outline-none"
            >
              Close
            </button>
            <button 
              onClick={handleSave}
              disabled={isTesting}
              className="px-4 py-2 text-sm font-medium text-white bg-primary-600 border border-transparent rounded-md shadow-sm hover:bg-primary-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary-500 disabled:opacity-50"
            >
              Save & Test
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

export default JiraSettingsModal;
