import axios from 'axios';

// In development, this will be empty (uses Vite proxy to localhost:5000)
// In production, define VITE_API_URL in Vercel to point to your live backend
const BASE = import.meta.env.VITE_API_URL || '';

// ── Axios instance with JWT interceptor ────────────────────────────────────────
const api = axios.create({ baseURL: BASE });

// Attach Bearer token automatically to every request
api.interceptors.request.use((config) => {
  try {
    const token = localStorage.getItem('havoc_token');
    if (token) {
      if (config.headers && typeof config.headers.set === 'function') {
        config.headers.set('Authorization', `Bearer ${token}`);
      } else {
        config.headers['Authorization'] = `Bearer ${token}`;
      }
    }
  } catch {
    // ignore parse errors
  }
  return config;
});

// Handle 401 globally — token expired, force logout
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      const isAuthEndpoint = error.config?.url?.includes('/api/auth/');
      if (!isAuthEndpoint) {
        // Token expired / invalid — clear session and reload to login
        localStorage.removeItem('havoc_token');
        localStorage.removeItem('havoc_user');
        window.location.reload();
      }
    }
    return Promise.reject(error);
  }
);

// ── API calls ─────────────────────────────────────────────────────────────────
export const getMetrics         = ()             => api.get('/api/metrics?latest=true');
export const getVulnerabilities = ()             => api.get('/api/vulnerabilities?latest=true');
export const getScanHistory     = ()             => api.get('/api/scan-history');
export const getRadar           = ()             => api.get('/api/radar?latest=true');
export const getEpss            = ()             => api.get('/api/epss?latest=true');
export const getRemediation     = ()             => api.get('/api/remediation');
export const getAISolution      = (id)           => api.get(`/api/ai-solution/${id}`);
export const startScan          = (target, options) => api.post('/api/scan/start', { target, ...options });
export const stopScan           = (target)       => api.post('/api/scan/stop', { target });
export const getScanStatus      = ()             => api.get('/api/scan/status');
export const clearDatabase      = ()             => api.post('/api/settings/clear');
export const removeAccount      = ()             => api.post('/api/settings/remove-account');

// Auth endpoints (use plain axios — no token needed for login/register)
export const loginUser          = (email, password) => axios.post(`${BASE}/api/auth/login`, { email, password });
export const registerUser       = (firstName, lastName, email, password) => axios.post(`${BASE}/api/auth/register`, { firstName, lastName, email, password });
export const resetPassword      = (email, oldPassword, newPassword) => api.post('/api/auth/reset-password', { email, oldPassword, newPassword });

export const exportJsonUrl  = `${BASE}/api/export/json`;
export const exportCsvUrl   = `${BASE}/api/export/csv`;
export const exportHtmlUrl  = `${BASE}/api/export/html`;

// Authenticated download helpers
export const downloadJson = () => api.get('/api/export/json', { responseType: 'blob' });
export const downloadCsv  = () => api.get('/api/export/csv',  { responseType: 'blob' });
export const downloadHtml = () => api.get('/api/export/html', { responseType: 'blob' });

export const triggerDownload = async (promise, filename) => {
  const res = await promise;
  const url = window.URL.createObjectURL(new Blob([res.data]));
  const link = document.createElement('a');
  link.href = url;
  link.setAttribute('download', filename);
  document.body.appendChild(link);
  link.click();
  link.parentNode.removeChild(link);
  window.URL.revokeObjectURL(url);
};

// Billing endpoints (Stripe)
export const getPlans          = ()                      => api.get('/api/billing/plans');
export const getMyPlan         = (userId)                => api.get(`/api/billing/my-plan?user_id=${userId}`);
export const createCheckout    = (userId, plan, email)   => api.post('/api/billing/checkout', { user_id: userId, plan, email });
export const openBillingPortal = (userId)                => api.post('/api/billing/portal', { user_id: userId });

// Razorpay billing endpoints (India — UPI / NetBanking / Cards / Wallets)
export const getRazorpayPlans   = ()           => api.get('/api/razorpay/plans');
export const createRazorpayOrder = (plan)      => api.post('/api/razorpay/create-order', { plan });
export const verifyRazorpayPayment = (payload) => api.post('/api/razorpay/verify', payload);

// Admin Database Management
export const getAdminTables      = ()                            => api.get('/api/admin/tables');
export const getAdminTableData   = (table, page, perPage, search) => api.get(`/api/admin/tables/${table}`, { params: { page, per_page: perPage, search } });
export const deleteAdminRow      = (table, rowId)                => api.delete(`/api/admin/tables/${table}/rows/${rowId}`);
export const updateUserRole      = (userId, role)                => api.put(`/api/admin/users/${userId}/role`, { role });
export const getAdminStats       = ()                            => api.get('/api/admin/stats');
