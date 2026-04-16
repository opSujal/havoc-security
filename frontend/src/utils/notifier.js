import toast from 'react-hot-toast';

export const getLocalNotifications = () => {
  try {
    return JSON.parse(localStorage.getItem('havoc_ui_notifications')) || [];
  } catch {
    return [];
  }
};

export const clearLocalNotifications = () => {
  localStorage.setItem('havoc_ui_notifications', JSON.stringify([]));
  window.dispatchEvent(new Event('havoc_notification_update'));
};

const addLocalNotification = (type, message, desc = '') => {
  const notifs = getLocalNotifications();
  const newNotif = {
    id: `ui-${Date.now()}-${Math.random().toString(36).substring(2, 9)}`,
    _typeTag: type, // 'success', 'error', 'info', 'warning'
    label: message,
    sub: desc,
    date: new Date().toISOString()
  };
  
  const updated = [newNotif, ...notifs].slice(0, 50); // keep last 50
  localStorage.setItem('havoc_ui_notifications', JSON.stringify(updated));
  
  // Trigger topbar to reload
  window.dispatchEvent(new Event('havoc_notification_update'));
};

export const notify = {
  success: (msg, desc = '') => {
    toast.success(msg);
    addLocalNotification('success', msg, desc);
  },
  error: (msg, desc = '') => {
    toast.error(msg);
    addLocalNotification('error', msg, desc);
  },
  info: (msg, desc = '') => {
    toast(msg, { icon: 'ℹ️' });
    addLocalNotification('info', msg, desc);
  },
  warning: (msg, desc = '') => {
    toast(msg, { icon: '⚠️' });
    addLocalNotification('warning', msg, desc);
  }
};
