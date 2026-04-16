import { useState, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { Database, ArrowLeft, Search, Trash2, Users, Shield, ChevronLeft, ChevronRight, RefreshCw, HardDrive, BarChart3, Table2 } from 'lucide-react';
import { getAdminTables, getAdminTableData, deleteAdminRow, updateUserRole, getAdminStats } from '../api/api';
import { notify } from '../utils/notifier';
import './AdminDatabase.css';

function formatBytes(bytes) {
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
  return (bytes / 1048576).toFixed(2) + ' MB';
}

export default function AdminDatabase() {
  const navigate = useNavigate();
  const [tables, setTables] = useState([]);
  const [activeTable, setActiveTable] = useState(null);
  const [tableData, setTableData] = useState(null);
  const [page, setPage] = useState(1);
  const [search, setSearch] = useState('');
  const [loading, setLoading] = useState(false);
  const [stats, setStats] = useState(null);
  const [deleteConfirm, setDeleteConfirm] = useState(null); // { table, id }

  // Fetch table list and stats
  const loadTables = useCallback(async () => {
    try {
      const [tRes, sRes] = await Promise.all([getAdminTables(), getAdminStats()]);
      setTables(tRes.data);
      setStats(sRes.data);
    } catch {
      notify.error('Access Denied', 'Failed to load admin data.');
    }
  }, []);

  useEffect(() => { loadTables(); }, [loadTables]);

  // Fetch table data
  const loadTableData = useCallback(async (table, pg = 1, q = '') => {
    setLoading(true);
    try {
      const res = await getAdminTableData(table, pg, 50, q);
      setTableData(res.data);
    } catch {
      notify.error('Query Failed', `Could not load table "${table}".`);
    }
    setLoading(false);
  }, []);

  const openTable = (name) => {
    setActiveTable(name);
    setPage(1);
    setSearch('');
    loadTableData(name, 1, '');
  };

  const handleSearch = (e) => {
    e.preventDefault();
    setPage(1);
    loadTableData(activeTable, 1, search);
  };

  const handlePageChange = (newPage) => {
    setPage(newPage);
    loadTableData(activeTable, newPage, search);
  };

  const handleDelete = async (table, id) => {
    try {
      await deleteAdminRow(table, id);
      notify.success('Row Deleted', `Removed row #${id} from ${table}`);
      loadTableData(activeTable, page, search);
      loadTables(); // refresh counts
      setDeleteConfirm(null);
    } catch {
      notify.error('Delete Failed', 'Could not delete row.');
    }
  };

  const handleRoleToggle = async (userId, currentRole) => {
    const newRole = currentRole === 'Admin' ? 'User' : 'Admin';
    try {
      await updateUserRole(userId, newRole);
      notify.success('Role Updated', `User #${userId} is now ${newRole}`);
      loadTableData(activeTable, page, search);
    } catch {
      notify.error('Update Failed', 'Could not update user role.');
    }
  };

  // Table icon mapping
  const tableIcon = (name) => {
    if (name === 'users') return <Users size={15} />;
    if (name === 'vulnerabilities') return <Shield size={15} />;
    return <Table2 size={15} />;
  };

  return (
    <div className="admin-db-page fadein">

      {/* Header */}
      <div className="admin-db-header liquid-glass">
        <button className="admin-db-back" onClick={() => navigate('/settings')}>
          <ArrowLeft size={16} /> Back
        </button>
        <div className="admin-db-header-center">
          <Database size={20} className="admin-db-header-icon" />
          <div>
            <h1 className="admin-db-title">Raw Database Manager</h1>
            <p className="admin-db-subtitle">Admin-only · Direct SQLite access</p>
          </div>
        </div>
        <button className="admin-db-refresh" onClick={() => { loadTables(); if (activeTable) loadTableData(activeTable, page, search); }}>
          <RefreshCw size={14} /> Refresh
        </button>
      </div>

      {/* Stats strip */}
      {stats && (
        <div className="admin-db-stats">
          {[
            { label: 'Users', value: stats.total_users, icon: <Users size={14} />, color: '#60a5fa' },
            { label: 'Scans', value: stats.total_scans, icon: <BarChart3 size={14} />, color: '#4ade80' },
            { label: 'Vulnerabilities', value: stats.total_vulns, icon: <Shield size={14} />, color: '#ff3c5a' },
            { label: 'DB Size', value: formatBytes(stats.db_size_bytes), icon: <HardDrive size={14} />, color: '#f59e0b' },
          ].map(s => (
            <div key={s.label} className="admin-stat-card liquid-glass">
              <div className="admin-stat-icon" style={{ color: s.color }}>{s.icon}</div>
              <div className="admin-stat-value">{s.value}</div>
              <div className="admin-stat-label">{s.label}</div>
            </div>
          ))}
        </div>
      )}

      <div className="admin-db-body">
        {/* Sidebar: Table list */}
        <div className="admin-db-sidebar liquid-glass">
          <div className="admin-db-sidebar-title">Tables</div>
          {tables.map(t => (
            <button
              key={t.name}
              className={`admin-db-table-btn ${activeTable === t.name ? 'active' : ''}`}
              onClick={() => openTable(t.name)}
            >
              <span className="admin-db-table-icon">{tableIcon(t.name)}</span>
              <span className="admin-db-table-name">{t.name}</span>
              <span className="admin-db-table-count">{t.rows}</span>
            </button>
          ))}
        </div>

        {/* Main: Table data viewer */}
        <div className="admin-db-main">
          {!activeTable ? (
            <div className="admin-db-empty">
              <Database size={48} strokeWidth={1} />
              <p>Select a table from the sidebar to view its data</p>
            </div>
          ) : (
            <>
              {/* Toolbar */}
              <div className="admin-db-toolbar liquid-glass">
                <div className="admin-db-toolbar-left">
                  <span className="admin-db-table-badge">{activeTable}</span>
                  {tableData && <span className="admin-db-row-count">{tableData.total} rows</span>}
                </div>
                <form onSubmit={handleSearch} className="admin-db-search-form">
                  <Search size={14} className="admin-db-search-icon" />
                  <input
                    type="text"
                    placeholder="Search across columns..."
                    value={search}
                    onChange={e => setSearch(e.target.value)}
                    className="admin-db-search-input"
                  />
                </form>
              </div>

              {/* Data table */}
              <div className="admin-db-table-wrap">
                {loading ? (
                  <div className="admin-db-loading">Loading...</div>
                ) : tableData && tableData.rows.length > 0 ? (
                  <table className="admin-db-table">
                    <thead>
                      <tr>
                        {tableData.columns.map(c => (
                          <th key={c.name}>
                            <span className="admin-col-name">{c.name}</span>
                            <span className="admin-col-type">{c.type || '—'}</span>
                          </th>
                        ))}
                        <th className="admin-col-actions">Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {tableData.rows.map((row, ri) => (
                        <tr key={ri}>
                          {tableData.columns.map(c => (
                            <td key={c.name} title={String(row[c.name] ?? '')}>
                              {/* Special: role toggle for users table */}
                              {activeTable === 'users' && c.name === 'role' ? (
                                <button
                                  className={`admin-role-badge ${row[c.name] === 'Admin' ? 'admin' : 'user'}`}
                                  onClick={() => handleRoleToggle(row.id, row[c.name])}
                                  title="Click to toggle role"
                                >
                                  {row[c.name] || 'User'}
                                </button>
                              ) : (
                                <span className="admin-cell-text">
                                  {row[c.name] === null ? <span className="admin-null">NULL</span> : String(row[c.name]).substring(0, 120)}
                                </span>
                              )}
                            </td>
                          ))}
                          <td className="admin-col-actions">
                            {deleteConfirm?.table === activeTable && deleteConfirm?.id === row.id ? (
                              <div className="admin-confirm-row">
                                <button className="admin-confirm-yes" onClick={() => handleDelete(activeTable, row.id)}>Yes</button>
                                <button className="admin-confirm-no" onClick={() => setDeleteConfirm(null)}>No</button>
                              </div>
                            ) : (
                              <button
                                className="admin-delete-btn"
                                onClick={() => setDeleteConfirm({ table: activeTable, id: row.id })}
                                title="Delete row"
                              >
                                <Trash2 size={13} />
                              </button>
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                ) : (
                  <div className="admin-db-no-data">No rows found</div>
                )}
              </div>

              {/* Pagination */}
              {tableData && tableData.total_pages > 1 && (
                <div className="admin-db-pagination">
                  <button disabled={page <= 1} onClick={() => handlePageChange(page - 1)}>
                    <ChevronLeft size={14} /> Prev
                  </button>
                  <span className="admin-page-info">
                    Page {tableData.page} of {tableData.total_pages}
                  </span>
                  <button disabled={page >= tableData.total_pages} onClick={() => handlePageChange(page + 1)}>
                    Next <ChevronRight size={14} />
                  </button>
                </div>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  );
}
